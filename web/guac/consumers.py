import asyncio
import logging
import re
import urllib.parse
import uuid
from xml.etree import ElementTree as ET

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from guacamole.client import GuacamoleClient

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.guac_utils import is_user_activity
from lib.cuckoo.core.database import Database

from .timeout_manager import SessionTimeoutManager

try:
    import libvirt
    LIBVIRT_AVAILABLE = True
except ImportError:
    LIBVIRT_AVAILABLE = False

logger = logging.getLogger("guac-session")
web_cfg = Config("web")

machinery = Config().cuckoo.machinery
machinery_dsn = getattr(Config(machinery), machinery).get("dsn", "qemu:///system")

TASK_POLL_INTERVAL = 10
ACTIVE_GUAC_TASK_STATUSES = ("pending", "running")


def _get_vnc_port(vm_label, dsn=machinery_dsn):
    """Look up VNC port for a VM from libvirt. Must be called from sync context.
    `dsn` is the local hypervisor for single-node, or a worker's libvirt-over-SSH
    in central mode (the VM lives on the worker hosting the job)."""
    if not LIBVIRT_AVAILABLE:
        return None

    conn = None
    try:
        conn = libvirt.open(dsn)
        if not conn:
            return None
        dom = conn.lookupByName(vm_label)
        if not dom:
            return None
        state = dom.state(flags=0)
        if not state or state[0] != 1:
            return None
        xml_desc = dom.XMLDesc(0)
        root = ET.fromstring(xml_desc)
        graphics = root.find('./devices/graphics[@type="vnc"]')
        if graphics is not None:
            return int(graphics.get("port"))
        return None
    except Exception as e:
        logger.error("Failed to get VNC port for %s: %s", vm_label, e)
        return None
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def _check_vm_running(vm_label):
    """Check if the VM is running in libvirt. Must be called from sync context."""
    if not LIBVIRT_AVAILABLE:
        return False

    conn = None
    try:
        conn = libvirt.open(machinery_dsn)
        if conn:
            dom = conn.lookupByName(vm_label)
            if dom:
                state = dom.state(flags=0)
                return state and state[0] == 1
    except Exception as e:
        logger.error("Error checking VM status for %s: %s", vm_label, e)
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
    return False


class GuacamoleWebSocketConsumer(AsyncWebsocketConsumer):
    subprotocols = ["guacamole"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = None
        self.task = None
        self.monitor_task = None
        self.guac_token = None
        self.guac_task_id = None
        self.vm_label = None
        self.is_closing = False
        self.timeout_manager = None
        self.timeout_task = None
        self._disconnect_seen = False
        self._close_sent = False
        self._close_lock = asyncio.Lock()

    async def _delete_guac_session(self) -> None:
        """Delete the current guac session from the DB and clear the token."""
        if not self.guac_token:
            return
        try:
            db = Database()
            await sync_to_async(db.delete_guac_session)(self.guac_token)
            self.guac_token = None
        except Exception as e:
            logger.error("Failed to delete guac session %s: %s", self.guac_token, e)

    async def _close_websocket(self):
        """Close the websocket at most once across all concurrent code paths."""
        async with self._close_lock:
            if self._close_sent or self._disconnect_seen:
                return

            self._close_sent = True

        try:
            await self.close()
        except RuntimeError as error:
            if "Unexpected ASGI message 'websocket.close'" in str(error):
                logger.debug("Suppressing duplicate websocket.close for session")
                return
            raise

    async def connect(self):
        """Validate session token, look up VNC server-side, connect to guacd."""
        try:
            # 1. Read and validate the session cookie
            cookies = self.scope.get("cookies", {})
            token_str = cookies.get("guac_session")

            if not token_str:
                logger.warning("WebSocket rejected: no guac_session cookie")
                await self.close()
                return

            try:
                token = uuid.UUID(token_str)
            except ValueError:
                logger.warning("WebSocket rejected: invalid token format")
                await self.close()
                return

            # 2. Look up session in DB
            db = Database()
            session_data = await sync_to_async(db.get_guac_session)(token)

            if not session_data:
                logger.warning("WebSocket rejected: token not found in DB")
                await self.close()
                return

            self.guac_token = str(token)
            self.guac_task_id = session_data["task_id"]
            self.vm_label = session_data["vm_label"]
            vm_label = self.vm_label

            vnc_port = None
            worker_ip = None  # central mode: set to the worker's IP when the task's VM is remote
            if self.guac_task_id > 0:
                # 3. Verify task can still host an interactive session
                task = await sync_to_async(db.view_task)(self.guac_task_id)
                if not task or task.status not in ACTIVE_GUAC_TASK_STATUSES:
                    logger.warning(
                        "WebSocket rejected: task %s is not active for guac", self.guac_task_id
                    )
                    await self._delete_guac_session()
                    await self.close()
                    return

                # 4. Central mode: a broker-dispatched job's VM lives on a worker, so
                # resolve that worker's libvirt DSN + IP and look up the VNC port from ITS
                # libvirt; the tunnel then targets the worker's guacd. None => single-node.
                from lib.cuckoo.common.central_guac import libvirt_dsn_for_task

                vnc_dsn, worker_ip = await sync_to_async(libvirt_dsn_for_task)(self.guac_task_id, machinery_dsn)

                # 4b. Look up VNC port server-side from libvirt (local or worker)
                vnc_port = await sync_to_async(_get_vnc_port)(vm_label, vnc_dsn)
                if not vnc_port:
                    logger.warning(
                        "WebSocket rejected: no VNC port for VM %s", vm_label
                    )
                    await self.close()
                    return
            else:
                # Direct VNC connection
                guest_ip = session_data.get("guest_ip")
                if not guest_ip:
                    # Autodiscover port given just the VM name
                    vnc_port = await sync_to_async(_get_vnc_port)(vm_label)
                    if not vnc_port:
                        logger.warning(
                            "WebSocket rejected: could not autodiscover VNC port for VM %s", vm_label
                        )
                        await self.close()
                        return
                else:
                    try:
                        vnc_port = int(vm_label)
                    except ValueError:
                        logger.warning(
                            "WebSocket rejected: invalid direct VNC port %s", vm_label
                        )
                        await self.close()
                        return

            # 5. Parse config. Central mode: target the WORKER's guacd (which
            # reaches the VM's VNC on its own localhost); single-node uses configured guacd.
            guacd_hostname = worker_ip or web_cfg.guacamole.guacd_host or "localhost"
            guacd_port = int(web_cfg.guacamole.guacd_port) or 4822
            guacd_recording_path = web_cfg.guacamole.guacd_recording_path or ""
            guest_protocol = web_cfg.guacamole.guest_protocol or "vnc"
            guest_width = int(web_cfg.guacamole.guest_width) or 1280
            guest_height = int(web_cfg.guacamole.guest_height) or 1024
            guest_username = web_cfg.guacamole.username or ""
            guest_password = web_cfg.guacamole.password or ""

            query_string = self.scope.get("query_string", b"").decode()
            params = urllib.parse.parse_qs(query_string)
            # Sanitize recording name — only allow alphanumeric, dash, underscore
            raw_recording = params.get("recording_name", ["task-recording"])[0]
            guacd_recording_name = re.sub(r"[^a-zA-Z0-9_-]", "", raw_recording)

            if self.guac_task_id > 0:
                if "rdp" in guest_protocol:
                    guest_host = session_data.get("guest_ip", vm_label)
                    if not guest_host:
                        guest_host = vm_label
                    guest_port = int(web_cfg.guacamole.guest_rdp_port) or 3389
                    ignore_cert = (
                        "true"
                        if web_cfg.guacamole.ignore_rdp_cert is True
                        else "false"
                    )
                    extra_args = {
                        "disable-wallpaper": "true",
                        "disable-theming": "true",
                    }
                else:
                    # Central: the task's VM is on a worker, whose guacd (guacd_hostname=
                    # worker_ip) reaches the VM's VNC on its OWN localhost; single-node uses
                    # the configured vnc_host.
                    guest_host = "localhost" if worker_ip else (web_cfg.guacamole.vnc_host or "localhost")
                    guest_port = vnc_port
                    ignore_cert = "false"
                    vnc_color_depth = str(
                        getattr(web_cfg.guacamole, "vnc_color_depth", 16)
                    )
                    vnc_cursor = getattr(web_cfg.guacamole, "vnc_cursor", "local")
                    extra_args = {
                        "color-depth": vnc_color_depth,
                        "cursor": vnc_cursor,
                    }
            else:
                # Direct VNC connection
                guest_protocol = "vnc"
                guest_ip = session_data.get("guest_ip")
                guest_host = guest_ip or web_cfg.guacamole.vnc_host or "localhost"
                guest_port = vnc_port
                ignore_cert = "false"
                vnc_color_depth = str(
                    getattr(web_cfg.guacamole, "vnc_color_depth", 16)
                )
                vnc_cursor = getattr(web_cfg.guacamole, "vnc_cursor", "local")
                extra_args = {
                    "color-depth": vnc_color_depth,
                    "cursor": vnc_cursor,
                }

            # 6. Connect to guacd
            self.client = GuacamoleClient(guacd_hostname, guacd_port)

            logger.info(
                "Guacamole connecting to guacd at %s:%s. Handshake: protocol=%s, host=%s, port=%s, recording_name=%s",
                guacd_hostname,
                guacd_port,
                guest_protocol,
                guest_host,
                guest_port,
                guacd_recording_name,
            )

            await sync_to_async(self.client.handshake)(
                protocol=guest_protocol,
                width=guest_width,
                height=guest_height,
                hostname=guest_host,
                port=guest_port,
                username=guest_username,
                password=guest_password,
                recording_path=guacd_recording_path,
                recording_name=guacd_recording_name,
                ignore_cert=ignore_cert,
                **extra_args,
            )

            if self.client.connected:
                await self.accept(subprotocol="guacamole")
                logger.info(
                    "Guacamole session accepted: task=%s vm=%s",
                    self.guac_task_id,
                    vm_label,
                )

                # 7. Initialize timeout handling
                if self.guac_task_id > 0:
                    try:
                        vm_ip = session_data.get("guest_ip") or guest_host
                        self.timeout_manager = SessionTimeoutManager(
                            vm_ip=vm_ip,
                            user="unknown_user",
                            session_id=self.guac_token,
                            task_id=str(self.guac_task_id),
                        )
                    except Exception as e:
                        logger.error("Failed to initialize timeout manager: %s", e)
                        self.timeout_manager = None
                else:
                    self.timeout_manager = None

                # 8. Start background tasks
                self.task = asyncio.create_task(self.read_guacd())
                if self.guac_task_id > 0:
                    self.monitor_task = asyncio.create_task(self.monitor_task_status())
                else:
                    self.monitor_task = asyncio.create_task(self.monitor_vm_status())
                if self.timeout_manager and self.timeout_manager.idle_timeout_seconds > 0:
                    self.timeout_task = asyncio.create_task(self.monitor_timeout())
            else:
                logger.warning("Guacamole handshake failed.")
                self.is_closing = True
                await self._close_websocket()

        except Exception as e:
            logger.error("Error during Guacamole connect: %s", str(e))
            self.is_closing = True
            await self._close_websocket()

    async def monitor_task_status(self):
        """Periodically check if the CAPE task can still host the session."""
        try:
            while True:
                await asyncio.sleep(TASK_POLL_INTERVAL)
                if not self.guac_task_id:
                    break
                db = Database()
                task = await sync_to_async(db.view_task)(self.guac_task_id)
                if not task or task.status not in ACTIVE_GUAC_TASK_STATUSES:
                    logger.info(
                        "Task %s no longer running, disconnecting guac session",
                        self.guac_task_id,
                    )
                    await self._delete_guac_session()
                    await self._close_websocket()
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Error in task monitor: %s", e)

    async def monitor_vm_status(self):
        """Periodically check if the VM is still running. If not, release the lock and close."""
        try:
            while True:
                await asyncio.sleep(TASK_POLL_INTERVAL)
                if self.guac_task_id > 0:
                    break

                is_running = await sync_to_async(_check_vm_running)(self.vm_label)

                if not is_running:
                    logger.info("VM %s is no longer running, unlocking and disconnecting", self.vm_label)
                    db = Database()
                    machine = await sync_to_async(db.view_machine_by_label)(self.vm_label)
                    if machine and machine.locked:
                        await sync_to_async(db.unlock_machine)(machine)
                        await sync_to_async(db.session.commit)()
                    await self._close_websocket()
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Error in VM monitor: %s", e)

    async def disconnect(self, code):
        """Clean up on WebSocket disconnect."""
        self.is_closing = True
        self._disconnect_seen = True

        if self.timeout_manager:
            self.timeout_manager.set_inactive()

        tasks = [t for t in (self.monitor_task, self.task, self.timeout_task) if t]
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

        if self.client:
            try:
                await sync_to_async(self.client.close)()
            except Exception as e:
                logger.error("Error closing guacamole client: %s", str(e))

        await self._delete_guac_session()

    async def receive(self, text_data=None, bytes_data=None):
        """Forward data from browser to guacd."""
        if text_data and self.client:
            if self.timeout_manager and is_user_activity(text_data):
                self.timeout_manager.update_activity()

            try:
                await sync_to_async(self.client.send)(text_data)
            except Exception as e:
                logger.error("Failed to send data to guacd: %s", str(e))

    async def read_guacd(self):
        """Forward data from guacd to browser."""
        try:
            while True:
                content = await sync_to_async(
                    self.client.receive, thread_sensitive=False
                )()
                if content:
                    await self.send(text_data=content)
                else:
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Exception in Guacamole message loop: %s", e)
        finally:
            await self._close_websocket()

    async def monitor_timeout(self):
        """Monitor session for idle timeout and handle cleanup when timeout occurs."""
        try:
            while self.timeout_manager and self.timeout_manager.is_active and not self.is_closing:
                await asyncio.sleep(self.timeout_manager.activity_check_interval)

                if not self.timeout_manager or not self.timeout_manager.is_active:
                    break

                if self.timeout_manager.is_timed_out():
                    idle_time = self.timeout_manager.get_idle_time_ms()
                    logger.info(
                        "Session timeout detected for %s, idle for %sms (threshold: %ss)",
                        self.timeout_manager.session_id,
                        idle_time,
                        self.timeout_manager.idle_timeout_seconds,
                    )
                    await self.handle_timeout()
                    break
                else:
                    idle_time = self.timeout_manager.get_idle_time_ms()
                    logger.debug("Session %s idle for %sms", self.timeout_manager.session_id, idle_time)

        except asyncio.CancelledError:
            logger.debug("Timeout monitor cancelled for session %s", getattr(self.timeout_manager, "session_id", "unknown"))
        except Exception as e:
            logger.error("Error in timeout monitor: %s", str(e))

    async def handle_timeout(self):
        """Handle session timeout by signalling analysis completion and closing the connection."""
        if not self.timeout_manager:
            return

        try:
            logger.info(
                "Handling timeout for session %s, VM: %s",
                self.timeout_manager.session_id,
                self.timeout_manager.vm_ip,
            )
            success = await self.timeout_manager.complete_analysis()
            if success:
                logger.info("Successfully signalled analysis complete for %s", self.timeout_manager.vm_ip)
            else:
                logger.warning("Failed to signal analysis complete for %s", self.timeout_manager.vm_ip)

            try:
                await self.send(text_data="5.error,35.Session timed out due to inactivity,3.522;")
            except Exception as e:
                logger.warning("Could not send timeout message to client: %s", e)

        except Exception as e:
            logger.error("Error handling session timeout: %s", e)
        finally:
            if not self.is_closing:
                await self._close_websocket()
