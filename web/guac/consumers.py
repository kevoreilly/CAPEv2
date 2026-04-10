import asyncio
import logging
import uuid
import urllib.parse
from xml.etree import ElementTree as ET

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from guacamole.client import GuacamoleClient

from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database

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


def _get_vnc_port(vm_label):
    """Look up VNC port for a VM from libvirt. Must be called from sync context."""
    if not LIBVIRT_AVAILABLE:
        return None
    conn = None
    try:
        conn = libvirt.open(machinery_dsn)
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


class GuacamoleWebSocketConsumer(AsyncWebsocketConsumer):
    subprotocols = ["guacamole"]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = None
        self.task = None
        self.monitor_task = None
        self.guac_token = None
        self.guac_task_id = None

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
            vm_label = session_data["vm_label"]

            # 3. Verify task is still running
            task = await sync_to_async(db.view_task)(self.guac_task_id)
            if not task or task.status != "running":
                logger.warning(
                    "WebSocket rejected: task %s is not running", self.guac_task_id
                )
                await sync_to_async(db.delete_guac_session)(token)
                await self.close()
                return

            # 4. Look up VNC port server-side from libvirt
            vnc_port = await sync_to_async(_get_vnc_port)(vm_label)
            if not vnc_port:
                logger.warning(
                    "WebSocket rejected: no VNC port for VM %s", vm_label
                )
                await self.close()
                return

            # 5. Parse config
            guacd_hostname = web_cfg.guacamole.guacd_host or "localhost"
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
            import re
            raw_recording = params.get("recording_name", ["task-recording"])[0]
            guacd_recording_name = re.sub(r"[^a-zA-Z0-9_-]", "", raw_recording)

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
                guest_host = web_cfg.guacamole.vnc_host or "localhost"
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
                self.task = asyncio.create_task(self.read_guacd())
                self.monitor_task = asyncio.create_task(self.monitor_task_status())
            else:
                logger.warning("Guacamole handshake failed.")
                await self.close()

        except Exception as e:
            logger.error("Error during Guacamole connect: %s", str(e))
            await self.close()

    async def monitor_task_status(self):
        """Periodically check if the CAPE task is still running. Disconnect if not."""
        try:
            while True:
                await asyncio.sleep(TASK_POLL_INTERVAL)
                if not self.guac_task_id:
                    break
                db = Database()
                task = await sync_to_async(db.view_task)(self.guac_task_id)
                if not task or task.status != "running":
                    logger.info(
                        "Task %s no longer running, disconnecting guac session",
                        self.guac_task_id,
                    )
                    if self.guac_token:
                        await sync_to_async(db.delete_guac_session)(self.guac_token)
                    await self.close()
                    break
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error("Error in task monitor: %s", e)

    async def disconnect(self, code):
        """Clean up on WebSocket disconnect."""
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass

        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        if self.client:
            try:
                await sync_to_async(self.client.close)()
            except Exception as e:
                logger.error("Error closing guacamole client: %s", str(e))

        if self.guac_token:
            try:
                db = Database()
                await sync_to_async(db.delete_guac_session)(self.guac_token)
            except Exception:
                pass

    async def receive(self, text_data=None, bytes_data=None):
        """Forward data from browser to guacd."""
        if text_data and self.client:
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
            await self.close()
