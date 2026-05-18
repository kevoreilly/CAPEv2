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
        """
        Initiate the GuacamoleClient and create a connection to it.
        """
        guacd_hostname = web_cfg.guacamole.guacd_host or "localhost"
        guacd_port = int(web_cfg.guacamole.guacd_port) or 4822
        guacd_recording_path = web_cfg.guacamole.guacd_recording_path or ""
        guest_protocol = web_cfg.guacamole.guest_protocol or "vnc"
        guest_width = int(web_cfg.guacamole.guest_width) or 1280
        guest_height = int(web_cfg.guacamole.guest_height) or 1024
        guest_username = web_cfg.guacamole.username or ""
        guest_password = web_cfg.guacamole.password or ""

        params = urllib.parse.parse_qs(self.scope["query_string"].decode())

        if "rdp" in guest_protocol:
            hosts = params.get("guest_ip", "")
            guest_host = hosts[0]
            guest_port = int(web_cfg.guacamole.guest_rdp_port) or 3389
            ignore_cert = "true" if web_cfg.guacamole.ignore_rdp_cert is True else "false"
        else:
            guest_host = web_cfg.guacamole.vnc_host or "localhost"
            ports = params.get("vncport", ["5900"])
            guest_port = int(ports[0])
            ignore_cert = "false"

        guacd_recording_name = params.get("recording_name", ["task-recording"])[0]

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
        )

        if self.client.connected:
            # start receiving data from GuacamoleClient
            loop = asyncio.get_event_loop()
            self.task = loop.create_task(self.open())

            # Accept connection
            await self.accept(subprotocol="guacamole")
        else:
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
        """
        Close the GuacamoleClient connection on WebSocket disconnect.
        """
        if self.task:
            self.task.cancel()
        if self.client:
            await sync_to_async(self.client.close)()

    async def receive(self, text_data=None, bytes_data=None):
        """
        Handle data received in the WebSocket, send to GuacamoleClient.
        """
        if text_data is not None:
            # logger.debug("To server: %s", text_data)
            await sync_to_async(self.client.send)(text_data)

    async def open(self):
        """
        Receive data from GuacamoleClient and pass it to the WebSocket
        """
        try:
            while True:
                content = await sync_to_async(self.client.receive)()
                if content:
                    # logger.debug("From server: %s", content)
                    await self.send(text_data=content)
                else:
                    break
        except Exception:
            # Connection lost
            pass
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
