import asyncio
import logging
import urllib.parse

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from guacamole.client import GuacamoleClient

from lib.cuckoo.common.config import Config

logger = logging.getLogger("guac-session")
web_cfg = Config("web")


class GuacamoleWebSocketConsumer(AsyncWebsocketConsumer):
    client = None
    task = None

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

        self.client.handshake(
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

    async def disconnect(self, code):
        """
        Close the GuacamoleClient connection on WebSocket disconnect.
        """
        self.task.cancel()
        await sync_to_async(self.client.close)()

    async def receive(self, text_data=None, bytes_data=None):
        """
        Handle data received in the WebSocket, send to GuacamoleClient.
        """
        if text_data is not None:
            logger.debug("To server: %s", text_data)
            self.client.send(text_data)

    async def open(self):
        """
        Receive data from GuacamoleClient and pass it to the WebSocket
        """
        while True:
            content = await sync_to_async(self.client.receive)()
            if content:
                logger.debug("From server: %s", content)
                await self.send(text_data=content)
