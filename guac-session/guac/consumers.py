import asyncio
import logging
import os
import urllib.parse

from asgiref.sync import sync_to_async
from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from distutils.util import strtobool
from dotenv import load_dotenv
from guacamole.client import GuacamoleClient

load_dotenv()
logger = logging.getLogger("guac-session")


class GuacamoleWebSocketConsumer(AsyncWebsocketConsumer):
    client = None
    task = None

    async def connect(self):
        """
        Initiate the GuacamoleClient and create a connection to it.
        """
        guacd_hostname = os.getenv("GUACD_SERVICE_HOST", "localhost")
        guacd_port = int(os.getenv("GUACD_SERVICE_PORT", "4822"))
        guacd_recording_path = os.getenv("GUACD_RECORDING_PATH", "")
        guest_protocol = os.getenv("GUEST_PROTOCOL", "vnc")
        guest_width = int(os.getenv("GUEST_WIDTH", "1280"))
        guest_height = int(os.getenv("GUEST_HEIGHT", "1024"))
        guest_username = os.getenv("GUEST_USERNAME", "")
        guest_password = os.getenv("GUEST_PASSWORD", "")

        params = urllib.parse.parse_qs(self.scope["query_string"].decode())

        if "rdp" in guest_protocol:
            guest_host = params.get("guest_ip", "")
            guest_port = int(os.getenv("GUEST_RDP_PORT", "3389"))
        else:
            guest_host = "localhost"
            ports = params.get("vncport", ["5900"])
            guest_port = int(ports[0])
        
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
