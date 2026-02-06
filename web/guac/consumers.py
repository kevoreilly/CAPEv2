import asyncio
import logging
import urllib.parse

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from guacamole.client import GuacamoleClient

# Ensure this import path matches your project structure
from lib.cuckoo.common.config import Config

logger = logging.getLogger("guac-session")
web_cfg = Config("web")

class GuacamoleWebSocketConsumer(AsyncWebsocketConsumer):
    # Channels 4: Explicitly declare supported subprotocols
    subprotocols = ["guacamole"]
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = None
        self.task = None

    async def connect(self):
        """
        Initiate the GuacamoleClient and create a connection to it.
        """
        try:
            # 1. Parse Configuration & Parameters inside a try block
            # This prevents 500 errors from reaching the client as HTML
            guacd_hostname = web_cfg.guacamole.guacd_host or "localhost"
            guacd_port = int(web_cfg.guacamole.guacd_port) or 4822
            guacd_recording_path = web_cfg.guacamole.guacd_recording_path or ""
            guest_protocol = web_cfg.guacamole.guest_protocol or "vnc"
            guest_width = int(web_cfg.guacamole.guest_width) or 1280
            guest_height = int(web_cfg.guacamole.guest_height) or 1024
            guest_username = web_cfg.guacamole.username or ""
            guest_password = web_cfg.guacamole.password or ""

            # Safe decoding of query string
            query_string = self.scope.get("query_string", b"").decode()
            params = urllib.parse.parse_qs(query_string)

            if "rdp" in guest_protocol:
                hosts = params.get("guest_ip", [""])
                guest_host = hosts[0]
                guest_port = int(web_cfg.guacamole.guest_rdp_port) or 3389
                ignore_cert = "true" if web_cfg.guacamole.ignore_rdp_cert is True else "false"
            else:
                guest_host = web_cfg.guacamole.vnc_host or "localhost"
                ports = params.get("vncport", ["5900"])
                guest_port = int(ports[0])
                ignore_cert = "false"

            guacd_recording_name = params.get("recording_name", ["task-recording"])[0]

            # 2. Connect to Guacamole Daemon (guacd)
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
                # 3. Start the background reader task
                # Use asyncio.create_task instead of get_event_loop()
                self.task = asyncio.create_task(self.open())

                # 4. Accept the WebSocket connection specifically for 'guacamole'
                await self.accept(subprotocol="guacamole")
                logger.info("Guacamole connection accepted.")
            else:
                logger.warning("Guacamole handshake failed. Closing connection.")
                await self.close()

        except Exception as e:
            logger.error(f"Error during Guacamole connect: {e}")
            await self.close()

    async def disconnect(self, code):
        """
        Close the GuacamoleClient connection on WebSocket disconnect.
        """
        # Cancel the reader task if it exists
        if self.task:
            self.task.cancel()
        
        # Close the client safely
        if self.client:
            try:
                await sync_to_async(self.client.close)()
            except Exception as e:
                logger.error(f"Error closing guacamole client: {e}")

    async def receive(self, text_data=None, bytes_data=None):
        """
        Handle data received in the WebSocket, send to GuacamoleClient.
        """
        if text_data and self.client:
            # logger.debug("To server: %s", text_data) # Verbose logging can slow down RDP
            try:
                await sync_to_async(self.client.send)(text_data)
            except Exception as e:
                logger.error(f"Failed to send data to guacd: {e}")

    async def open(self):
        """
        Receive data from GuacamoleClient and pass it to the WebSocket
        """
        try:
            while True:
                # This blocks in a thread, releasing the async loop
                content = await sync_to_async(self.client.receive)()
                if content:
                    # logger.debug("From server: %s", content)
                    await self.send(text_data=content)
                else:
                    break
        except asyncio.CancelledError:
            pass # Task cancellation is normal on disconnect
        except Exception as e:
            logger.error("Exception in Guacamole message loop: %s", e)
        finally:
            # Ensure we close the websocket if the guacd connection dies
            await self.close()