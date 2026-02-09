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
            # Capture session_id from URL route for logging context
            session_id = self.scope["url_route"]["kwargs"].get("session_id", "unknown")

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

                # RDP Performance Optimizations
                # Default to safe/fast values if not present in config
                disable_wallpaper = "true" if getattr(web_cfg.guacamole, "rdp_disable_wallpaper", "yes") == "yes" else "false"
                disable_theming = "true" if getattr(web_cfg.guacamole, "rdp_disable_theming", "yes") == "yes" else "false"
                enable_font_smoothing = "true" if getattr(web_cfg.guacamole, "rdp_enable_font_smoothing", "no") == "yes" else "false"
                enable_full_window_drag = "true" if getattr(web_cfg.guacamole, "rdp_enable_full_window_drag", "no") == "yes" else "false"
                enable_desktop_composition = "true" if getattr(web_cfg.guacamole, "rdp_enable_desktop_composition", "no") == "yes" else "false"
                enable_menu_animations = "true" if getattr(web_cfg.guacamole, "rdp_enable_menu_animations", "no") == "yes" else "false"
                enable_audio = "audio" if getattr(web_cfg.guacamole, "enable_audio", "no") == "yes" else None

                extra_args = {
                    "disable-wallpaper": disable_wallpaper,
                    "disable-theming": disable_theming,
                    "enable-font-smoothing": enable_font_smoothing,
                    "enable-full-window-drag": enable_full_window_drag,
                    "enable-desktop-composition": enable_desktop_composition,
                    "enable-menu-animations": enable_menu_animations,
                }
                if enable_audio:
                    extra_args["enable-audio"] = "true"

            else:
                guest_host = web_cfg.guacamole.vnc_host or "localhost"
                ports = params.get("vncport", ["5900"])
                guest_port = int(ports[0])
                ignore_cert = "false"

                # VNC Performance Optimizations
                vnc_color_depth = str(getattr(web_cfg.guacamole, "vnc_color_depth", 16))
                vnc_cursor = getattr(web_cfg.guacamole, "vnc_cursor", "local")

                extra_args = {
                    "color-depth": vnc_color_depth,
                    "cursor": vnc_cursor,
                }

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
                **extra_args
            )

            if self.client.connected:
                # 3. Accept the WebSocket connection specifically for 'guacamole'
                # Accept first to ensure the channel is open before sending data
                await self.accept(subprotocol="guacamole")
                logger.info("Guacamole connection accepted for session %s.", session_id)

                # 4. Start the background reader task
                # Use asyncio.create_task instead of get_event_loop()
                self.task = asyncio.create_task(self.read_guacd())
            else:
                logger.warning("Guacamole handshake failed. Closing connection.")
                await self.close()

        except Exception as e:
            logger.error("Error during Guacamole connect: %s", str(e))
            await self.close()

    async def disconnect(self, code):
        """
        Close the GuacamoleClient connection on WebSocket disconnect.
        """
        # Cancel the reader task if it exists
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass

        # Close the client safely
        if self.client:
            try:
                await sync_to_async(self.client.close)()
            except Exception as e:
                logger.error("Error closing guacamole client: %s", str(e))

    async def receive(self, text_data=None, bytes_data=None):
        """
        Handle data received in the WebSocket, send to GuacamoleClient.
        """
        if text_data and self.client:
            # logger.debug("To server: %s", text_data) # Verbose logging can slow down RDP
            try:
                await sync_to_async(self.client.send)(text_data)
            except Exception as e:
                logger.error("Failed to send data to guacd: %s", str(e))

    async def read_guacd(self):
        """
        Receive data from GuacamoleClient and pass it to the WebSocket
        """
        try:
            while True:
                # This blocks in a thread, releasing the async loop
                # thread_sensitive=False allows this to run in a separate thread pool, not blocking the main thread
                content = await sync_to_async(self.client.receive, thread_sensitive=False)()
                if content:
                    # logger.debug("From server: %s", content)
                    await self.send(text_data=content)
                else:
                    break
        except asyncio.CancelledError:
            pass  # Task cancellation is normal on disconnect
        except Exception as e:
            logger.error("Exception in Guacamole message loop: %s", e)
        finally:
            # Ensure we close the websocket if the guacd connection dies
            await self.close()
