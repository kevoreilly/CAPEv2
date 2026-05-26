from django.urls import re_path

from .consumers import GuacamoleWebSocketConsumer

websocket_urlpatterns = [
    re_path(
        r"^guac/websocket-tunnel/(?P<session_id>\w+)/?$",
        GuacamoleWebSocketConsumer.as_asgi(),
    ),
]
