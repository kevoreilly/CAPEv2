import os

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "guac-session.settings")

django_asgi_app = get_asgi_application()

import guac.routing

application = ProtocolTypeRouter(
    {
        "websocket": AuthMiddlewareStack(URLRouter(guac.routing.websocket_urlpatterns)),
    }
)
