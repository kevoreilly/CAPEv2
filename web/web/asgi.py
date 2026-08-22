"""
ASGI config for web project.
"""
import sys
import os
from os.path import abspath, dirname, join

# --- 1. SETUP PATHS FIRST ---
current_dir = dirname(abspath(__file__)) # The directory this file is in
webdir = abspath(join(current_dir, "..")) # The parent directory (web)

sys.path.append(abspath(join(webdir, ".."))) # Add CAPE root
sys.path.append(webdir) # Add web root
os.chdir(webdir) # Change working directory

# --- 2. DJANGO SETUP ---
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web.settings")

from django.core.asgi import get_asgi_application
django_asgi_app = get_asgi_application()

# --- 3. CHANNELS IMPORTS ---
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator
from channels.auth import AuthMiddlewareStack

# Import local routing after Django is setup
import web.routing

# --- 4. APPLICATION DEFINITION ---
application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(
                URLRouter(web.routing.websocket_urlpatterns)
            )
        ),
    }
)
