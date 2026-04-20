"""
ASGI config for web project.
"""
import sys
import os
from os.path import abspath, dirname, join

# --- 1. SETUP PATHS FIRST (Moved from bottom to top) ---
# Add / and /web (relative to CAPE/Cuckoo install location) to our path
# This ensures imports below can actually find the modules.
current_dir = dirname(abspath(__file__)) # The directory this file is in
webdir = abspath(join(current_dir, "..")) # The parent directory (web)

sys.path.append(abspath(join(webdir, ".."))) # Add CAPE root
sys.path.append(webdir) # Add web root
os.chdir(webdir) # Change working directory

# --- 2. DJANGO SETUP ---
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web.guac_settings")

# Initialize Django ASGI application early to ensure the AppRegistry
# is populated before importing code that may import ORM models.
from django.core.asgi import get_asgi_application
django_asgi_app = get_asgi_application()

# --- 3. CHANNELS IMPORTS ---
from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.security.websocket import AllowedHostsOriginValidator # Import this

# Import local routing after Django is setup
import guac.routing

# --- 4. APPLICATION DEFINITION ---
application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        # Wrap the websocket router in AllowedHostsOriginValidator
        # This prevents 403 Forbidden errors that confuse the Guacamole client
        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(
                URLRouter(guac.routing.websocket_urlpatterns)
            )
        ),
    }
)
