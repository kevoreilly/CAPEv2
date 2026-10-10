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

# Import local routing after Django is setup
import guac.routing
from guac.channels_auth import GuacAuthMiddlewareStack

websocket_patterns = guac.routing.websocket_urlpatterns

# --- 4. APPLICATION DEFINITION ---
application = ProtocolTypeRouter(
    {
        "http": django_asgi_app,
        # Backend-agnostic websocket auth. channels' stock AuthMiddlewareStack resolves
        # scope["user"] by load_backend()-ing the session's exact auth backend; for an
        # OIDC/allauth session that imports allauth.account.*, which guac_settings does NOT
        # install -> RuntimeError -> ws handshake 500 for every OIDC user (local ModelBackend
        # sessions load fine, masking it). GuacAuthMiddlewareStack resolves the user straight
        # from the session (id + auth-hash check) without loading the backend. See guac/channels_auth.py.
        "websocket": AllowedHostsOriginValidator(
            GuacAuthMiddlewareStack(
                URLRouter(websocket_patterns)
            )
        ),
    }
)
