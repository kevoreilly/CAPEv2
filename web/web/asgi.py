# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
ASGI config for web project.
Please read https://channels.readthedocs.io/en/latest/deploying.html#nginx-supervisor-ubuntu
"""

import sys

# These lines ensure that imports used by the ASGI daemon can be found
from os import chdir, environ
from os.path import abspath, dirname, join

from channels.auth import AuthMiddlewareStack
from channels.routing import ProtocolTypeRouter, URLRouter
from django.core.asgi import get_asgi_application

environ.setdefault("DJANGO_SETTINGS_MODULE", "web.guac_settings")

django_asgi_app = get_asgi_application()

import guac.routing

application = ProtocolTypeRouter(
    {
        "websocket": AuthMiddlewareStack(URLRouter(guac.routing.websocket_urlpatterns)),
    }
)

# Add / and /web (relative to CAPE install location) to our path
webdir = abspath(join(dirname(abspath(__file__)), ".."))
sys.path.append(abspath(join(webdir, "..")))
sys.path.append(webdir)

chdir(webdir)
