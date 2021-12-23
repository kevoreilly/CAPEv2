from __future__ import absolute_import

# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
ASGI config for web project.
Please read https://channels.readthedocs.io/en/latest/deploying.html#nginx-supervisor-ubuntu
"""

# These lines ensure that imports used by the ASGI daemon can be found
import sys
from os.path import join, dirname, abspath

# Add / and /web (relative to cuckoo-modified install location) to our path
webdir = abspath(join(dirname(abspath(__file__)), ".."))
sys.path.append(abspath(join(webdir, "..")))
sys.path.append(webdir)

# Have ASGI run out of the WebDir
from os import chdir, environ

chdir(webdir)

# Set django settings
environ.setdefault("DJANGO_SETTINGS_MODULE", "web.settings")

# This application object is used by any ASGI server configured to use this
# file. This includes Django's development server, if the ASGI_APPLICATION
# setting points here.
from django.core.asgi import get_asgi_application

application = get_asgi_application()
