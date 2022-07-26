# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
WSGI config for web project.

This module contains the WSGI application used by Django's development server
and any production WSGI deployments. It should expose a module-level variable
named ``application``. Django's ``runserver_plus`` and ``runfcgi`` commands discover
this application via the ``WSGI_APPLICATION`` setting.

Usually you will have the standard Django WSGI application here, but it also
might make sense to replace the whole Django WSGI application with a custom one
that later delegates to the Django one. For example, you could introduce WSGI
middleware here, or combine a Django application with an application of another
framework.

"""

# These lines ensure that imports used by the WSGI daemon can be found
import sys
from os.path import abspath, dirname, join

# Add / and /web (relative to cuckoo-modified install location) to our path
webdir = abspath(join(dirname(abspath(__file__)), ".."))
sys.path.append(abspath(join(webdir, "..")))
sys.path.append(webdir)

# Have WSGI run out of the WebDir
from os import chdir, environ

chdir(webdir)

# Set django settings
environ.setdefault("DJANGO_SETTINGS_MODULE", "web.settings")

# This application object is used by any WSGI server configured to use this
# file. This includes Django's development server, if the WSGI_APPLICATION
# setting points here.
from django.core.wsgi import get_wsgi_application

application = get_wsgi_application()
