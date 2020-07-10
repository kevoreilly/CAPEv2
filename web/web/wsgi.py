from __future__ import absolute_import

# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
WSGI config for web project.

This module contains the WSGI application used by Django's development server
and any production WSGI deployments. It should expose a module-level variable
named ``application``. Django's ``runserver`` and ``runfcgi`` commands discover
this application via the ``WSGI_APPLICATION`` setting.

Usually you will have the standard Django WSGI application here, but it also
might make sense to replace the whole Django WSGI application with a custom one
that later delegates to the Django one. For example, you could introduce WSGI
middleware here, or combine a Django application with an application of another
framework.

"""

"""

:: Correctly setting up WSGI w/ Apache2, using only HTTPS. Start here.

You can use the following command to generate SSL certs for an HTTPS setup.
# sudo openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout \
    /etc/apache2/ssl/cert.key -out /etc/apache2/ssl/cert.crt

The following Apache2 vhost will work plug-and-play with the above command
// Begin Apache2 config for WSGI usage

<VirtualHost *:80>
        RewriteEngine On
        RewriteCond %{HTTPS} off
        RewriteRule (.*) https://%{HTTP_HOST}%{REQUEST_URI}
</VirtualHost>

<VirtualHost *:443>

        # Remember to change paths where necessary

        SSLEngine On
        SSLCertificateFile      /etc/apache2/ssl/cert.crt
        SSLCertificateKeyFile   /etc/apache2/ssl/cert.key

        # WARNING :: I haven't looked to ensure that all libs in use are threadsafe
        #   If you have some free ram, keep your threadcount at 1; spawn processes
        #   You've been warned. Weird things may happen...
        WSGIDaemonProcess web processes=5 threads=20

        WSGIScriptAlias         /       /opt/cuckoo/cuckoo-modified/web/web/wsgi.py

        <Directory /opt/cuckoo/cuckoo-modified/web>
                Require         all     granted
                WSGIScriptReloading On
        </Directory>

        Alias /static /opt/cuckoo/cuckoo-modified/web/static

        ErrorLog        ${APACHE_LOG_DIR}/error.log
        LogLevel        error
        CustomLog       ${APACHE_LOG_DIR}/access.log    combined

</VirtualHost>

// End Apache2 config for WSGI usage
"""

# These lines ensure that imports used by the WSGI daemon can be found
import sys
from os.path import join, dirname, abspath

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
