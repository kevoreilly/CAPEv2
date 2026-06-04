# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

LOCAL_SETTINGS = True
from .settings import *  # noqa: F403

# If you want to customize your cuckoo path set it here.
# CUCKOO_PATH = "/where/cuckoo/is/placed/"

# Override default secret key stored in secret_key.py
# Make this unique, and don't share it with anybody.
# SECRET_KEY = "YOUR_RANDOM_KEY"

# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = "en-us"

ADMINS = (
    # ("Your Name", "your_email@example.com"),
)

MANAGERS = ADMINS

# Allow verbose debug error message in case of application fault.
# It's strongly suggested to set it to False if you are serving the
# web application from a web server front-end (i.e. Apache).
DEBUG = True

# A list of strings representing the host/domain names that this Django site
# can serve.
# Values in this list can be fully qualified names (e.g. 'www.example.com').
# When DEBUG is True or when running tests, host validation is disabled; any
# host will be accepted. Thus it's usually only necessary to set it in production.
ALLOWED_HOSTS = ["*"]

# Uncomment for deployment with NGINX
# STATIC_ROOT = ""
# STATIC_ROOT = os.path.join(os.getcwd(), "static")

# SOCIALACCOUNT_PROVIDERS removed: managed dynamically from web.conf [oauth_oidc] in settings.py.
# The previous stub here (google + github) was dead — the provider apps were commented out in INSTALLED_APPS.

# Session lifetime: 8-hour sliding idle timeout. SESSION_SAVE_EVERY_REQUEST
# resets the SESSION_COOKIE_AGE window on each request, so the session expires
# only after 8h of *inactivity* (not 8h absolute). Combined with django-allauth
# + Okta SSO, an idle user is forced back through Okta, capping the gap between
# an Okta account disable/lockout and CAPE access being revoked. Note: saving
# the session every request adds session-store writes; fine for this scale.
SESSION_COOKIE_AGE = 28800
SESSION_SAVE_EVERY_REQUEST = True
