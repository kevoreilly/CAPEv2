# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import os
import sys
from contextlib import suppress
from pathlib import Path

if os.geteuid() == 0 and os.getenv("CAPE_AS_ROOT", "0") != "1":
    sys.exit("Root is not allowed. You gonna break permission and other parts of CAPE. RTM!")

# Cuckoo path.
CUCKOO_PATH = os.path.join(Path.cwd(), "..")
sys.path.append(CUCKOO_PATH)

BASE_DIR = Path(__file__).resolve().parent.parent

RUNNING_TESTS = "test" in sys.argv

from lib.cuckoo.common.config import Config

# In case we have VPNs enabled we need to initialize through the following
# two methods as they verify the interaction with VPNs as well as gather
# which VPNs are available (for representation upon File/URL submission).
# if not RUNNING_TESTS:
from lib.cuckoo.core.startup import init_rooter, init_routing

init_rooter()
init_routing()


cfg = Config("reporting")
aux_cfg = Config("auxiliary")
web_cfg = Config("web")
api_cfg = Config("api")

REPROCESS_TASKS = web_cfg.general.reprocess_tasks
# CSRF TRUSTED ORIGINS
# For requests that include the Origin header, Django's CSRF protection
# requires that header match the origin present in the Host header.

csfr_list = []
if web_cfg.security.csrf_trusted_origins:
    for host in web_cfg.security.csrf_trusted_origins.split(","):
        csfr_list.extend([f"http://{host}", f"https://{host}"])

CSRF_TRUSTED_ORIGINS = csfr_list
# CSRF_COOKIE_SECURE = "True"

# If reporting is enabled via the web GUI, then require one of these to be enabled
if web_cfg.web_reporting.get("enabled", True):
    # Error handling for database backends
    if not cfg.mongodb.get("enabled") and not cfg.elasticsearchdb.get("enabled"):
        raise Exception("No database backend reporting module is enabled! Please enable either ElasticSearch or MongoDB.")

    if cfg.mongodb.get("enabled") and cfg.elasticsearchdb.get("enabled") and not cfg.elasticsearchdb.get("searchonly"):
        raise Exception("Both database backend reporting modules are enabled. Please only enable ElasticSearch or MongoDB.")

WEB_AUTHENTICATION = web_cfg.web_auth.get("enabled", False)
WEB_OAUTH = web_cfg.oauth

# Get connection options from reporting.conf.
MONGO_HOST = cfg.mongodb.get("host", "127.0.0.1")
MONGO_PORT = cfg.mongodb.get("port", 27017)
MONGO_DB = cfg.mongodb.get("db", "cuckoo")
MONGO_USER = cfg.mongodb.get("username")
MONGO_PASS = cfg.mongodb.get("password")
MONGO_AUTHSOURCE = cfg.mongodb.get("authsource", "cuckoo")

ELASTIC_HOST = cfg.elasticsearchdb.get("host", "127.0.0.1")
ELASTIC_PORT = cfg.elasticsearchdb.get("port", 9200)
ELASTIC_INDEX = cfg.elasticsearchdb.get("index", "cuckoo")
ELASTIC_USER = cfg.elasticsearchdb.get("username", None)
ELASTIC_PASS = cfg.elasticsearchdb.get("password", None)
ELASTIC_USE_SSL = cfg.elasticsearchdb.get("use_ssl", None)
ELASTIC_VERIFY_CERTS = cfg.elasticsearchdb.get("verify_certs", None)

moloch_cfg = cfg.moloch
zip_cfg = web_cfg.zipped_download

URL_ANALYSIS = web_cfg.url_analysis.get("enabled", False)
DLNEXEC = web_cfg.dlnexec.get("enabled", False)
ZIP_PWD = zip_cfg.get("zip_pwd", b"infected")
if not isinstance(ZIP_PWD, bytes):
    ZIP_PWD = ZIP_PWD.encode()
ZIPPED_DOWNLOAD_ALL = zip_cfg.get("download_all", False)
MOLOCH_BASE = moloch_cfg.get("base")
MOLOCH_NODE = moloch_cfg.get("node")
MOLOCH_ENABLED = moloch_cfg.get("enabled", False)

VTDL_ENABLED = web_cfg.download_services.get("virustotal", False)
VTDL_KEY = web_cfg.download_services.get("vtkey", False)

BAZAAR_ENABLED = web_cfg.download_services.get("malwarebazaar", False)

TEMP_PATH = Config().cuckoo.get("tmppath", "/tmp")

# DEPRECATED - Enabled/Disable Zer0m0n tickbox on the submission page
OPT_ZER0M0N = False

COMMENTS = web_cfg.comments.enabled
ADMIN = web_cfg.admin.enabled
ANON_VIEW = web_cfg.general.anon_viewable
ALLOW_DL_REPORTS_TO_ALL = web_cfg.general.reports_dl_allowed_to_all

# If false run next command
# python3 manage.py runserver_plus 0.0.0.0:8000 --traceback --keep-meta-shutdown
DEBUG = True

# Database settings. We don't need it.
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "siteauth.sqlite"}}

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# Deprecated in Django 5.0
# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale.
USE_L10N = True

# Disabling time zone support and using local time for web interface and storage.
# https://docs.djangoproject.com/en/4.0/topics/i18n/
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# Unique secret key generator.
# Secret key will be placed in secret_key.py file.
try:
    from .secret_key import SECRET_KEY  # noqa: F401
except ImportError:
    SETTINGS_DIR = os.path.abspath(os.path.dirname(__file__))
    # Using the same generation schema of Django startproject.
    from django.utils.crypto import get_random_string

    key = get_random_string(50, "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)")

    # Write secret_key.py
    _ = Path(os.path.join(SETTINGS_DIR, "secret_key.py")).write_text(f'SECRET_KEY = "{key}"')

    # Reload key.
    from .secret_key import SECRET_KEY  # noqa: F401

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
MEDIA_ROOT = ""

# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = ""

# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/home/media/media.lawrence.com/static/"
STATIC_ROOT = ""

# URL prefix for static files.
# Example: "http://media.lawrence.com/static/"
STATIC_URL = "/static/"

# Additional locations of static files
STATICFILES_DIRS = (os.path.join(Path.cwd(), "static"),)

# List of finder classes that know how to find static files in
# various locations.
STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
    #    'django.contrib.staticfiles.finders.DefaultStorageFinder',
)

# Template class for starting w. django 1.10
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            "templates",
        ],
        "OPTIONS": {
            "debug": True,
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.debug",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.template.context_processors.request",
                "django.contrib.messages.context_processors.messages",
                "django_settings_export.settings_export",
            ],
            "loaders": [
                "django.template.loaders.filesystem.Loader",
                "django.template.loaders.app_directories.Loader",
            ],
        },
    },
]


MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Cuckoo headers.
    "web.headers.CuckooHeaders",
    #'web.middleware.ExceptionMiddleware',
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # 'django_otp.middleware.OTPMiddleware',
    # in case you want custom auth, place logic in web/web/middleware.py
    # "web.middleware.CustomAuth",
]

OTP_TOTP_ISSUER = "CAPE Sandbox"

# Header/protection related
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = "DENY"

ROOT_URLCONF = "web.urls"

# Python dotted path to the WSGI application used by Django's runserver_plus.
WSGI_APPLICATION = "web.wsgi.application"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    #'django.contrib.sites',
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # Uncomment the next line to enable the admin:
    "django.contrib.admin",
    # Uncomment the next line to enable admin documentation:
    # 'django.contrib.admindocs',
    "analysis",
    "compare",
    "apiv2",
    "users",
    "django_extensions",
    # 'django_otp',
    # 'django_otp.plugins.otp_totp',
    # allauth
    "django.contrib.sites",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
    "allauth.socialaccount.providers.agave",
    "allauth.socialaccount.providers.amazon",
    "allauth.socialaccount.providers.amazon_cognito",
    "allauth.socialaccount.providers.angellist",
    "allauth.socialaccount.providers.apple",
    "allauth.socialaccount.providers.asana",
    "allauth.socialaccount.providers.auth0",
    "allauth.socialaccount.providers.authentiq",
    "allauth.socialaccount.providers.azure",
    "allauth.socialaccount.providers.baidu",
    "allauth.socialaccount.providers.basecamp",
    "allauth.socialaccount.providers.battlenet",
    "allauth.socialaccount.providers.bitbucket",
    "allauth.socialaccount.providers.bitbucket_oauth2",
    "allauth.socialaccount.providers.bitly",
    "allauth.socialaccount.providers.box",
    "allauth.socialaccount.providers.cern",
    "allauth.socialaccount.providers.coinbase",
    "allauth.socialaccount.providers.dataporten",
    "allauth.socialaccount.providers.daum",
    "allauth.socialaccount.providers.digitalocean",
    "allauth.socialaccount.providers.discord",
    "allauth.socialaccount.providers.disqus",
    "allauth.socialaccount.providers.douban",
    "allauth.socialaccount.providers.doximity",
    "allauth.socialaccount.providers.draugiem",
    "allauth.socialaccount.providers.dropbox",
    "allauth.socialaccount.providers.dwolla",
    "allauth.socialaccount.providers.edmodo",
    "allauth.socialaccount.providers.edx",
    "allauth.socialaccount.providers.eventbrite",
    "allauth.socialaccount.providers.eveonline",
    "allauth.socialaccount.providers.evernote",
    "allauth.socialaccount.providers.exist",
    "allauth.socialaccount.providers.facebook",
    "allauth.socialaccount.providers.feedly",
    "allauth.socialaccount.providers.figma",
    "allauth.socialaccount.providers.fivehundredpx",
    "allauth.socialaccount.providers.flickr",
    "allauth.socialaccount.providers.foursquare",
    "allauth.socialaccount.providers.fxa",
    "allauth.socialaccount.providers.github",
    "allauth.socialaccount.providers.gitlab",
    "allauth.socialaccount.providers.globus",
    "allauth.socialaccount.providers.google",
    "allauth.socialaccount.providers.hubic",
    "allauth.socialaccount.providers.instagram",
    "allauth.socialaccount.providers.jupyterhub",
    "allauth.socialaccount.providers.kakao",
    "allauth.socialaccount.providers.keycloak",
    "allauth.socialaccount.providers.line",
    "allauth.socialaccount.providers.linkedin",
    "allauth.socialaccount.providers.linkedin_oauth2",
    "allauth.socialaccount.providers.mailchimp",
    "allauth.socialaccount.providers.mailru",
    "allauth.socialaccount.providers.meetup",
    "allauth.socialaccount.providers.microsoft",
    "allauth.socialaccount.providers.naver",
    "allauth.socialaccount.providers.nextcloud",
    "allauth.socialaccount.providers.odnoklassniki",
    "allauth.socialaccount.providers.openid",
    "allauth.socialaccount.providers.openstreetmap",
    "allauth.socialaccount.providers.orcid",
    "allauth.socialaccount.providers.patreon",
    "allauth.socialaccount.providers.paypal",
    "allauth.socialaccount.providers.persona",
    "allauth.socialaccount.providers.pinterest",
    "allauth.socialaccount.providers.quickbooks",
    "allauth.socialaccount.providers.reddit",
    "allauth.socialaccount.providers.robinhood",
    "allauth.socialaccount.providers.salesforce",
    "allauth.socialaccount.providers.sharefile",
    "allauth.socialaccount.providers.shopify",
    "allauth.socialaccount.providers.slack",
    "allauth.socialaccount.providers.soundcloud",
    "allauth.socialaccount.providers.spotify",
    "allauth.socialaccount.providers.stackexchange",
    "allauth.socialaccount.providers.steam",
    "allauth.socialaccount.providers.stocktwits",
    "allauth.socialaccount.providers.strava",
    "allauth.socialaccount.providers.stripe",
    "allauth.socialaccount.providers.telegram",
    "allauth.socialaccount.providers.trello",
    "allauth.socialaccount.providers.tumblr",
    "allauth.socialaccount.providers.twentythreeandme",
    "allauth.socialaccount.providers.twitch",
    "allauth.socialaccount.providers.twitter",
    "allauth.socialaccount.providers.untappd",
    "allauth.socialaccount.providers.vimeo",
    "allauth.socialaccount.providers.vimeo_oauth2",
    "allauth.socialaccount.providers.vk",
    "allauth.socialaccount.providers.weibo",
    "allauth.socialaccount.providers.weixin",
    "allauth.socialaccount.providers.windowslive",
    "allauth.socialaccount.providers.xing",
    "allauth.socialaccount.providers.yahoo",
    "allauth.socialaccount.providers.yandex",
    "allauth.socialaccount.providers.ynab",
    "allauth.socialaccount.providers.zoho",
    "allauth.socialaccount.providers.zoom",
    "allauth.socialaccount.providers.okta",
    "crispy_forms",
    "captcha",  # https://pypi.org/project/django-recaptcha/
    "rest_framework",
    "rest_framework.authtoken",
]

if api_cfg.api.token_auth_enabled:
    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [
            "rest_framework.authentication.TokenAuthentication",
            "rest_framework.authentication.SessionAuthentication",
        ],
        "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
        "DEFAULT_THROTTLE_CLASSES": ["apiv2.throttling.SubscriptionRateThrottle"],
        "DEFAULT_THROTTLE_RATES": {
            "user": api_cfg.api.default_user_ratelimit,
            "subscription": api_cfg.api.default_subscription_ratelimit,
        },
    }

else:
    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [],
        "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.AllowAny"],
    }

TWOFA = web_cfg.web_auth.get("2fa", False)

NOCAPTCHA = web_cfg.web_auth.get("captcha", False)
# create your keys here -> https://www.google.com/recaptcha/about/
RECAPTCHA_PRIVATE_KEY = "TEST_PUBLIC_KEY"
RECAPTCHA_PUBLIC_KEY = "TEST_PRIVATE_KEY"
RECAPTCHA_DEFAULT_ACTION = "generic"
RECAPTCHA_REQUIRED_SCORE = 0.85

# RECAPTCHA_DOMAIN = 'www.recaptcha.net'

CRISPY_TEMPLATE_PACK = "bootstrap4"

AUTHENTICATION_BACKENDS = (
    # used for default signin such as loggin into admin panel
    "django.contrib.auth.backends.ModelBackend",
    # used for social authentications
    "allauth.account.auth_backends.AuthenticationBackend",
)

SETTINGS_EXPORT = [
    "WEB_AUTHENTICATION",
    "WEB_OAUTH",
    "ZIPPED_DOWNLOAD_ALL",
]

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
if web_cfg.registration.get("email_confirmation", False):
    EMAIL_HOST = web_cfg.registration.get("email_host", False)
    EMAIL_HOST_USER = web_cfg.registration.get("email_user", False)
    EMAIL_HOST_PASSWORD = web_cfg.registration.get("email_password", False)
    EMAIL_PORT = web_cfg.registration.get("email_port", 465)
    EMAIL_TLS_SSL = web_cfg.registration.get("use_tls", False)
    EMAIL_USE_SSL = web_cfg.registration.get("use_ssl", False)
    SERVER_EMAIL = EMAIL_HOST_USER
    DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

SITE_ID = 1

# https://django-allauth.readthedocs.io/en/latest/configuration.html
if web_cfg.registration.get("email_confirmation", False):
    ACCOUNT_EMAIL_VERIFICATION = "mandatory"
    SOCIALACCOUNT_EMAIL_VERIFICATION = ACCOUNT_EMAIL_VERIFICATION
else:
    ACCOUNT_EMAIL_VERIFICATION = "none"
    SOCIALACCOUNT_EMAIL_VERIFICATION = ACCOUNT_EMAIL_VERIFICATION

ACCOUNT_EMAIL_REQUIRED = web_cfg.registration.get("email_required", False)
ACCOUNT_EMAIL_SUBJECT_PREFIX = web_cfg.registration.get("email_prefix_subject", False)
ACCOUNT_LOGIN_ATTEMPTS_LIMIT = 3
LOGIN_REDIRECT_URL = "/"
ACCOUNT_LOGOUT_REDIRECT_URL = "/accounts/login/"
MANUAL_APPROVE = web_cfg.registration.get("manual_approve", False)
REGISTRATION_ENABLED = web_cfg.registration.get("enabled", False)
EMAIL_CONFIRMATION = web_cfg.registration.get("email_confirmation", False)
#### ALlauth end

if web_cfg.registration.get("disposable_email_disable", False):
    DISPOSABLE_DOMAIN_LIST = os.path.join(CUCKOO_PATH, web_cfg.registration.disposable_domain_list)
    ACCOUNT_ADAPTER = "web.allauth_adapters.DisposableEmails"

if web_cfg.registration.get("captcha_enabled", False):
    ACCOUNT_SIGNUP_FORM_CLASS = "web.allauth_forms.CaptchedSignUpForm"

# Fix to avoid migration warning in django 1.7 about test runner (1_6.W001).
# In future it could be removed: https://code.djangoproject.com/ticket/23469
TEST_RUNNER = "django.test.runner.DiscoverRunner"

# A sample logging configuration. The only tangible logging
# performed by this configuration is to send an email to
# the site admins on every HTTP 500 error when DEBUG=False.
# See http://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
# if not RUNNING_TESTS:
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "filters": {"require_debug_false": {"()": "django.utils.log.RequireDebugFalse"}},
    "handlers": {
        "mail_admins": {"level": "ERROR", "filters": ["require_debug_false"], "class": "django.utils.log.AdminEmailHandler"}
    },
    "loggers": {
        "django.request": {
            "handlers": ["mail_admins"],
            "level": "ERROR",
            "propagate": True,
        },
    },
}

SILENCED_SYSTEM_CHECKS = [
    "admin.E408",
    "models.W042",
    #'captcha.recaptcha_test_key_error'
]

ALLOWED_HOSTS = ["*"]

# Max size
MAX_UPLOAD_SIZE = web_cfg.general.max_sample_size

SECURE_REFERRER_POLICY = "same-origin"  # "no-referrer-when-downgrade"

# https://django-csp.readthedocs.io/en/latest/configuration.html
CSP_DEFAULT_SRC = ["'self'"]
# When DEBUG is on we don't require HTTPS on our resources because in a local environment
# we generally don't have access to HTTPS. However, when DEBUG is off, such as in our
# production environment, we want all our resources to load over HTTPS
CSP_UPGRADE_INSECURE_REQUESTS = not DEBUG
# For roughly 60% of the requests to our django server we should include the report URI.
# This helps keep down the number of CSP reports sent from client web browsers
CSP_REPORT_PERCENTAGE = 0.6
CSP_FONT_SRC = ["https://fonts.googleapis.com"]
CSP_STYLE_SRC = ["'self'"]
CSP_IMG_SRC = ["'self'"]

RATELIMIT_ERROR_MSG = "Too many request without auth! You have exceed your free request per minute for anon users. We are researcher friendly and provide api, but if you buy a good whiskey to @doomedraven, we will be even more friendlier ;). Limits can be changed in conf/api.conf"

# Hack to import local settings.
try:
    LOCAL_SETTINGS
except NameError:
    with suppress(ImportError):
        from .local_settings import *  # noqa: F403
