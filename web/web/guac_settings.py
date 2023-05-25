import logging.config
import os
import sys
from pathlib import Path

from django.utils.log import DEFAULT_LOGGING

CUCKOO_PATH = os.path.join(Path.cwd(), "..")
sys.path.append(CUCKOO_PATH)

# Build paths inside the project like this: BASE_DIR / "subdir".
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!

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

# SECURITY WARNING: don"t run with debug turned on in production!
DEBUG = True

LOGGING_CONFIG = None

ALLOWED_HOSTS = [
    "*",
]

INSTALLED_APPS = [
    "channels",
    "guac",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sessions",
    "django_extensions",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "web.guac_urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# Database settings. We don't need it.
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": "siteauth.sqlite"}}

ASGI_APPLICATION = "web.asgi.application"

# Internationalization
# https://docs.djangoproject.com/en/4.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.0/howto/static-files/

STATIC_URL = "/static/"

# Additional locations of static files
# STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]

STATIC_ROOT = os.path.join(BASE_DIR, "static")

STATICFILES_FINDERS = (
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
    #    "django.contrib.staticfiles.finders.DefaultStoragddeFinder",
)

LOG_LEVEL = "WARNING"
logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(levelname)s:%(name)s:%(message)s",
            },
            "django.server": DEFAULT_LOGGING["formatters"]["django.server"],
        },
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
            },
            "file": {
                "class": "logging.handlers.RotatingFileHandler",
                "filename": BASE_DIR / "guac-server.log",
                "formatter": "default",
                "maxBytes": 1024 * 1024 * 100,  # 100 mb
            },
            "gunicorn": {
                "class": "logging.handlers.RotatingFileHandler",
                "formatter": "default",
                "filename": BASE_DIR / "gunicorn.log",
                "maxBytes": 1024 * 1024 * 100,  # 100 mb
            },
            "django.server": DEFAULT_LOGGING["handlers"]["django.server"],
        },
        "loggers": {
            "": {
                "handlers": ["console"],
                "level": LOG_LEVEL,
                "propagate": True,
            },
            "django.utils.autoreload": {
                "handlers": ["console"],
                "level": "ERROR",
            },
            "django": {
                "handlers": ["file"],
                "level": LOG_LEVEL,
                "propagate": False,
            },
            "guac-session": {
                "handlers": ["file"],
                "level": LOG_LEVEL,
                "propagate": False,
            },
            "gunicorn.errors": {
                "level": LOG_LEVEL,
                "handlers": ["gunicorn"],
                "propagate": True,
            },
            "django.server": DEFAULT_LOGGING["loggers"]["django.server"],
        },
    }
)
