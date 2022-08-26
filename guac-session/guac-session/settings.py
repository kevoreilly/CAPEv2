import logging.config
import os
from distutils.util import strtobool
from json import loads
from pathlib import Path

from django.utils.log import DEFAULT_LOGGING
from dotenv import load_dotenv

load_dotenv()
# Build paths inside the project like this: BASE_DIR / "subdir".
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!

# Unique secret key generator.
# Secret key will be placed in secret_key.py file.
try:
    from .secret_key import *
except ImportError:
    SETTINGS_DIR = os.path.abspath(os.path.dirname(__file__))
    # Using the same generation schema of Django startproject.
    from django.utils.crypto import get_random_string

    key = get_random_string(50, "abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*(-_=+)")

    # Write secret_key.py
    with open(os.path.join(SETTINGS_DIR, "secret_key.py"), "w") as key_file:
        key_file.write('SECRET_KEY = "{0}"'.format(key))

    # Reload key.
    from .secret_key import *


# SECURITY WARNING: don"t run with debug turned on in production!
DEBUG = bool(strtobool(os.environ.get("GUACAMOLE_DEBUG", "false")))

LOGGING_CONFIG = None

if DEBUG:
    LOG_LEVEL = "DEBUG"
else:
    LOG_LEVEL = os.environ.get("GUACAMOLE_LOG_LEVEL", "info").upper()

allowed_hosts = os.environ.get("GUACAMOLE_ALLOWED_HOSTS", '["*",]')
ALLOWED_HOSTS = loads(allowed_hosts)

# Application definition

INSTALLED_APPS = [
    "channels",
    "guac",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_extensions",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "guac-session.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

ASGI_APPLICATION = "guac-session.asgi.application"


# Database
# https://docs.djangoproject.com/en/4.0/ref/settings/#databases

"""
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql_psycopg2",
        "NAME": "guactest",
        "USER": "guacuser",
        "PASSWORD": "guactest",
        "HOST": "localhost",
    }
}
"""

# Password validation
# https://docs.djangoproject.com/en/4.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": ("django.contrib.auth.password_validation.UserAttributeSimilarityValidator"),
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


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

# Default primary key field type
# https://docs.djangoproject.com/en/4.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
