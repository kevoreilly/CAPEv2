from django.apps import AppConfig


class ApiKeyConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apikey"
    verbose_name = "API Keys"

    def ready(self):
        # Import signal handlers so the disable-cascades-revoke handler
        # gets registered. Importing inside ready() avoids the standard
        # "models not yet loaded" startup pitfall.
        from . import signals  # noqa: F401
