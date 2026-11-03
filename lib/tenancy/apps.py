"""Django AppConfig for `lib.tenancy`."""

import sys

try:
    from django.apps import AppConfig
except ImportError:

    class AppConfig:  # type: ignore[no-redef]
        def __init__(self, *args, **kwargs):
            pass


sys.modules.setdefault("cape_tenancy.apps", sys.modules[__name__])


class CapeTenancyConfig(AppConfig):
    name = "lib.tenancy"
    label = "cape_tenancy"
    verbose_name = "CAPE Multi-Tenancy & Object Storage"
    default_auto_field = "django.db.models.BigAutoField"

    def ready(self) -> None:
        from lib.tenancy.hooks import (
            default_mongo_analysis_filter,
            register_core_hooks,
            register_mongo_filter,
            wrap_mongodb_module,
        )

        register_mongo_filter(default_mongo_analysis_filter)
        register_core_hooks()
        try:
            import dev_utils.mongodb as mongodb_mod

            wrap_mongodb_module(mongodb_mod)
        except ImportError:
            pass
