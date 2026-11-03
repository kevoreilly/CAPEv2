"""`lib.tenancy`: Self-contained Multi-Tenancy and Cloud Object Storage (`s3`, `gcs`, `azure`, `local`) for CAPEv2.

Both `[multitenancy]` and `[object_storage]` default to `enabled = no` in `conf/cuckoo.conf`
and can be enabled independently or together. Also registers `cape_tenancy` in `sys.modules`
for backward compatibility.
"""

from __future__ import annotations

import sys
from typing import Any, MutableMapping

# Register `cape_tenancy` module alias before importing submodules so both `lib.tenancy.*`
# and `cape_tenancy.*` resolve to the identical module objects.
sys.modules.setdefault("cape_tenancy", sys.modules[__name__])

from lib.tenancy import (  # noqa: E402
    acl,
    backfill,
    central,
    context,
    context_processors,
    hooks,
    middleware,
    policy,
    resources,
    storage,
    urls,
    views,
)

for _mod_name, _mod_obj in (
    ("acl", acl),
    ("backfill", backfill),
    ("central", central),
    ("context", context),
    ("context_processors", context_processors),
    ("hooks", hooks),
    ("middleware", middleware),
    ("policy", policy),
    ("resources", resources),
    ("storage", storage),
    ("urls", urls),
    ("views", views),
):
    sys.modules.setdefault(f"cape_tenancy.{_mod_name}", _mod_obj)

from lib.tenancy.acl import (  # noqa: E402
    TaskAcl,
    VisibilityConflictError,
    VisibilityStamp,
    ensure_acl_schema,
    get_task_acl,
    resolve_task_scope,
    set_task_acl,
    sync_stamp_to_mongo,
    toggle_task_visibility_cas,
)
from lib.tenancy.context import (  # noqa: E402
    entitlements_scope_context,
    get_current_entitlements,
    get_current_viewer,
    reset_current_entitlements,
    reset_current_viewer,
    set_current_entitlements,
    set_current_viewer,
    unscoped_context,
    viewer_scope_context,
)
from lib.tenancy.hooks import (  # noqa: E402
    apply_mongo_filters,
    default_es_query_filter,
    default_machine_list_filter,
    default_mongo_analysis_filter,
    default_report_stamp_hook,
    default_route_list_filter,
    default_sql_task_acl_clause,
    default_sql_task_query_filter,
    default_submission_context_filter,
    default_tag_list_filter,
    register_core_hooks,
    register_es_filter,
    register_mongo_filter,
    register_sql_filter,
    wrap_mongodb_module,
    wrap_submission_and_web_utils,
)
from lib.tenancy.middleware import (  # noqa: E402
    TenancyMiddleware,
    classify_view_action,
    default_viewer_resolver,
    tenancy_exempt,
)
from lib.tenancy.policy import (  # noqa: E402
    PRIVATE,
    PUBLIC,
    TENANT,
    VISIBILITIES,
    MultitenancyConfig,
    ResourceScope,
    ViewerContext,
    can_delete,
    can_read,
    can_set_visibility,
    can_toggle,
    multitenancy_config,
    scope_match,
    viewer_scope_es_filter,
    viewer_scope_match,
)
from lib.tenancy.resources import (  # noqa: E402
    ResourceEntitlements,
    filter_submission_form_context,
    merge_group_policies,
    reconcile_idp_groups_to_django_groups,
    resolve_user_entitlements,
    validate_and_normalize_submission,
)
from lib.tenancy.storage.config import (  # noqa: E402
    CentralModeConfig,
    ObjectStorageConfig,
    central_mode_config,
    object_storage_config,
)
from lib.tenancy.urls import get_urlpatterns, match_visibility_task_id  # noqa: E402
from lib.tenancy.views import (  # noqa: E402
    dispatch_central_view,
    dispatch_object_storage_view,
    tasks_set_visibility,
)

__version__ = "0.2.0"

APP_NAME = "lib.tenancy.apps.CapeTenancyConfig"
LEGACY_APP_NAME = "cape_tenancy.apps.CapeTenancyConfig"
MIDDLEWARE_PATH = "lib.tenancy.middleware.TenancyMiddleware"
LEGACY_MIDDLEWARE_PATH = "cape_tenancy.middleware.TenancyMiddleware"
CONTEXT_PROCESSOR_PATH = "lib.tenancy.context_processors.tenancy_context"
LEGACY_CONTEXT_PROCESSOR_PATH = "cape_tenancy.context_processors.tenancy_context"


def is_enabled() -> bool:
    """Return True if `[multitenancy] enabled = yes` OR `[object_storage] enabled = yes`."""
    try:
        if multitenancy_config().enabled:
            return True
    except Exception:
        pass
    try:
        if object_storage_config().enabled:
            return True
    except Exception:
        pass
    return False


def install(settings_globals: MutableMapping[str, Any], *, wrap_mongo: bool = True) -> None:
    """Mount `lib.tenancy` into CAPEv2's Django `settings.py` / `local_settings.py` namespace."""
    installed_apps = list(settings_globals.get("INSTALLED_APPS", []))
    if (
        APP_NAME not in installed_apps
        and LEGACY_APP_NAME not in installed_apps
        and "lib.tenancy" not in installed_apps
        and "cape_tenancy" not in installed_apps
    ):
        installed_apps.insert(0, APP_NAME)
        settings_globals["INSTALLED_APPS"] = installed_apps

    middleware_list = list(settings_globals.get("MIDDLEWARE", []))
    if MIDDLEWARE_PATH not in middleware_list and LEGACY_MIDDLEWARE_PATH not in middleware_list:
        middleware_list.append(MIDDLEWARE_PATH)
        settings_globals["MIDDLEWARE"] = middleware_list

    templates = settings_globals.get("TEMPLATES")
    if isinstance(templates, list):
        for tmpl in templates:
            opts = tmpl.setdefault("OPTIONS", {})
            processors = list(opts.get("context_processors", []))
            if CONTEXT_PROCESSOR_PATH not in processors and LEGACY_CONTEXT_PROCESSOR_PATH not in processors:
                processors.append(CONTEXT_PROCESSOR_PATH)
                opts["context_processors"] = processors

    register_mongo_filter(default_mongo_analysis_filter)
    register_core_hooks()

    if wrap_mongo:
        try:
            import dev_utils.mongodb as mongodb_mod

            wrap_mongodb_module(mongodb_mod)
        except ImportError:
            pass


__all__ = [
    "__version__",
    "is_enabled",
    "install",
    "PRIVATE",
    "PUBLIC",
    "TENANT",
    "VISIBILITIES",
    "MultitenancyConfig",
    "ObjectStorageConfig",
    "CentralModeConfig",
    "object_storage_config",
    "central_mode_config",
    "ViewerContext",
    "ResourceScope",
    "ResourceEntitlements",
    "can_read",
    "can_toggle",
    "can_delete",
    "can_set_visibility",
    "scope_match",
    "viewer_scope_match",
    "viewer_scope_es_filter",
    "multitenancy_config",
    "merge_group_policies",
    "resolve_user_entitlements",
    "filter_submission_form_context",
    "validate_and_normalize_submission",
    "reconcile_idp_groups_to_django_groups",
    "TaskAcl",
    "VisibilityStamp",
    "VisibilityConflictError",
    "ensure_acl_schema",
    "get_task_acl",
    "resolve_task_scope",
    "set_task_acl",
    "toggle_task_visibility_cas",
    "sync_stamp_to_mongo",
    "get_current_viewer",
    "set_current_viewer",
    "reset_current_viewer",
    "get_current_entitlements",
    "set_current_entitlements",
    "reset_current_entitlements",
    "viewer_scope_context",
    "entitlements_scope_context",
    "unscoped_context",
    "TenancyMiddleware",
    "default_viewer_resolver",
    "classify_view_action",
    "tenancy_exempt",
    "register_core_hooks",
    "register_mongo_filter",
    "register_sql_filter",
    "register_es_filter",
    "apply_mongo_filters",
    "default_mongo_analysis_filter",
    "default_es_query_filter",
    "default_sql_task_acl_clause",
    "default_sql_task_query_filter",
    "default_report_stamp_hook",
    "default_machine_list_filter",
    "default_tag_list_filter",
    "default_route_list_filter",
    "default_submission_context_filter",
    "wrap_mongodb_module",
    "wrap_submission_and_web_utils",
    "tasks_set_visibility",
    "dispatch_object_storage_view",
    "dispatch_central_view",
    "get_urlpatterns",
    "match_visibility_task_id",
]
