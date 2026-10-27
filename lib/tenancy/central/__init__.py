"""Backward-compatible `lib.tenancy.central` alias package pointing to `lib.tenancy.storage`."""

import sys

from lib.tenancy.storage import (
    artifact_storage,
    config,
    guac,
    job_directory,
    reporting,
    scope,
    storage_backend,
    views,
)
from lib.tenancy.storage import *  # noqa: F401,F403

for _sub_name, _sub_mod in (
    ("artifact_storage", artifact_storage),
    ("config", config),
    ("guac", guac),
    ("job_directory", job_directory),
    ("reporting", reporting),
    ("scope", scope),
    ("storage_backend", storage_backend),
    ("views", views),
):
    sys.modules.setdefault(f"{__name__}.{_sub_name}", _sub_mod)
    sys.modules.setdefault(f"cape_tenancy.central.{_sub_name}", _sub_mod)

sys.modules.setdefault("cape_tenancy.central", sys.modules[__name__])
