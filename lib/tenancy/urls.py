"""URL routing helpers for `lib.tenancy`."""

from __future__ import annotations

import re
from typing import Any, List, Optional

from lib.tenancy.views import tasks_set_visibility

VISIBILITY_PATH_RE = re.compile(r"^/?apiv2/tasks/visibility/(?P<task_id>[^/]+)/?$")


def match_visibility_task_id(path: str) -> Optional[str]:
    """Return the `task_id` segment if `path` matches `/apiv2/tasks/visibility/<task_id>/`."""
    m = VISIBILITY_PATH_RE.match(path or "")
    return m.group("task_id") if m else None


def get_urlpatterns() -> List[Any]:
    """Return Django `urlpatterns` for `lib.tenancy` endpoints."""
    from django.urls import re_path

    return [
        re_path(r"^apiv2/tasks/visibility/(?P<task_id>\d+)/$", tasks_set_visibility, name="cape_tenancy_task_visibility"),
    ]
