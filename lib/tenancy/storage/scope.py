"""Tenancy-aware viewer scope resolution for object-storage artifact serving.

`[object_storage]` and `[multitenancy]` are orthogonal toggles:
- When `[multitenancy] enabled = no`: `viewer_scope(user)` returns `None` (unrestricted)
  and `viewer_can_view_sample(...)` returns `True`.
- When `[multitenancy] enabled = yes`: `viewer_scope(user)` returns the MongoDB `$match`
  predicate for `user`, and `viewer_can_view_sample(...)` verifies the user can read at
  least one task associated with the sample hash.
"""

from __future__ import annotations

from typing import Any, Optional

from lib.tenancy.context import get_current_viewer
from lib.tenancy.middleware import default_viewer_resolver
from lib.tenancy.policy import multitenancy_config, viewer_scope_match


def viewer_scope(user: Any) -> Optional[dict[str, Any]]:
    """Return the MongoDB `$match` restricting object-storage results to what `user` may read, or `None`."""
    try:
        if not multitenancy_config().enabled:
            return None
        viewer = get_current_viewer()
        if viewer is None or (user is not None and getattr(user, "id", None) != viewer.user_id):
            viewer = default_viewer_resolver(user)
        return viewer_scope_match(viewer)
    except Exception:
        return {"_id": {"$in": []}}


def viewer_can_view_sample(
    user: Any,
    *,
    sha256: Optional[str] = None,
    sha1: Optional[str] = None,
    md5: Optional[str] = None,
    sample_id: Optional[int] = None,
) -> bool:
    """Return True if `user` may view the sample identified by hash or `sample_id`."""
    try:
        if not multitenancy_config().enabled:
            return True
        viewer = get_current_viewer()
        if viewer is None or (user is not None and getattr(user, "id", None) != viewer.user_id):
            viewer = default_viewer_resolver(user)
        if viewer.see_all:
            return True

        scope = viewer_scope_match(viewer)
        if scope is None:
            return True

        from dev_utils.mongodb import mongo_find_one

        hash_q: dict[str, Any] = {}
        if sha256:
            hash_q["target.file.sha256"] = sha256.lower()
        elif sha1:
            hash_q["target.file.sha1"] = sha1.lower()
        elif md5:
            hash_q["target.file.md5"] = md5.lower()
        elif sample_id is not None:
            hash_q["target.file.id"] = int(sample_id)
        if not hash_q:
            return False

        doc = mongo_find_one("analysis", {"$and": [hash_q, scope]}, {"_id": 1})
        return doc is not None
    except Exception:
        return False
