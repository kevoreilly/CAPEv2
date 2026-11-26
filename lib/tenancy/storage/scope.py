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


def _mongodb_enabled() -> bool:
    try:
        from lib.cuckoo.common.config import Config

        return bool(Config("reporting").mongodb.enabled)
    except Exception:
        return False


def _elasticsearch_enabled() -> bool:
    try:
        from lib.cuckoo.common.config import Config

        return bool(Config("reporting").elasticsearchdb.enabled)
    except Exception:
        return False


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

        sample_filter: dict[str, Any] = {}
        hash_q: dict[str, Any] = {}
        if sha256:
            val = sha256.lower()
            sample_filter["sha256"] = val
            hash_q["target.file.sha256"] = val
        elif sha1:
            val = sha1.lower()
            sample_filter["sha1"] = val
            hash_q["target.file.sha1"] = val
        elif md5:
            val = md5.lower()
            sample_filter["md5"] = val
            hash_q["target.file.md5"] = val
        elif sample_id is not None:
            val_int = int(sample_id)
            sample_filter["sample_id"] = val_int
            hash_q["target.file.id"] = val_int
        if not hash_q:
            return False

        if _mongodb_enabled():
            from dev_utils.mongodb import mongo_find_one

            doc = mongo_find_one("analysis", {"$and": [hash_q, scope]}, {"_id": 1})
            return doc is not None

        if _elasticsearch_enabled():
            try:
                from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index
                from lib.tenancy.policy import viewer_scope_es_filter

                field_name, field_val = next(iter(hash_q.items()))
                filters: list[dict[str, Any]] = [{"term": {field_name: field_val}}]
                es_filter = viewer_scope_es_filter(viewer)
                if es_filter:
                    filters.append(es_filter)
                res = elastic_handler.search(
                    index=get_analysis_index(),
                    body={"query": {"bool": {"filter": filters}}, "size": 1},
                )
                if (res or {}).get("hits", {}).get("hits"):
                    return True
            except Exception:
                pass

        from lib.tenancy.middleware import default_sample_access_checker

        return bool(default_sample_access_checker(viewer, sample_filter))
    except Exception:
        return False
