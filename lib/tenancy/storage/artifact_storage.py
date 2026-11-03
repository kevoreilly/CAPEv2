"""Filesystem <-> object-storage artifact seam (`s3`, `gcs`, `azure`, `local`).

When `[object_storage] enabled = no` (default), reads and streams directly from
`storage/analyses/<task_id>/<relpath>`. When `[object_storage] enabled = yes`, resolves
`task_id -> job_id` (enforcing viewer tenant scope when `[multitenancy]` is enabled) and
streams or lazily stages artifacts from `<prefix>/<job_id>/<relpath>` on the configured
backend (`S3Store`, `GCSStore`, `AzureBlobStore`, or `LocalFSStore`).
"""

from __future__ import annotations

import logging
import os
import re
from collections import OrderedDict
from typing import Any, Callable, Optional, Sequence

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.tenancy.storage.config import object_storage_bridge_required, object_storage_config
from lib.tenancy.storage.storage_backend import ArtifactNotFound, ArtifactStore, get_artifact_store

log = logging.getLogger(__name__)


def _local_analysis_path(task_id: Any, relpath: str) -> str:
    return os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), relpath)


def _safe_relpath(relpath: str) -> str:
    """Reject traversal, absolute paths, or backslashes before `relpath` becomes an object key."""
    from django.http import Http404

    if not relpath or relpath.startswith("/") or "\\" in relpath or ".." in relpath.split("/"):
        raise Http404(f"invalid artifact path: {relpath!r}")
    return relpath


_JOB_ID_CACHE: OrderedDict[str, str] = OrderedDict()
_JOB_ID_CACHE_MAX = 1024

_SAFE_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _is_safe_job_id(job_id: Any) -> bool:
    return isinstance(job_id, str) and _SAFE_JOB_ID_RE.match(job_id) is not None and ".." not in job_id


def job_id_from_custom(custom: Any) -> Optional[str]:
    """Parse the broker `job_id` out of a task's `custom` field."""
    if not custom:
        return None
    text = str(custom)
    first = text.split(",", 1)[0]
    if first.startswith("job_id="):
        v = first.split("=", 1)[1].strip()
        if v and _is_safe_job_id(v):
            return v
        if v:
            log.warning("object_storage: ignoring path-unsafe job_id=%r in submitted custom", v)
    token = text.strip()
    if token and "=" not in token and "," not in token and not re.match(r"^ui-\d+$", token):
        if _is_safe_job_id(token):
            return token
        if ".." in token or "/" in token:
            log.warning("object_storage: ignoring path-unsafe bare job_id token %r in submitted custom", token)
        else:
            log.debug("object_storage: bare custom %r is not a job_id; using scoped fallback", token)
    return None


def _rds_job_id(task_id: Any) -> Optional[str]:
    try:
        tid = int(task_id)
    except (TypeError, ValueError):
        return None
    try:
        from lib.cuckoo.core.database import Database

        t = Database().view_task(tid)
        return job_id_from_custom(getattr(t, "custom", None) if t else None)
    except Exception:
        log.exception("_rds_job_id: DB lookup failed for task %s; falling back to scoped resolution", tid)
        return None


def _job_id_for_task(task_id: Any, scope: Optional[dict[str, Any]] = None) -> str:
    """Resolve `task_id -> job_id` and authorize against `scope`."""
    from dev_utils.mongodb import mongo_find_one
    from django.http import Http404

    jid = _JOB_ID_CACHE.get(str(task_id))
    if jid is not None:
        try:
            _JOB_ID_CACHE.move_to_end(str(task_id))
        except KeyError:
            pass
    else:
        jid = _rds_job_id(task_id)
        if jid:
            _JOB_ID_CACHE[str(task_id)] = jid
            try:
                _JOB_ID_CACHE.move_to_end(str(task_id))
                if len(_JOB_ID_CACHE) > _JOB_ID_CACHE_MAX:
                    _JOB_ID_CACHE.popitem(last=False)
            except KeyError:
                pass

    if jid:
        if scope is not None:
            try:
                _own_unstamped = {"$and": [{"info.tenant_id": None}, {"info.id": int(task_id)}]}
                authq = {"$and": [{"info.job_id": jid}, {"$or": [scope, _own_unstamped]}]}
            except (TypeError, ValueError):
                authq = {"$and": [{"info.job_id": jid}, scope]}
            if not mongo_find_one("analysis", authq, {"_id": 1}):
                raise Http404("task not visible")
        return jid

    try:
        tid = int(task_id)
    except (TypeError, ValueError) as e:
        raise Http404("invalid task id") from e

    if scope is not None and object_storage_bridge_required():
        # Allow dist.py tasks that stamped info.job_id = "ui-<tid>" directly in MongoDB
        bridged_q = {"$and": [{"info.id": tid}, {"info.job_id": f"ui-{tid}"}, scope]}
        bridged_doc = mongo_find_one("analysis", bridged_q, {"info.job_id": 1})
        bridged_jid = ((bridged_doc or {}).get("info") or {}).get("job_id")
        if bridged_jid:
            return str(bridged_jid)
        raise Http404("no bridged job_id for task")

    query: dict[str, Any] = {"info.id": tid}
    if scope:
        query = {"$and": [query, scope]}
    doc = mongo_find_one("analysis", query, {"info.job_id": 1})
    job_id = ((doc or {}).get("info") or {}).get("job_id")
    if not job_id:
        raise Http404("no job_id mapping for task")
    return str(job_id)


def _store_and_container(task_id: Any, scope: Optional[dict[str, Any]] = None) -> tuple[ArtifactStore, str]:
    from django.http import Http404

    cfg = object_storage_config()
    store, is_remote = get_artifact_store(cfg)
    if not is_remote:
        return store, str(task_id)
    jid = _job_id_for_task(task_id, scope)
    if not _is_safe_job_id(jid):
        raise Http404("invalid job id")
    return store, f"{cfg.prefix}/{jid}"


def artifact_response(
    task_id: Any,
    relpath: str,
    content_type: str,
    filename: str,
    chunk: int = 8192,
    scope: Optional[dict[str, Any]] = None,
) -> Any:
    """Return a Django `StreamingHttpResponse` for an analysis artifact from any backend."""
    from django.http import Http404, StreamingHttpResponse

    _safe_relpath(relpath)
    store, container = _store_and_container(task_id, scope)
    try:
        body_iter, length = store.stream(container, relpath, chunk)
    except ArtifactNotFound as e:
        raise Http404(f"artifact not found: {relpath}") from e
    resp = StreamingHttpResponse(body_iter, content_type=content_type)
    if length is not None:
        resp["Content-Length"] = length
    resp["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


_DONE_MARKERS = (".objectstore.done", ".centralstore.done")


def _stage_tree(task_id: Any, scope: Optional[dict[str, Any]], want: Callable[[str], bool]) -> bool:
    store, container = _store_and_container(task_id, scope)
    local = _local_analysis_path(task_id, "")
    os.makedirs(local, exist_ok=True)
    local_real = os.path.realpath(local)
    complete = False
    for rel in store.iter_relpaths(container):
        if rel in _DONE_MARKERS:
            complete = True
            continue
        if not rel or rel.endswith("/") or not want(rel):
            continue
        try:
            _safe_relpath(rel)
        except Exception:
            continue
        dest = os.path.join(local, rel)
        dest_real = os.path.realpath(dest)
        if dest_real != local_real and not dest_real.startswith(local_real + os.sep):
            continue
        if os.path.exists(dest):
            continue
        store.download(container, rel, dest)
    return complete


def ensure_local_analysis(
    task_id: Any,
    scope: Optional[dict[str, Any]] = None,
    exclude_prefixes: Sequence[str] = ("memory/", "memory.dmp"),
) -> None:
    """Lazily materialize the remote `<prefix>/<job_id>/` tree into `storage/analyses/<task_id>/`."""
    cfg = object_storage_config()
    if not cfg.enabled:
        return
    base_dir = _local_analysis_path(task_id, "")
    marker = os.path.join(base_dir, ".object_staged")
    legacy_marker = os.path.join(base_dir, ".central_staged")
    if os.path.exists(marker) or os.path.exists(legacy_marker):
        return
    try:
        complete = _stage_tree(
            task_id, scope, want=lambda rel: not any(rel.startswith(p) for p in exclude_prefixes)
        )
        if complete:
            with open(marker, "w") as f:
                f.write("staged")
    except Exception as e:
        from django.http import Http404

        if isinstance(e, Http404):
            raise
        log.warning("object_storage: failed to stage analysis %s: %s", task_id, e)


def ensure_local_memory(
    task_id: Any,
    scope: Optional[dict[str, Any]] = None,
    include_full_ram: bool = True,
) -> None:
    """Stage memory dumps from object storage to the local analysis directory on demand."""
    cfg = object_storage_config()
    if not cfg.enabled:
        return
    try:
        _stage_tree(
            task_id,
            scope,
            want=lambda rel: rel.startswith("memory/") or (include_full_ram and rel.startswith("memory.dmp")),
        )
    except Exception as e:
        from django.http import Http404

        if isinstance(e, Http404):
            raise
        log.warning("object_storage: failed to stage memory for analysis %s: %s", task_id, e)


def artifact_exists(task_id: Any, relpath: str, scope: Optional[dict[str, Any]] = None) -> bool:
    try:
        _safe_relpath(relpath)
        store, container = _store_and_container(task_id, scope)
        return store.exists(container, relpath)
    except Exception:
        return False


def materialize_artifact(
    task_id: Any,
    relpath: str,
    scope: Optional[dict[str, Any]] = None,
) -> tuple[Optional[str], bool]:
    try:
        _safe_relpath(relpath)
        store, container = _store_and_container(task_id, scope)
        return store.materialize(container, relpath)
    except Exception:
        return (None, False)


def read_artifact_text(
    task_id: Any,
    relpath: str,
    max_bytes: int = 100000,
    scope: Optional[dict[str, Any]] = None,
) -> str:
    try:
        _safe_relpath(relpath)
        store, container = _store_and_container(task_id, scope)
        data = store.read_text(container, relpath, max_bytes)
    except Exception:
        return ""
    if len(data) > max_bytes:
        return data[:max_bytes] + "\n... [TRUNCATED] ..."
    return data
