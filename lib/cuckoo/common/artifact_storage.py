"""FS->object-store artifact seam. central_mode OFF -> local storage/analyses/<task_id>/
<relpath>; ON -> the configured backend (S3-compatible or shared local mount) at
<prefix>/<job_id>/<relpath>. The single-node vs central decision + the CAPE-specific bits
(task_id->job_id resolution, tenant scope, traversal guard) live here; the raw object I/O
is delegated to a pluggable ArtifactStore (lib/cuckoo/common/storage_backend.py) so central
mode runs on any S3-compatible store (AWS/MinIO/Ceph) or a shared mount, with AWS purely
config. Validated live on a CAPE box; the branch/seam logic here is the unit-testable part.
"""
import logging
import os
from collections import OrderedDict

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.central_mode import central_mode_config
from lib.cuckoo.common.storage_backend import get_artifact_store, ArtifactNotFound

log = logging.getLogger(__name__)


def _local_analysis_path(task_id, relpath):
    return os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), relpath)


def _safe_relpath(relpath):
    """Reject traversal/absolute/backslash before a relpath becomes an object key or a
    local path segment. Callers today pass regex-constrained (\\w+) or fixed relpaths, but
    this keeps the seam safe independent of caller discipline (audit MEDIUM-1)."""
    from django.http import Http404

    if not relpath or relpath.startswith("/") or "\\" in relpath or ".." in relpath.split("/"):
        raise Http404(f"invalid artifact path: {relpath!r}")
    return relpath


# Cache ONLY the unscoped resolution. task_id -> job_id is immutable once a task is dispatched, and a
# single report/tab view resolves it several times (each artifact_exists / stream call), so caching
# the see-all path avoids N identical mongo lookups. We deliberately do NOT cache a tenant-SCOPED
# resolution: that lookup is authorization-sensitive (a task's tenant/visibility can be reassigned),
# so a process-lifetime cache could keep serving a job_id the caller may no longer see. Scoped lookups
# always re-query. Only successful resolutions are cached; a bounded LRU so the hot (recently viewed)
# tasks stay cached and we evict one-at-a-time instead of dumping the whole cache at the threshold.
_JOB_ID_CACHE = OrderedDict()  # most-recently-used at the end
_JOB_ID_CACHE_MAX = 1024


def _job_id_for_task(task_id, scope=None):
    """Central mode keys the store by the global job_id (the broker passes it in custom,
    stamped into info.job_id at reporting; centralstore re-keys info.id to the unique
    central task id). Resolve task_id -> job_id via mongo.

    `scope` is the requesting viewer's tenant filter (e.g. entitled_scope_filter):
    info.id is a per-worker sequence and collides across workers in a central
    deployment, so the lookup is ANDed with the viewer's scope to guarantee the
    resolved doc is one the viewer may actually see — not another tenant's analysis
    that happens to share the numeric id (audit HIGH: cross-store id collision)."""
    from dev_utils.mongodb import mongo_find_one
    from django.http import Http404

    # Only the unscoped (see-all / MT-absent / break-glass) path is cache-safe — see the note on
    # _JOB_ID_CACHE. A present scope is authorization-sensitive, so never cache/serve it.
    use_cache = not scope
    if use_cache:
        cached = _JOB_ID_CACHE.get(str(task_id))
        if cached is not None:
            _JOB_ID_CACHE.move_to_end(str(task_id))  # mark most-recently-used
            return cached

    # filereport/full_memory routes capture task_id/analysis_number as \w+ (not \d+),
    # so a non-numeric segment must raise Http404 (the views catch it -> clean error),
    # not an uncaught ValueError -> HTTP 500.
    try:
        tid = int(task_id)
    except (TypeError, ValueError):
        raise Http404("invalid task id")
    query = {"info.id": tid}
    if scope:
        query = {"$and": [query, scope]}
    doc = mongo_find_one("analysis", query, {"info.job_id": 1})
    # info may be missing OR explicitly None ({"info": None}); coalesce both to {} before .get.
    job_id = ((doc or {}).get("info") or {}).get("job_id")
    if not job_id:
        raise Http404("no job_id mapping for task")

    if use_cache:
        _JOB_ID_CACHE[str(task_id)] = job_id
        _JOB_ID_CACHE.move_to_end(str(task_id))
        if len(_JOB_ID_CACHE) > _JOB_ID_CACHE_MAX:
            _JOB_ID_CACHE.popitem(last=False)  # evict least-recently-used
    return job_id


def _store_and_container(task_id, scope=None):
    """Return (ArtifactStore, container) for an analysis. Single-node: the local-FS store
    over storage/analyses, container=<task_id>. Central: the configured backend (S3/local
    mount), container="<s3_prefix>/<job_id>" (raises Http404 if the job_id can't resolve)."""
    cfg = central_mode_config()
    store, is_central = get_artifact_store(cfg)
    if not is_central:
        return store, str(task_id)
    return store, f"{cfg.s3_prefix}/{_job_id_for_task(task_id, scope)}"


def artifact_response(task_id, relpath, content_type, filename, chunk=8192, scope=None):
    """Return a Django streaming response for an analysis artifact from any backend.

    `scope`: the requesting viewer's tenant filter, threaded into the central
    task_id->job_id lookup so a viewer can't pull another tenant's artifact via an
    id collision (see _job_id_for_task)."""
    from django.http import StreamingHttpResponse, Http404

    _safe_relpath(relpath)
    store, container = _store_and_container(task_id, scope)  # may raise Http404 (no job_id)
    try:
        body_iter, length = store.stream(container, relpath, chunk)
    except ArtifactNotFound:
        raise Http404(f"artifact not found: {relpath}")
    resp = StreamingHttpResponse(body_iter, content_type=content_type)
    if length is not None:
        resp["Content-Length"] = length
    resp["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


def _stage_tree(task_id, scope, want):
    """Shared staging core for central mode: copy artifacts from the central store into the
    local storage/analyses/<task_id>/ tree so the MANY report features that read the local
    filesystem work centrally without rewriting each reader. `want(rel) -> bool` selects which
    relpaths to stage. Returns True iff the .centralstore.done completion marker was seen.
    Per-file copy errors are swallowed (best-effort), BUT _store_and_container() may raise Http404
    (bad task id / no job_id mapping / out-of-scope) and that PROPAGATES so a caller can return a
    clean 404; callers that want pure best-effort must catch it (ensure_local_* do). No-op
    single-node (caller guards)."""
    store, container = _store_and_container(task_id, scope)
    local = _local_analysis_path(task_id, "")
    os.makedirs(local, exist_ok=True)
    local_real = os.path.realpath(local)
    complete = False
    for rel in store.iter_relpaths(container):
        if rel == ".centralstore.done":
            complete = True
            continue  # completion marker is a control object, not an artifact — don't stage it
        if not rel or rel.endswith("/") or not want(rel):
            continue
        # Defence-in-depth: an object key suffix must never escape the analysis dir when it
        # becomes a LOCAL destination (centralstore only emits in-tree keys today).
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


def ensure_local_analysis(task_id, scope=None, exclude_prefixes=("memory/", "memory.dmp")):
    """Central mode: lazily materialize the central results/<job_id>/ tree into the local
    storage/analyses/<task_id>/ dir so the report features that read the local filesystem
    (json report, evtx, ETW aux/*.json, sysmon, process.log, behavior feeds, dropped files,
    …) work centrally without rewriting each reader. Cached via a .central_staged marker
    (subsequent calls are a cheap stat) — written only after the .centralstore.done marker is
    seen, so a listing taken mid-upload isn't cached as complete. Excludes the large on-demand
    memory dumps (memory/ subtree + the root memory.dmp[.zip/.strings] full-RAM image) which
    would otherwise bloat every report view by GBs; they stage on demand via ensure_local_
    memory / stream via materialize_artifact. No-op single-node. Best-effort: swallows transient
    errors (the per-file seam still serves downloads), but a clean Http404 propagates so a direct
    view caller returns 404 rather than a broken page."""
    cfg = central_mode_config()
    if not cfg.enabled:
        return
    marker = os.path.join(_local_analysis_path(task_id, ""), ".central_staged")
    if os.path.exists(marker):
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

        # A clean not-found (bad task id / no job_id mapping / out-of-scope) must propagate so a
        # direct view caller (report/load_files) returns a 404 instead of rendering a broken page.
        # Everything else stays best-effort: leave whatever staged; the per-file seam still serves.
        if isinstance(e, Http404):
            raise
        # ...but don't stay SILENT — S3 creds/permission/network failures otherwise vanish.
        log.warning("central mode: failed to stage analysis %s: %s", task_id, e)


def ensure_local_memory(task_id, scope=None):
    """Central mode: stage the memory dumps (the memory/ per-process subtree AND the root
    memory.dmp[.zip/.strings] full-RAM image) — which ensure_local_analysis EXCLUDES from the
    bulk stage because they are large — to the local analysis dir, on EXPLICIT demand (the
    memory-download endpoints). Idempotent per-file; not marker-gated. Best-effort (a clean Http404
    propagates so the view 404s; other errors are swallowed)."""
    cfg = central_mode_config()
    if not cfg.enabled:
        return
    try:
        _stage_tree(task_id, scope, want=lambda rel: rel.startswith("memory/") or rel.startswith("memory.dmp"))
    except Exception as e:
        from django.http import Http404

        # Let a clean not-found propagate (view -> 404); log-then-swallow everything else so a
        # staging failure (S3 creds/permission/network) is diagnosable rather than silent.
        if isinstance(e, Http404):
            raise
        log.warning("central mode: failed to stage memory for analysis %s: %s", task_id, e)


def artifact_exists(task_id, relpath, scope=None):
    """True iff an analysis artifact exists — local (single-node) or via the central store's
    existence check. Used to gate optional UI download links (decrypted/mixed pcap, tlskeys,
    mitmdump) the worker may or may not have produced; a local-FS check returns False for
    central-backed artifacts, hiding links for files that actually exist."""
    try:
        _safe_relpath(relpath)
        store, container = _store_and_container(task_id, scope)
        return store.exists(container, relpath)
    except Exception:
        return False


def materialize_artifact(task_id, relpath, scope=None):
    """Return (local_path, is_temp) for an artifact a caller must open as a real file —
    random-access slicing (procdump), filtering/regeneration (pcap), or handing to an external
    tool (VT upload). Single-node: the real local path, is_temp=False (DO NOT delete it).
    Central: the object streamed to a temp file, is_temp=True (caller deletes it in a finally).
    Returns (None, False) if absent."""
    try:
        _safe_relpath(relpath)
        store, container = _store_and_container(task_id, scope)
        return store.materialize(container, relpath)
    except Exception:
        return (None, False)


def read_artifact_text(task_id, relpath, max_bytes=100000, scope=None):
    """Read a text artifact (e.g. process.log) from any backend, truncated to max_bytes."""
    try:
        _safe_relpath(relpath)
        store, container = _store_and_container(task_id, scope)
        data = store.read_text(container, relpath, max_bytes)
    except Exception:
        return ""
    if len(data) > max_bytes:
        return data[:max_bytes] + "\n... [TRUNCATED] ..."
    return data
