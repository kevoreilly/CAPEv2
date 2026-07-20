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
import re
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


# A resolved job_id becomes the object-store container prefix ("<s3_prefix>/<job_id>/") on both the S3 and
# the local-mount backends, so it MUST be path-safe: an alnum-anchored charset with no ".." (a value like
# "..", ".foo" or "../../etc" could otherwise collapse the prefix to a parent ref and, on the local mount,
# escape the results tree to read arbitrary host files). This is the canonical guard shared by the read seam
# (job_id_from_custom below, applied at the single parse choke point) AND the write seam
# (centralstore.CentralStore.run imports _is_safe_job_id from here) so the two can never drift.
_SAFE_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _is_safe_job_id(job_id):
    return bool(job_id) and _SAFE_JOB_ID_RE.match(job_id) is not None and ".." not in job_id


def job_id_from_custom(custom):
    """Parse the broker job_id out of a task's RDS `custom` field. THE single parser shared by the WRITE
    consumer (centralstore.resolve_job_id) and the READ/DELETE consumers (central_views.central_job_id_for_task
    -> central_analysis_query / central_delete_analysis) so they can't drift. Pure (no DB).

    Anchored to match the submit-bridge's `custom NOT LIKE 'job_id=%'` enqueue filter so a client `custom`
    that evades the (out-of-tree) filter can't steer the job_id (which keys info.job_id, the info.id rewrite,
    the S3 prefix, and the pre-insert/scoped delete): honour 'job_id=' ONLY as the RAW first comma-field
    prefix -- SQL LIKE tests the RAW column, so do NOT .strip() before the prefix test (else ' job_id=...'
    would evade the filter yet resolve here) -- and NEVER a bare 'ui-<N>' (the bridge's reserved central-id
    form, which no direct submitter produces). A bare NON-ui token is the direct-submission fallback.

    The resolved value is ALSO required to be _is_safe_job_id: it becomes the store container prefix, so a
    path-unsafe custom (e.g. '../../etc') is rejected HERE -> return None -> the caller falls back to the
    scoped info.id lookup (read) / 'local-<id>' (write), never a container-escaping prefix. (Defence in depth:
    _store_and_container ALSO validates the resolved job_id, covering the mongo-fallback path too.) A rejected
    PROBE-SHAPED candidate is logged so a job_id-seam probe stays greppable; a bare free-text `custom` (a
    documented free-form field, so a note like 'my sample run' is not a job_id attempt) is only logged at
    debug -- else every artifact read of a non-bridged task would re-warn on the operator's own note.
    Returns the job_id or None."""
    if not custom:
        return None
    text = str(custom)
    first = text.split(",", 1)[0]  # RAW first field (no strip -> matches LIKE 'job_id=%' anchoring)
    if first.startswith("job_id="):
        v = first.split("=", 1)[1].strip()
        if v and _is_safe_job_id(v):
            return v
        if v:
            # An explicit 'job_id=' with an unsafe value is a deliberate attempt (probe/misconfig) -> warn.
            log.warning("central: ignoring path-unsafe job_id=%r in submitted custom (probe or misconfig)", v)
    token = text.strip()
    if token and "=" not in token and "," not in token and not re.match(r"^ui-\d+$", token):
        if _is_safe_job_id(token):
            return token
        # Only a whitespace-free bare token LOOKS like a job_id/path attempt (e.g. '../../etc') -> warn so a
        # seam probe is greppable. `custom` is free-text: a note with whitespace is not a probe, so log at
        # debug to avoid per-read WARNING spam (this resolver runs on every central artifact read).
        if any(c.isspace() for c in token):
            log.debug("central: bare custom %r is free-text, not a job_id; using scoped fallback", token)
        else:
            log.warning("central: ignoring path-unsafe bare job_id token %r in submitted custom", token)
    return None


def _rds_job_id(task_id):
    """The AUTHORIZED job_id from the RDS task row's custom field — RDS-derived (no mongo
    id-lookup), so it's collision-free AND independent of the tenancy reconcile (custom is
    stamped by the submit-bridge, present even when info.tenant_id/visibility aren't yet).
    None for a non-bridged task (caller falls back to the scoped info.id lookup)."""
    # Resolve int() BEFORE the DB try: a non-numeric id (the filereport/full_memory \w+
    # routes) is bad INPUT, not an RDS error — return None silently so it doesn't get
    # mislabeled as a DB failure in the log below (the fallback's own int() 404s it).
    try:
        tid = int(task_id)
    except (TypeError, ValueError):
        return None
    try:
        from lib.cuckoo.core.database import Database

        t = Database().view_task(tid)
        return job_id_from_custom(getattr(t, "custom", None) if t else None)
    except Exception:
        # A genuine non-bridged task returns None WITHOUT an exception (job_id_from_custom).
        # This except is a real RDS error (pool exhaustion / timeout) — log it so a bridged
        # OWNER silently degraded to the scoped info.id fallback (and possibly 404'd on their
        # own artifact during a DB blip) leaves a signal, not a mystery.
        log.exception("_rds_job_id: RDS lookup failed for task %s; falling back to scoped resolution", tid)
        return None


def _job_id_for_task(task_id, scope=None):
    """Central mode keys the store by the global job_id (the broker passes it in custom,
    stamped into info.job_id at reporting; centralstore re-keys info.id to the unique
    central task id). Resolve task_id -> job_id.

    PREFER the RDS-derived job_id (_rds_job_id) to identify WHICH doc, then AUTHORIZE it
    per-call against the viewer scope: callers gate can_view_task on the RDS task, but the
    job_id itself comes from the task's user-supplied `custom` — so it is NOT an
    unforgeable authorization token. The doc it resolves to must be in the viewer's `scope`
    OR unstamped (info.tenant_id null = authorized owner's not-yet-reconciled doc). A forged
    custom job_id pointing at another tenant's STAMPED doc fails that check -> Http404. Only
    the RDS task_id->job_id MAPPING is cached (scope-independent); the authorization is
    re-checked every call. A NON-bridged task (no RDS job_id) falls back to the scoped
    info.id lookup (never cached across scopes — cross-store id collision, audit HIGH)."""
    from dev_utils.mongodb import mongo_find_one
    from django.http import Http404

    # Resolve the candidate job_id. ONLY the RDS-derived mapping is cached: it's scope-
    # INDEPENDENT (from the task's own custom), so serving it to any viewer is safe as long
    # as the per-call authorization below still runs. The non-bridged info.id fallback is
    # scope-sensitive, so it is never cached / served cross-scope.
    jid = _JOB_ID_CACHE.get(str(task_id))
    if jid is not None:
        try:
            _JOB_ID_CACHE.move_to_end(str(task_id))  # mark MRU; another thread may have evicted it
        except KeyError:
            pass
    else:
        jid = _rds_job_id(task_id)
        if jid:
            _JOB_ID_CACHE[str(task_id)] = jid
            try:
                _JOB_ID_CACHE.move_to_end(str(task_id))
                if len(_JOB_ID_CACHE) > _JOB_ID_CACHE_MAX:
                    _JOB_ID_CACHE.popitem(last=False)  # evict LRU
            except KeyError:
                pass

    if jid:
        # Per-call AUTHORIZATION (not cached — scope-sensitive). scope None = see-all /
        # break-glass / MT-off -> no restriction. Else the doc for this job_id must be in scope
        # OR be the authorized owner's not-yet-reconciled doc. The unstamped arm (info.tenant_id
        # null) MUST be constrained to THIS task (info.id == the decorator-authorized task_id):
        # every doc is inserted unstamped and stamped later (and stranded on reconcile-skip), so an
        # UNCONSTRAINED null arm lets a forged custom job_id (ui-<victimN>) read a DIFFERENT task's
        # unstamped doc + its S3 artifacts cross-tenant (adversarial-review HIGH). A bridged owner's
        # doc is re-keyed to its central id, so info.id == task_id resolves the legit owner; a forged
        # job_id at another task's unstamped doc does not. A forged job_id -> a STAMPED doc fails the
        # scope arm too -> Http404.
        if scope is not None:
            try:
                _own_unstamped = {"$and": [{"info.tenant_id": None}, {"info.id": int(task_id)}]}
                authq = {"$and": [{"info.job_id": jid}, {"$or": [scope, _own_unstamped]}]}
            except (TypeError, ValueError):
                authq = {"$and": [{"info.job_id": jid}, scope]}  # non-numeric task id: no null arm
            if not mongo_find_one("analysis", authq, {"_id": 1}):
                raise Http404("task not visible")
        return jid

    # Non-bridged fallback: info.id can collide across workers, so AND the viewer scope
    # (defence-in-depth, audit HIGH). NOT cached — a scope-specific resolution must never be
    # served to a different-scope caller.
    # filereport/full_memory routes capture task_id as \w+ (not \d+), so a non-numeric
    # segment must raise Http404 (views catch it -> clean error), not an uncaught ValueError.
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
    return job_id


def _store_and_container(task_id, scope=None):
    """Return (ArtifactStore, container) for an analysis. Single-node: the local-FS store
    over storage/analyses, container=<task_id>. Central: the configured backend (S3/local
    mount), container="<s3_prefix>/<job_id>" (raises Http404 if the job_id can't resolve)."""
    from django.http import Http404

    cfg = central_mode_config()
    store, is_central = get_artifact_store(cfg)
    if not is_central:
        return store, str(task_id)
    jid = _job_id_for_task(task_id, scope)
    # The job_id becomes the container prefix. job_id_from_custom already rejects a path-unsafe RDS custom, but
    # the mongo-fallback branch of _job_id_for_task returns info.job_id straight from the doc -- validate HERE
    # too so a hostile value (e.g. from a second/legacy writer of the shared collection) can't escape the
    # results tree on the local-mount backend. Both read-seam return paths thus funnel through one guard.
    if not _is_safe_job_id(jid):
        raise Http404("invalid job id")
    return store, f"{cfg.s3_prefix}/{jid}"


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


def ensure_local_memory(task_id, scope=None, include_full_ram=True):
    """Central mode: stage the memory dumps (the memory/ per-process subtree AND, when include_full_ram, the
    root memory.dmp[.zip/.strings] full-RAM image) — which ensure_local_analysis EXCLUDES from the bulk stage
    because they are large — to the local analysis dir, on EXPLICIT demand (the memory-download endpoints).
    include_full_ram=False stages ONLY the per-process memory/ subtree: the procmemory endpoints serve
    per-process dumps, so they must not pull the multi-GB root full-RAM image onto the web node (that image
    is gated separately by [taskfullmemory] and served only by tasks_fullmemory). Idempotent per-file; not
    marker-gated. Best-effort (a clean Http404 propagates so the view 404s; other errors are swallowed)."""
    cfg = central_mode_config()
    if not cfg.enabled:
        return
    try:
        _stage_tree(task_id, scope, want=lambda rel: rel.startswith("memory/") or (
            include_full_ram and rel.startswith("memory.dmp")))
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
