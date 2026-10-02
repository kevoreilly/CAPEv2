"""Central-mode toggle. OFF (default) = single-node behavior (local pg/mongo/FS).
ON = the web/api app reads the central data plane (RDS via [database], DocumentDB
via [mongodb]) and serves artifacts from S3.

The relational + mongo CONNECTIONS are pointed by their existing conf; this flag
gates the code-level behavior that has no conf today — the FS->S3 artifact seam —
and carries the S3 location. Parsing logic is split into the pure `_parse()` helper
so it's unit-testable without importing the CAPE config machinery.
"""
import os
from dataclasses import dataclass


def _within(realpath, root):
    """True iff `realpath` is `root` itself or lives under it. Uses a separator-
    terminated prefix so a sibling like storage/binaries-evil does NOT count as
    inside storage/binaries (prefix-collision guard)."""
    return realpath == root or realpath.startswith(root.rstrip(os.sep) + os.sep)


def upload_target_realpath(full, base_real, trusted_roots):
    """Decide whether an analysis file may be shipped to the central store, and if
    so, the on-disk path whose CONTENT to upload.

    centralstore walks the analysis tree. Most entries are regular files inside the
    tree. A few are symlinks INTO trusted content roots — `binary` -> storage/binaries/
    <sha256> and any guacrecording symlinked from the analysis dir -> storage/
    guacrecordings/. Those must ship (the read seam serves them), so we resolve and
    upload their target content under the file's analysis-relative key.

    But artifacts are partly sample-influenced: a planted symlink (e.g. binary ->
    ~/.aws/credentials) would otherwise be read and exfiltrated to S3 (audit
    CRITICAL). So we ALLOW a resolved path only when it stays within the analysis
    tree itself or one of the trusted_roots; anything resolving elsewhere returns
    None (skip). Pure (os.path only) so it is unit-testable without boto3/Django.
    """
    realpath = os.path.realpath(full)
    for root in [base_real, *trusted_roots]:
        if _within(realpath, root):
            return realpath
    return None


def _as_bool(v, default=False):
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _as_int(v, default):
    """Coerce a config value to int, falling back to `default` on None/blank/garbage so a
    typo in [central_mode] degrades to the documented default instead of a startup crash."""
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _as_port(v, default):
    """A TCP port from config. int() accepts syntactically-valid but out-of-range values
    (0, -1, 99999) that would then format into a broken URL and silently kill worker resolution;
    fall back to `default` unless the value is a real port (1..65535)."""
    p = _as_int(v, default)
    return p if 1 <= p <= 65535 else default


@dataclass
class CentralModeConfig:
    enabled: bool = False
    s3_bucket: str = ""
    s3_region: str = "us-east-1"
    s3_prefix: str = "results"  # results/<job_id>/...
    # Artifact storage backend (when central mode is ON). "s3" = any S3-compatible object
    # store (AWS S3, MinIO, Ceph RGW, …) via boto3; "local" = a shared local/NFS mount.
    # Single-node (enabled=False) always uses the local storage/analyses tree regardless.
    storage_backend: str = "s3"
    # S3-compatible endpoint + creds. ALL OPTIONAL: empty s3_endpoint_url -> AWS's default
    # endpoint; empty creds -> boto3's default chain (IAM role on AWS). Set them to point at
    # MinIO/Ceph/etc. — this is the ONLY thing that made the artifact store AWS-locked.
    s3_endpoint_url: str = ""
    s3_access_key: str = ""
    s3_secret_key: str = ""
    # For storage_backend="local" (central with a shared mount): the root the per-job
    # artifact trees live under (results/<job_id>/...). Empty -> falls back to the local
    # storage/analyses tree.
    central_local_root: str = ""
    # Broker job-tracking DynamoDB table — lets the central node resolve a live
    # job to the worker hosting its VM (interactive Guacamole worker routing).
    broker_table: str = ""
    # Job->worker directory backend for interactive guac routing (central_guac.py):
    # "broker_http" (default; vendor-neutral — resolves via the broker's GET /api/status/<job_id>,
    # so no DynamoDB/boto3) or "dynamodb" (AWS; reads broker_table).
    job_directory: str = "broker_http"
    # For job_directory="broker_http": the broker base URL + Bearer API token.
    broker_url: str = ""
    broker_api_token: str = ""
    # Interactive-Guac worker access (central_guac.py resolves a live task's VM on the worker that
    # hosts it). These carry the deployment's worker conventions so they aren't hardcoded for
    # non-deb topologies. worker_api_token_file: file holding the worker apiv2 Token (blank/absent
    # => no auth header). worker_api_port: the worker's apiv2/web port. worker_ssh_user +
    # worker_ssh_keyfile: the central node's libvirt-over-SSH identity onto workers.
    worker_api_token_file: str = "/etc/cape/api-token"
    worker_api_port: int = 8000
    worker_ssh_user: str = "cape"
    worker_ssh_keyfile: str = "/home/cape/.ssh/id_ed25519"
    # The report doc -> central DocumentDB write is the NATIVE mongodb.py reporting module
    # pointed at DocumentDB via [mongodb] (tls=yes, retrywrites=no); central_mode therefore
    # only carries the FS->S3 artifact location.
    #
    # Read-only SQLAlchemy URL of the CENTRAL control-plane RDS, used by workers ONLY to
    # resolve a central task's authoritative tenancy (tenant_id/user_id/visibility) when
    # stamping the shared DocumentDB analysis doc. A worker's own [database] is its LOCAL
    # per-worker task DB (a different id space), and centralstore rewrites info.id to the
    # CENTRAL task id — so the stamp must be resolved against the central RDS, not locally.
    # Empty (default) => the worker cannot resolve central tenancy and stamps FAIL-CLOSED
    # (private/unowned). Set this (read-only creds) on workers in a central+MT deployment.
    central_database_url: str = ""
    # Management/UI node opt-in: this node advertises the fleet's route options on the
    # submission form but runs NO rooter (only workers route traffic). When yes, init_rooter
    # and init_routing tolerate an unreachable rooter (warn + skip route verification/NAT while
    # still populating vpns/socks5s for the form) instead of raising CuckooStartupError. Default
    # no, so single-node AND workers keep failing fast on a missing rooter. Set yes ONLY on the
    # central UI node.
    tolerate_missing_rooter: bool = False


def _parse(sec) -> "CentralModeConfig":
    """Pure: turn a [central_mode] config section (dict-like) into CentralModeConfig."""
    get = sec.get if hasattr(sec, "get") else (lambda k, d=None: d)
    return CentralModeConfig(
        enabled=_as_bool(get("enabled", False), False),
        s3_bucket=str(get("s3_bucket", "") or ""),
        s3_region=str(get("s3_region", "us-east-1") or "us-east-1"),
        s3_prefix=str(get("s3_prefix", "results") or "results"),
        storage_backend=str(get("storage_backend", "s3") or "s3").strip().lower(),
        s3_endpoint_url=str(get("s3_endpoint_url", "") or ""),
        s3_access_key=str(get("s3_access_key", "") or ""),
        s3_secret_key=str(get("s3_secret_key", "") or ""),
        central_local_root=str(get("central_local_root", "") or ""),
        broker_table=str(get("broker_table", "") or ""),
        job_directory=str(get("job_directory", "broker_http") or "broker_http").strip().lower(),
        broker_url=str(get("broker_url", "") or ""),
        broker_api_token=str(get("broker_api_token", "") or ""),
        worker_api_token_file=str(get("worker_api_token_file", "/etc/cape/api-token") or "/etc/cape/api-token"),
        worker_api_port=_as_port(get("worker_api_port", 8000), 8000),
        worker_ssh_user=str(get("worker_ssh_user", "cape") or "cape"),
        worker_ssh_keyfile=str(get("worker_ssh_keyfile", "/home/cape/.ssh/id_ed25519") or "/home/cape/.ssh/id_ed25519"),
        central_database_url=str(get("central_database_url", "") or ""),
        tolerate_missing_rooter=_as_bool(get("tolerate_missing_rooter", False), False),
    )


def central_mode_config() -> "CentralModeConfig":
    # Lazy import so module import stays dependency-free (the CAPE config machinery
    # is only touched when this is actually called at runtime).
    from lib.cuckoo.common.config import Config

    try:
        sec = Config("cuckoo").get("central_mode")
    except Exception:
        sec = {}
    return _parse(sec)


def central_bridge_required():
    """True when tenant isolation REQUIRES the submit-bridge: central mode AND multitenancy are both enabled.

    In that mode only a bridged 'ui-<central_id>' doc has a globally-unique, tenant-resolvable identity (the
    bridge assigns it, centralstore stamps it, the reconcile maps it to a tenant via the central RDS). A
    non-bridged / direct-submit 'local-<id>' doc has NO tenancy by construction -- the worker never knew a
    tenant, there is no central RDS row for the reconcile to map, so its info.tenant_id stays null forever and
    its worker-local info.id collides across workers. So when the bridge is required the own-doc read/write/
    delete filters MUST refuse the ambiguous info.id arms and key ONLY on the ui- id; a non-bridged doc is
    single-tenant only. Fail-closed on BOTH probes: if the central config read RAISES we can't rule out
    central+MT, so assume bridge-required (the MOST restrictive own-doc filter -- a ui-only key that can never
    match a foreign collision); _mt_enabled() is itself fail-closed (assumes enabled if its config layer is
    present but unreadable). This MUST NOT propagate an exception -- its callers build a Mongo filter inline
    (e.g. set_task_visibility's except arm) and can't handle a raise."""
    try:
        if not central_mode_config().enabled:
            return False
    except Exception:
        return True  # mode indeterminate -> fail closed (ui-only own-doc filter)
    try:
        from lib.cuckoo.common.tenancy_optional import _mt_enabled

        return _mt_enabled()
    except Exception:
        return True  # MT layer indeterminate -> fail closed


def central_own_analysis_filter(task_id, tenant_id):
    """The Mongo filter identifying the caller's OWN analysis doc for a central task, DERIVED from the
    authorized task_id. The SINGLE key used by every central WRITE that mutates a task's own doc -- the
    visibility-toggle write (lib.cuckoo.core.data.tasking.set_task_visibility), the central DELETE and the
    comment write (web.analysis.central_views / views.comments) -- so they can't drift.

    CRITICAL Mongo semantics: an equality on null ({info.tenant_id: None}) ALSO matches documents where the
    field is ABSENT, and every doc is inserted unstamped (stamp_tenant_info / reconcile write the tenant only
    at report time; a reconcile-skipped doc stays stranded). So a bare {info.id: tid} arm ANDed with only a
    null-or-ours tenant guard would re-admit a FOREIGN worker-local doc that collides on info.id (audit HIGH:
    it backs a destructive delete + a re-owning $set). The own-doc arms are therefore qualified by job_id:

      * info.job_id == 'ui-<task_id>' -- the bridge assigns this GLOBALLY-UNIQUE id and centralstore stamps it
        (rewriting info.id to the same central id), so it uniquely + unforgeably (DERIVED, never read from the
        user `custom`) addresses a bridged task's doc.
      * info.id == task_id AND info.job_id in {absent/null, 'ui-<task_id>'} -- an OWN doc not yet keyed (before
        centralstore stamps job_id). A foreign doc that has already been stamped 'local-<n>' fails this arm.
      * info.id == task_id AND info.job_id == 'local-<task_id>' AND info.tenant_id == ours -- an OWN
        direct-submit / non-bridged doc: central mode explicitly supports this topology (resolve_job_id's
        non-broker fallback, mongodb.py's direct-submit handling, central_analysis_query's read fallback), so
        the write MUST address it -- but 'local-<n>' is NOT globally unique (two workers both mint it), so it
        is OURS only once it carries OUR tenant stamp. (This means a restrictive toggle of an own NON-bridged
        doc is a safe no-op until reconcile stamps it -- bounded, and preferable to admitting a foreign doc.)

    All ANDed with a {tenant_id null-or-ours} guard: a FOREIGN doc STAMPED for another tenant that collides on
    info.id is excluded, so the $set can't relabel/re-own it. Pass the TASK's tenant_id (the doc's expected
    owner), which also lets a break-glass toggle of another tenant's task match (the task carries that tenant).

    This is NOT identical to the READ filter (central_analysis_query ANDs its non-bridged arm with the full
    viewer_scope); it is the WRITE-side own-doc key, deliberately tenant-guarded. A 0-match is a safe no-op
    (no own doc yet; reconcile stamps it from the authoritative SQL value on report).

    BRIDGE-REQUIRED (central + MT, central_bridge_required()): the info.id arms are DROPPED entirely -- only a
    bridged 'ui-<tid>' doc is a tenant-isolated own doc, so the filter is {info.job_id: ui-<tid>} AND the
    tenant guard. This fully closes the residual below (no bare info.id surface at all); a non-bridged doc is
    single-tenant only in that mode, and centralstore/mongodb refuse to PERSIST one under central+MT so the
    ui-only key always resolves an existing own doc.

    NON-bridge-required (single-node / MT-off): the three-arm form supports direct-submit docs. RESIDUAL there:
    a FOREIGN doc inserted but NOT YET keyed (info.job_id absent) that collides on info.id still passes the
    second arm during that transient window -- acceptable when MT is off (no tenant boundary to cross)."""
    _tid = int(task_id)
    _tenant_guard = {"$or": [{"info.tenant_id": None}, {"info.tenant_id": tenant_id}]}
    if central_bridge_required():
        # Only a globally-unique bridged id is a tenant-isolated own doc; no ambiguous info.id arm.
        return {"$and": [{"info.job_id": f"ui-{_tid}"}, _tenant_guard]}
    return {"$and": [
        {"$or": [
            {"info.job_id": f"ui-{_tid}"},
            # own not-yet-keyed doc: our info.id AND no foreign job_id stamped on it
            {"$and": [{"info.id": _tid}, {"info.job_id": {"$in": [None, f"ui-{_tid}"]}}]},
            # own direct-submit doc: 'local-<tid>' is OURS only once it carries OUR tenant stamp
            {"$and": [{"info.id": _tid}, {"info.job_id": f"local-{_tid}"}, {"info.tenant_id": tenant_id}]},
        ]},
        _tenant_guard,
    ]}
