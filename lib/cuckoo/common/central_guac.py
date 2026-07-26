"""Central-mode interactive-Guacamole worker routing.

Single-node: a task's live analysis VM is in local libvirt and guacd is on
localhost. In the broker/autoscaling topology the VM runs on an ephemeral ASG
worker, so the central guac consumer must target THAT worker's guacd + VM.

worker_ip_for_task() resolves task_id (info.id) -> info.job_id -> the broker job
record's sandbox_worker_ip (recorded by the dispatcher at dispatch time) -> the
worker's private IP. The job record is fetched via a pluggable JobDirectory
(job_directory.py): the broker's HTTP status API by default (vendor-neutral), or
DynamoDB (opt-in, AWS) — so the fork carries no hard DynamoDB/boto3 dependency. Returns None for box-local /
single-node tasks (no broker record), so the consumer/view keep their localhost
path unchanged when central mode is off or the task ran locally.
"""
import logging

log = logging.getLogger(__name__)


def _worker_api_token(token_file):
    """Read the worker apiv2 Token from token_file; '' if unset/unreadable (=> no auth header).
    Never raises — a missing token file just means unauthenticated requests."""
    try:
        with open(token_file) as f:
            return f.read().strip()
    except Exception:
        return ""


def _worker_task_view_url(worker_ip, port, cape_task_id):
    """The worker's apiv2 task-view URL. port comes from [central_mode] worker_api_port."""
    return "http://%s:%d/apiv2/tasks/view/%d/" % (worker_ip, int(port), int(cape_task_id))


def _libvirt_ssh_dsn(ip, ssh_user, keyfile):
    """qemu+ssh libvirt DSN to a worker. ssh_user/keyfile come from [central_mode]
    (worker_ssh_user/worker_ssh_keyfile) so the deb defaults aren't hardcoded. keyfile is
    URL-quoted (safe='/') so a configured path with a '&'/'?'/space can't corrupt the query."""
    from urllib.parse import quote

    return "qemu+ssh://%s@%s/system?keyfile=%s&no_verify=1" % (ssh_user, ip, quote(keyfile, safe="/"))


def _job_id_for_task(task_id):
    """Resolve the broker job_id for a task. Prefer the RDS task.custom stamp
    ('job_id=ui-<id>', set by the submit-bridge at enqueue) — it exists DURING the
    live run, which is exactly when interactive guac is needed. The DocumentDB
    analysis doc is only written at reporting (after the VM is gone), so it can't be
    relied on here; fall back to it only for non-bridged/seeded tasks."""
    try:
        from lib.cuckoo.core.database import Database

        t = Database().view_task(int(task_id))
        custom = getattr(t, "custom", None) if t else None
        if custom:
            # comma-separated k=v pairs — take ONLY the job_id= value (not the rest of the
            # string), matching centralstore.resolve_job_id; a trailing ',foo=bar' would
            # otherwise corrupt the DynamoDB key / S3 prefix lookup.
            text = str(custom)
            for part in text.split(","):
                part = part.strip()
                if part.startswith("job_id="):
                    v = part.split("=", 1)[1].strip()
                    if v:
                        return v
            # Bare-token form (custom is just the job id) — kept in sync with
            # centralstore.resolve_job_id, which also accepts a bare token for non-bridged tasks.
            token = text.strip()
            if token and "=" not in token and "," not in token:
                return token
    except Exception:
        pass
    try:
        from dev_utils.mongodb import mongo_find_one

        doc = mongo_find_one("analysis", {"info.id": int(task_id)}, {"info.job_id": 1})
        # info may be missing OR explicitly None ({"info": None}); coalesce both before .get.
        return ((doc or {}).get("info") or {}).get("job_id")
    except Exception:
        return None


def _worker_ip(cfg, task_id):
    """Resolve task_id -> the hosting worker's private IP using an ALREADY-loaded cfg, so
    worker_ip_for_task and libvirt_dsn_for_task parse [central_mode] once per call instead of
    twice. Returns None (local/unresolvable). The IP is validated in job_directory.loc_from_item."""
    from lib.cuckoo.common.job_directory import get_job_directory

    directory = get_job_directory(cfg)
    if directory is None:
        return None
    try:
        job_id = _job_id_for_task(task_id)
        if not job_id:
            return None
        loc = directory.lookup(job_id)
        return loc.worker_ip if loc else None
    except Exception as e:
        log.warning("central guac: worker resolution failed for task %s: %s", task_id, e)
        return None


def worker_ip_for_task(task_id):
    """Private IP of the worker hosting this task's live VM, or None (local)."""
    from lib.cuckoo.common.central_mode import central_mode_config

    return _worker_ip(central_mode_config(), task_id)


def worker_vm_for_task(task_id):
    """For a live broker-dispatched interactive task, return (vm_label, guest_ip) of the
    VM on the worker — needed to build the guac session_data on the central node, where
    the local machines table is empty (the VM lives on the worker). Resolves the broker
    record (job_id -> worker IP + the worker-local cape_task_id) then asks that worker's
    apiv2 for the task's machine. Returns (None, None) for non-bridged/local tasks."""
    from lib.cuckoo.common.central_mode import central_mode_config
    from lib.cuckoo.common.job_directory import get_job_directory

    cfg = central_mode_config()
    directory = get_job_directory(cfg)
    if directory is None:
        return (None, None)
    try:
        job_id = _job_id_for_task(task_id)
        if not job_id:
            return (None, None)
        loc = directory.lookup(job_id)
        if not loc:
            return (None, None)
        worker_ip = loc.worker_ip
        cape_task_id = loc.cape_task_id
        if not worker_ip or cape_task_id is None:
            return (None, None)

        import requests

        token = _worker_api_token(cfg.worker_api_token_file)
        headers = {"Authorization": f"Token {token}"} if token else {}
        r = requests.get(_worker_task_view_url(worker_ip, cfg.worker_api_port, cape_task_id),
                         headers=headers, timeout=10)
        data = (r.json() or {}).get("data", {})
        return (data.get("machine"), None)  # central guac uses the worker's localhost for VNC
    except Exception as e:
        log.warning("central guac: worker VM lookup failed for task %s: %s", task_id, e)
        return (None, None)


def libvirt_dsn_for_task(task_id, local_dsn):
    """libvirt DSN to query the VM's VNC port: the worker's libvirt over SSH for a
    worker-hosted task, else the local DSN. (Requires the central node's worker_ssh_user
    to hold worker_ssh_keyfile, authorized on workers — deploy-time plumbing.)"""
    from lib.cuckoo.common.central_mode import central_mode_config

    cfg = central_mode_config()  # loaded once; shared with the worker-IP resolution below
    ip = _worker_ip(cfg, task_id)
    if not ip:
        return (local_dsn, None)
    # The central node's libvirt-over-SSH identity onto workers comes from [central_mode]
    # (worker_ssh_user/worker_ssh_keyfile); no_verify skips host-key prompts for ephemeral
    # in-VPC workers.
    dsn = _libvirt_ssh_dsn(ip, cfg.worker_ssh_user, cfg.worker_ssh_keyfile)
    return (dsn, ip)
