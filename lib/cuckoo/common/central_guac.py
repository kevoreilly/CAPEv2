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


def _bracket(host):
    """Bracket an IPv6 literal for use as a URL/DSN netloc; leave IPv4/hostnames as-is.
    _valid_worker_ip accepts any ipaddress.ip_address, so an IPv6 worker IP (e.g. 'fd00::5')
    reaches these builders and MUST be bracketed ('[fd00::5]') or the ':' collides with the
    port separator and the URL/DSN is malformed."""
    text = str(host)
    return "[%s]" % text if ":" in text else text


def _worker_machine_url(worker_ip, port, cape_task_id):
    """The worker's apiv2 machine-label URL (tasks/machine): a control-plane infra read that
    returns ONLY the task's analysis-VM label, so this lookup is not blocked by the worker's
    per-tenant task scoping. port comes from [central_mode] worker_api_port. The presented
    worker_api_token authorizes via the worker's [api] control_plane_token shared secret (or,
    on a token_auth_enabled=yes worker, an is_local_admin principal)."""
    return "http://%s:%d/apiv2/tasks/machine/%d/" % (_bracket(worker_ip), int(port), int(cape_task_id))


def _libvirt_ssh_dsn(ip, ssh_user, keyfile):
    """qemu+ssh libvirt DSN to a worker. ssh_user/keyfile come from [central_mode]
    (worker_ssh_user/worker_ssh_keyfile) so the deb defaults aren't hardcoded. keyfile is
    URL-quoted (safe='/') so a configured path with a '&'/'?'/space can't corrupt the query.
    An IPv6 worker IP is bracketed so its ':'s don't corrupt the netloc."""
    from urllib.parse import quote

    return "qemu+ssh://%s@%s/system?keyfile=%s&no_verify=1" % (ssh_user, _bracket(ip), quote(keyfile, safe="/"))


def _job_id_for_task(task_id):
    """Resolve the broker job_id for a live interactive task's VM, for the guac tunnel.

    DERIVE it deterministically from the caller's AUTHORIZED task_id -- 'ui-<task_id>' -- NEVER from
    the forgeable task.custom. The central submit-bridge assigns job_id='ui-<rds_task_id>' and stamps
    it into custom (central-submit-bridge.py; its docstring: "job_id is deterministic 'ui-<rds_task_id>'
    so the central read seam can resolve rds_task_id -> job_id"). custom is a user-supplied submission
    field, and the bridge SKIPS a task whose custom is already 'job_id=%%' -- so a user who submits
    custom='job_id=ui-<victim>' keeps that forged value, and reading it here resolved ANOTHER tenant's
    worker/VM (adversarial-review HIGH: cross-tenant live-VM tunnel). Deriving binds the tunnel to the
    caller's OWN task (can_manage_task already authorized it in the guac view/consumer); a forged custom
    cannot redirect it, and a non-bridged / not-running task simply misses the broker directory
    (-> no worker_ip -> local DSN). The DocumentDB doc can't help here anyway (written only at reporting,
    after the VM is gone)."""
    try:
        return f"ui-{int(task_id)}"
    except (TypeError, ValueError):
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


def _worker_machine_body(task_id):
    """Resolve task_id -> the hosting worker's apiv2 tasks/machine response dict, or None.
    Shared by worker_vm_for_task (VM label) and worker_vnc_port_for_task (VNC port): resolves
    the broker record (job_id -> worker IP + worker-local cape_task_id) then asks that worker's
    apiv2. Central mode only; None => non-bridged/local task, or a worker/auth error (logged)."""
    from lib.cuckoo.common.central_mode import central_mode_config
    from lib.cuckoo.common.job_directory import get_job_directory

    cfg = central_mode_config()
    directory = get_job_directory(cfg)
    if directory is None:
        return None
    try:
        job_id = _job_id_for_task(task_id)
        if not job_id:
            return None
        loc = directory.lookup(job_id)
        if not loc:
            return None
        worker_ip = loc.worker_ip
        cape_task_id = loc.cape_task_id
        if not worker_ip or cape_task_id is None:
            return None

        import requests

        token = _worker_api_token(cfg.worker_api_token_file)
        headers = {"Authorization": f"Token {token}"} if token else {}
        r = requests.get(_worker_machine_url(worker_ip, cfg.worker_api_port, cape_task_id),
                         headers=headers, timeout=10)
        if r.status_code != 200:
            # A 401/403/404 here is almost always an auth/authorization misconfig — the
            # presented worker_api_token doesn't match the worker's [api] control_plane_token
            # (or, on a token_auth_enabled=yes worker, isn't an is_local_admin principal) —
            # NOT a genuinely local task. Log it so a dead live-VM attach is diagnosable
            # instead of silently degrading to None == "no VM" (the caller can't tell apart).
            log.warning(
                "central guac: worker %s tasks/machine for task %s returned HTTP %s "
                "(verify worker_api_token matches the worker's [api] control_plane_token)",
                worker_ip, task_id, r.status_code,
            )
            return None
        return r.json() or {}
    except Exception as e:
        log.warning("central guac: worker VM lookup failed for task %s: %s", task_id, e)
        return None


def worker_vm_for_task(task_id):
    """For a live broker-dispatched interactive task, return (vm_label, guest_ip) of the
    VM on the worker — needed to build the guac session_data on the central node, where
    the local machines table is empty (the VM lives on the worker). Returns (None, None)
    for non-bridged/local tasks. guest_ip is None: central guac reaches the VM's VNC via the
    worker's own localhost, so the guest IP isn't needed here."""
    body = _worker_machine_body(task_id)
    if not body:
        return (None, None)
    # tasks/machine returns {"error": False, "machine": "<label>", "vnc_port": <int|null>}.
    return (body.get("machine") or None, None)


def worker_vnc_port_for_task(task_id):
    """VNC port of the worker-hosted VM for a live interactive task, resolved by the WORKER's
    own apiv2 (local libvirt on the worker — reliable, SSH-free). REPLACES the fragile UI-side
    libvirt-over-SSH lookup (qemu+ssh://cape@worker), which intermittently hangs or returns -1
    during VM boot and was the cause of guac 519 (UPSTREAM_NOT_FOUND). Returns an int port, or
    None (non-bridged/local task, worker error, or the VM isn't exposing a VNC port yet)."""
    body = _worker_machine_body(task_id)
    if not body:
        return None
    vp = body.get("vnc_port")
    try:
        vp = int(vp)
    except (TypeError, ValueError):
        return None
    return vp if vp > 0 else None


def local_vnc_port(vm_label, dsn=None, retries=3):
    """Resolve a VM's live VNC port from LOCAL libvirt (the host that runs the VM — the worker
    itself in central mode). Reliable and SSH-free: the worker reports this via its apiv2 so the
    central UI never opens the worker's libvirt over SSH. Returns an int port, or None if the VM
    isn't running or hasn't been assigned a VNC port yet. Rejects <=0 — libvirt reports port='-1'
    in the brief autoport-assignment window right after VM start, so retry to ride that out."""
    try:
        import time
        import libvirt
        from xml.etree import ElementTree as ET
        from lib.cuckoo.common.config import Config

        if not dsn:
            machinery = Config().cuckoo.machinery
            dsn = getattr(Config(machinery), machinery).get("dsn", "qemu:///system")
    except Exception:
        return None
    for _attempt in range(max(1, int(retries or 1))):
        conn = None
        try:
            conn = libvirt.open(dsn)
            if conn:
                dom = conn.lookupByName(vm_label)
                st = dom.state(flags=0)
                if st and st[0] == 1:
                    g = ET.fromstring(dom.XMLDesc(0)).find('./devices/graphics[@type="vnc"]')
                    raw = (g.get("port") if g is not None else "") or ""
                    p = int(raw) if raw.lstrip("-").isdigit() else 0
                    if p > 0:
                        return p
        except Exception:
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass
        time.sleep(0.5)
    return None


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
