"""Pluggable job->worker directory for central-mode interactive routing.

central_guac.py needs to resolve a LIVE task's broker job_id to the worker hosting its
VM — the worker's private IP + the worker-local cape_task_id — so the central node can
target that worker's guacd / libvirt for interactive Guacamole. The broker dispatcher
records this mapping when it pushes the job; in our AWS broker it lives in a DynamoDB
item keyed by job_id (sandbox_worker_ip, cape_task_id). That DynamoDB get_item was the
LAST hard AWS coupling in the CAPE fork's job path (the FS->S3 artifact seam is already
abstracted in storage_backend.py).

This module pulls it behind a tiny vendor-neutral interface so a non-AWS deployment can
resolve the same mapping over the broker's HTTP status API (or any KV store) instead of
DynamoDB — keeping the fork AWS-free (AWS is one config value), while the AWS broker +
DynamoDB stay in the private IaC repo. The lookup result shape (worker_ip + cape_task_id)
is the only contract; everything else about how the broker stores it is a backend detail.
Django-free + unit-testable, like storage_backend.py.
"""
import logging

log = logging.getLogger(__name__)


class JobLocation:
    """Where a live broker job's VM is. worker_ip = the worker's private IP; cape_task_id
    = the worker-local CAPE task id (used to query that worker's apiv2 for the VM). Either
    may be None when the broker hasn't dispatched the job to a worker yet."""

    __slots__ = ("worker_ip", "cape_task_id")

    def __init__(self, worker_ip=None, cape_task_id=None):
        # "" / missing -> None so callers can do a simple truthiness check; keep
        # cape_task_id as-is (it can legitimately be 0, distinct from absent None).
        self.worker_ip = worker_ip or None
        self.cape_task_id = cape_task_id

    def __eq__(self, other):
        return (
            isinstance(other, JobLocation)
            and self.worker_ip == other.worker_ip
            and self.cape_task_id == other.cape_task_id
        )

    def __repr__(self):
        return f"JobLocation(worker_ip={self.worker_ip!r}, cape_task_id={self.cape_task_id!r})"


def _valid_worker_ip(ip):
    """The broker record's sandbox_worker_ip becomes the netloc of a qemu+ssh libvirt DSN AND of
    an authenticated apiv2 URL (central_guac.py). A poisoned/spoofed broker record with a value
    like '1.2.3.4/system?keyfile=/attacker/key&no_verify=1&x=' or 'attacker:9999/x?a=' would
    otherwise inject libvirt URI params or redirect the Token-bearing apiv2 request to an attacker
    host. It is knowably a bare IP, so require it to parse as one; anything else -> None (the caller
    then keeps the localhost/single-node path). Validating here — the one normalizer both backends
    and both consumers flow through — is the single choke point."""
    if not ip:
        return None
    import ipaddress

    text = str(ip).strip()
    try:
        ipaddress.ip_address(text)
    except ValueError:
        log.warning("job_directory: ignoring non-IP sandbox_worker_ip %r from broker record", ip)
        return None
    return text


def loc_from_item(item):
    """Map a broker job record (dict from DynamoDB or the broker HTTP status API — both
    use the SAME field names) to a JobLocation. Pure, so it's the unit-testable core both
    backends share. The worker IP is validated (see _valid_worker_ip) before it reaches the
    DSN/URL builders."""
    item = item or {}
    return JobLocation(_valid_worker_ip(item.get("sandbox_worker_ip")), item.get("cape_task_id"))


class JobDirectory:
    """Abstract job->worker resolver. Backends implement lookup(job_id)."""

    def lookup(self, job_id):
        """Return a JobLocation for job_id, or None if it can't be resolved (network/
        config error, or no such job). worker_ip/cape_task_id inside may still be None
        if the broker hasn't dispatched the job yet."""
        raise NotImplementedError


class DynamoJobDirectory(JobDirectory):
    """Read the broker's DynamoDB job item directly (default for our AWS broker — keeps
    today's [central_mode] broker_table behavior byte-for-byte)."""

    def __init__(self, table, region="us-east-1"):
        self.table = table
        self.region = region

    def lookup(self, job_id):
        try:
            import boto3

            item = (
                boto3.resource("dynamodb", region_name=self.region)
                .Table(self.table)
                .get_item(Key={"job_id": job_id})
                .get("Item", {})
            )
        except Exception as e:
            log.warning("job_directory(dynamodb): lookup failed for %s: %s", job_id, e)
            return None
        return loc_from_item(item)


class BrokerHttpJobDirectory(JobDirectory):
    """Resolve via the broker's HTTP status API — vendor-neutral (no DynamoDB / boto3 in
    the fork). The broker's GET {broker_url}/api/status/{job_id} returns the same job
    record (sandbox_worker_ip + cape_task_id). Bearer-auth with the broker API token."""

    def __init__(self, broker_url, token=""):
        self.broker_url = (broker_url or "").rstrip("/")
        self.token = token or ""

    def lookup(self, job_id):
        if not self.broker_url:
            return None
        try:
            import requests

            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            r = requests.get(f"{self.broker_url}/api/status/{job_id}", headers=headers, timeout=10)
            if r.status_code != 200:
                return None
            item = r.json() or {}
        except Exception as e:
            log.warning("job_directory(broker_http): lookup failed for %s: %s", job_id, e)
            return None
        return loc_from_item(item)


def get_job_directory(cfg):
    """Return a JobDirectory for the central-mode config, or None when central mode is off
    or no directory is configured — in which case central_guac's callers keep their
    single-node/localhost path unchanged. Default backend is 'broker_http' (vendor-neutral —
    resolves via the broker's HTTP API); 'dynamodb' (AWS) is opt-in."""
    if not getattr(cfg, "enabled", False):
        return None
    backend = (getattr(cfg, "job_directory", "") or "broker_http").strip().lower()
    if backend == "broker_http":
        if not getattr(cfg, "broker_url", ""):
            return None
        return BrokerHttpJobDirectory(cfg.broker_url, getattr(cfg, "broker_api_token", ""))
    # 'dynamodb' (opt-in, AWS) — None if broker_table unset (matches the pre-abstraction gate).
    if not getattr(cfg, "broker_table", ""):
        return None
    return DynamoJobDirectory(cfg.broker_table, getattr(cfg, "s3_region", "us-east-1"))
