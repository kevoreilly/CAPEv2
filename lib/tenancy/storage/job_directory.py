"""Pluggable job -> worker directory for distributed interactive Guacamole routing."""

from __future__ import annotations

import ipaddress
import logging
from typing import Any, Optional

log = logging.getLogger(__name__)


class JobLocation:
    """Where a live distributed job's VM is hosted (`worker_ip`, `cape_task_id`)."""

    __slots__ = ("worker_ip", "cape_task_id")

    def __init__(self, worker_ip: Optional[str] = None, cape_task_id: Any = None) -> None:
        self.worker_ip = worker_ip or None
        self.cape_task_id = cape_task_id

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, JobLocation)
            and self.worker_ip == other.worker_ip
            and self.cape_task_id == other.cape_task_id
        )

    def __repr__(self) -> str:
        return f"JobLocation(worker_ip={self.worker_ip!r}, cape_task_id={self.cape_task_id!r})"


def _valid_worker_ip(ip: Any) -> Optional[str]:
    if not ip:
        return None
    text = str(ip).strip()
    try:
        ipaddress.ip_address(text)
    except ValueError:
        log.warning("job_directory: ignoring non-IP sandbox_worker_ip %r from broker record", ip)
        return None
    return text


def loc_from_item(item: Optional[dict[str, Any]]) -> JobLocation:
    item = item or {}
    return JobLocation(_valid_worker_ip(item.get("sandbox_worker_ip")), item.get("cape_task_id"))


class JobDirectory:
    """Abstract job -> worker resolver."""

    def lookup(self, job_id: str) -> Optional[JobLocation]:
        raise NotImplementedError


class DynamoJobDirectory(JobDirectory):
    """Read the broker's DynamoDB job item directly (opt-in AWS backend)."""

    def __init__(self, table: str, region: str = "us-east-1") -> None:
        self.table = table
        self.region = region

    def lookup(self, job_id: str) -> Optional[JobLocation]:
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
    """Resolve via the broker's vendor-neutral HTTP status API (`GET {broker_url}/api/status/{job_id}`)."""

    def __init__(self, broker_url: str, token: str = "") -> None:
        self.broker_url = (broker_url or "").rstrip("/")
        self.token = token or ""

    def lookup(self, job_id: str) -> Optional[JobLocation]:
        if not self.broker_url:
            return None
        try:
            import requests

            headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
            r = requests.get(f"{self.broker_url}/api/status/{job_id}", headers=headers, timeout=10)
            if r.status_code != 200:
                log.warning(
                    "job_directory(broker_http): status %s for %s (check broker_url/broker_api_token)",
                    r.status_code,
                    job_id,
                )
                return None
            item = r.json() or {}
        except Exception as e:
            log.warning("job_directory(broker_http): lookup failed for %s: %s", job_id, e)
            return None
        return loc_from_item(item)


def get_job_directory(cfg: Any) -> Optional[JobDirectory]:
    if not getattr(cfg, "enabled", False):
        return None
    backend = (getattr(cfg, "job_directory", "") or "broker_http").strip().lower()
    if backend == "broker_http":
        if not getattr(cfg, "broker_url", ""):
            return None
        return BrokerHttpJobDirectory(cfg.broker_url, getattr(cfg, "broker_api_token", ""))
    if not getattr(cfg, "broker_table", ""):
        return None
    region = getattr(cfg, "region", None) or getattr(cfg, "s3_region", "us-east-1")
    return DynamoJobDirectory(cfg.broker_table, region)
