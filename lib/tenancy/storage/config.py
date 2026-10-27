"""Cloud-agnostic object storage configuration (`[object_storage]` with `[central_mode]` fallback).

OFF (default) = single-node behavior (local filesystem `storage/analyses/<task_id>/`).
ON = the web/API app and workers ship and serve analysis artifacts through a pluggable
object-storage backend:
- `s3`: AWS S3, MinIO, Ceph RGW, or any S3-compatible endpoint (`boto3`)
- `gcs`: Google Cloud Storage (`google-cloud-storage`)
- `azure`: Azure Blob Storage (`azure-storage-blob`)
- `local`: Shared local / NFS filesystem mount (`local_root`)
"""

from __future__ import annotations

import os
from typing import Any, Optional


def _within(realpath: str, root: str) -> bool:
    """True iff `realpath` is `root` itself or lives under it."""
    return realpath == root or realpath.startswith(root.rstrip(os.sep) + os.sep)


def upload_target_realpath(full: str, base_real: str, trusted_roots: list[str]) -> Optional[str]:
    """Decide whether an analysis file may be shipped to the object store, and if
    so, the on-disk path whose CONTENT to upload.
    """
    realpath = os.path.realpath(full)
    for root in [base_real, *trusted_roots]:
        if _within(realpath, root):
            return realpath
    return None


def _as_bool(v: Any, default: bool = False) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _as_int(v: Any, default: int) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def _as_port(v: Any, default: int) -> int:
    p = _as_int(v, default)
    return p if 1 <= p <= 65535 else default


class ObjectStorageConfig:
    """Cloud-agnostic object storage configuration with backward-compatible `s3_*` / `central_*` properties."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        backend: Optional[str] = None,
        bucket: Optional[str] = None,
        prefix: Optional[str] = None,
        region: Optional[str] = None,
        endpoint_url: Optional[str] = None,
        access_key: Optional[str] = None,
        secret_key: Optional[str] = None,
        gcp_project: str = "",
        gcp_credentials_path: str = "",
        azure_connection_string: str = "",
        azure_account_url: str = "",
        azure_credential: str = "",
        local_root: Optional[str] = None,
        broker_table: str = "",
        job_directory: str = "broker_http",
        broker_url: str = "",
        broker_api_token: str = "",
        worker_api_token_file: str = "/etc/cape/api-token",
        worker_api_port: int = 8000,
        worker_ssh_user: str = "cape",
        worker_ssh_keyfile: str = "/home/cape/.ssh/id_ed25519",
        central_database_url: str = "",
        tolerate_missing_rooter: bool = False,
        # Legacy aliases (`CentralModeConfig` compatibility)
        storage_backend: Optional[str] = None,
        s3_bucket: Optional[str] = None,
        s3_prefix: Optional[str] = None,
        s3_region: Optional[str] = None,
        s3_endpoint_url: Optional[str] = None,
        s3_access_key: Optional[str] = None,
        s3_secret_key: Optional[str] = None,
        central_local_root: Optional[str] = None,
    ) -> None:
        self.enabled = bool(enabled)
        eff_backend = backend if backend is not None else (storage_backend if storage_backend is not None else "s3")
        self.backend = str(eff_backend or "s3").strip().lower()
        self.bucket = str(bucket if bucket is not None else (s3_bucket or ""))
        self.prefix = str(prefix if prefix is not None else (s3_prefix if s3_prefix is not None else "results")) or "results"
        self.region = str(region if region is not None else (s3_region if s3_region is not None else "us-east-1")) or "us-east-1"
        self.endpoint_url = str(endpoint_url if endpoint_url is not None else (s3_endpoint_url or ""))
        self.access_key = str(access_key if access_key is not None else (s3_access_key or ""))
        self.secret_key = str(secret_key if secret_key is not None else (s3_secret_key or ""))
        self.gcp_project = str(gcp_project or "")
        self.gcp_credentials_path = str(gcp_credentials_path or "")
        self.azure_connection_string = str(azure_connection_string or "")
        self.azure_account_url = str(azure_account_url or "")
        self.azure_credential = str(azure_credential or "")
        self.local_root = str(local_root if local_root is not None else (central_local_root or ""))
        self.broker_table = str(broker_table or "")
        self.job_directory = str(job_directory or "broker_http").strip().lower()
        self.broker_url = str(broker_url or "")
        self.broker_api_token = str(broker_api_token or "")
        self.worker_api_token_file = str(worker_api_token_file or "/etc/cape/api-token")
        self.worker_api_port = int(worker_api_port)
        self.worker_ssh_user = str(worker_ssh_user or "cape")
        self.worker_ssh_keyfile = str(worker_ssh_keyfile or "/home/cape/.ssh/id_ed25519")
        self.central_database_url = str(central_database_url or "")
        self.tolerate_missing_rooter = bool(tolerate_missing_rooter)

    @property
    def storage_backend(self) -> str:
        return self.backend

    @storage_backend.setter
    def storage_backend(self, value: str) -> None:
        self.backend = str(value or "s3").strip().lower()

    @property
    def s3_bucket(self) -> str:
        return self.bucket

    @s3_bucket.setter
    def s3_bucket(self, value: str) -> None:
        self.bucket = str(value or "")

    @property
    def s3_prefix(self) -> str:
        return self.prefix

    @s3_prefix.setter
    def s3_prefix(self, value: str) -> None:
        self.prefix = str(value or "results")

    @property
    def s3_region(self) -> str:
        return self.region

    @s3_region.setter
    def s3_region(self, value: str) -> None:
        self.region = str(value or "us-east-1")

    @property
    def s3_endpoint_url(self) -> str:
        return self.endpoint_url

    @s3_endpoint_url.setter
    def s3_endpoint_url(self, value: str) -> None:
        self.endpoint_url = str(value or "")

    @property
    def s3_access_key(self) -> str:
        return self.access_key

    @s3_access_key.setter
    def s3_access_key(self, value: str) -> None:
        self.access_key = str(value or "")

    @property
    def s3_secret_key(self) -> str:
        return self.secret_key

    @s3_secret_key.setter
    def s3_secret_key(self, value: str) -> None:
        self.secret_key = str(value or "")

    @property
    def central_local_root(self) -> str:
        return self.local_root

    @central_local_root.setter
    def central_local_root(self, value: str) -> None:
        self.local_root = str(value or "")


CentralModeConfig = ObjectStorageConfig


def _parse(sec: Any) -> ObjectStorageConfig:
    """Turn an `[object_storage]` or `[central_mode]` config section into `ObjectStorageConfig`."""
    get = sec.get if hasattr(sec, "get") else (lambda k, d=None: d)
    backend = get("backend", None) or get("storage_backend", "s3") or "s3"
    bucket = get("bucket", None) or get("s3_bucket", "") or ""
    prefix = get("prefix", None) or get("s3_prefix", "results") or "results"
    region = get("region", None) or get("s3_region", "us-east-1") or "us-east-1"
    endpoint_url = get("endpoint_url", None) or get("s3_endpoint_url", "") or ""
    access_key = get("access_key", None) or get("s3_access_key", "") or ""
    secret_key = get("secret_key", None) or get("s3_secret_key", "") or ""
    local_root = get("local_root", None) or get("central_local_root", "") or ""

    return ObjectStorageConfig(
        enabled=_as_bool(get("enabled", False), False),
        backend=str(backend).strip().lower(),
        bucket=str(bucket),
        prefix=str(prefix),
        region=str(region),
        endpoint_url=str(endpoint_url),
        access_key=str(access_key),
        secret_key=str(secret_key),
        gcp_project=str(get("gcp_project", "") or ""),
        gcp_credentials_path=str(get("gcp_credentials_path", "") or ""),
        azure_connection_string=str(get("azure_connection_string", "") or ""),
        azure_account_url=str(get("azure_account_url", "") or ""),
        azure_credential=str(get("azure_credential", "") or ""),
        local_root=str(local_root),
        broker_table=str(get("broker_table", "") or ""),
        job_directory=str(get("job_directory", "broker_http") or "broker_http").strip().lower(),
        broker_url=str(get("broker_url", "") or ""),
        broker_api_token=str(get("broker_api_token", "") or ""),
        worker_api_token_file=str(get("worker_api_token_file", "/etc/cape/api-token") or "/etc/cape/api-token"),
        worker_api_port=_as_port(get("worker_api_port", 8000), 8000),
        worker_ssh_user=str(get("worker_ssh_user", "cape") or "cape"),
        worker_ssh_keyfile=str(
            get("worker_ssh_keyfile", "/home/cape/.ssh/id_ed25519") or "/home/cape/.ssh/id_ed25519"
        ),
        central_database_url=str(get("central_database_url", "") or ""),
        tolerate_missing_rooter=_as_bool(get("tolerate_missing_rooter", False), False),
    )


def object_storage_config() -> ObjectStorageConfig:
    """Load `[object_storage]` from `cuckoo.conf` (falling back to `[central_mode]`)."""
    from lib.cuckoo.common.config import Config

    cfg_obj = None
    try:
        cfg_obj = Config("cuckoo")
    except Exception:
        return _parse({})

    sec: Any = None
    try:
        sec = cfg_obj.get("object_storage")
    except Exception:
        sec = None

    if not sec:
        try:
            sec = cfg_obj.get("central_mode")
        except Exception:
            sec = {}
    else:
        # If [object_storage] exists with enabled=no (default), still check if legacy [central_mode] is enabled
        parsed_obj = _parse(sec)
        if not parsed_obj.enabled:
            try:
                legacy_sec = cfg_obj.get("central_mode")
                if legacy_sec and _as_bool(legacy_sec.get("enabled", False), False):
                    return _parse(legacy_sec)
            except Exception:
                pass
        return parsed_obj

    return _parse(sec or {})


central_mode_config = object_storage_config


def object_storage_bridge_required() -> bool:
    """True when tenant isolation requires unique bridged task identity (`object_storage` AND `multitenancy` enabled)."""
    try:
        if not object_storage_config().enabled:
            return False
    except Exception:
        return True
    try:
        from lib.tenancy.policy import multitenancy_config

        return bool(multitenancy_config().enabled)
    except Exception:
        return True


central_bridge_required = object_storage_bridge_required


def object_storage_own_analysis_filter(task_id: Any, tenant_id: Any) -> dict[str, Any]:
    """Build the MongoDB filter identifying the caller's own analysis doc for a task."""
    _tid = int(task_id)
    _tenant_guard = {"$or": [{"info.tenant_id": None}, {"info.tenant_id": tenant_id}]}
    if object_storage_bridge_required():
        return {
            "$and": [
                {"$or": [{"info.job_id": f"ui-{_tid}"}, {"info.id": _tid, "info.job_id": str(_tid)}]},
                _tenant_guard,
            ]
        }
    return {
        "$and": [
            {
                "$or": [
                    {"info.job_id": f"ui-{_tid}"},
                    {"$and": [{"info.id": _tid}, {"info.job_id": {"$in": [None, f"ui-{_tid}", str(_tid)]}}]},
                    {"$and": [{"info.id": _tid}, {"info.job_id": f"local-{_tid}"}, {"info.tenant_id": tenant_id}]},
                ]
            },
            _tenant_guard,
        ]
    }


central_own_analysis_filter = object_storage_own_analysis_filter
