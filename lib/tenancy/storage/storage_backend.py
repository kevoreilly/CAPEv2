"""Pluggable cloud-agnostic artifact-storage backends (`s3`, `gcs`, `azure`, `local`).

Supported backends when `[object_storage] enabled = yes`:
- `s3`: AWS S3, MinIO, Ceph RGW, or any S3-compatible object store (`boto3`)
- `gcs`: Google Cloud Storage (`google-cloud-storage`)
- `azure`: Azure Blob Storage (`azure-storage-blob`)
- `local`: Shared local / NFS filesystem mount (`local_root`)

When `[object_storage] enabled = no` (default), single-node mode uses `LocalFSStore` over
`storage/analyses/<task_id>`. All SDK imports (`boto3`, `google.cloud.storage`,
`azure.storage.blob`) are lazy so unused backends require zero extra packages installed.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from typing import Any, Iterator, Optional


class ArtifactNotFound(Exception):
    """Raised by `stream()` when an artifact key is absent."""


class ArtifactStore:
    """Abstract per-analysis object store keyed by `(container, relpath)`."""

    def exists(self, container: str, relpath: str) -> bool:
        raise NotImplementedError

    def stream(self, container: str, relpath: str, chunk: int = 8192) -> tuple[Iterator[bytes], Optional[int]]:
        """Return `(byte_iterator, content_length_or_None)`. Raise `ArtifactNotFound` if absent."""
        raise NotImplementedError

    def read_text(self, container: str, relpath: str, max_bytes: int) -> str:
        """Return up to `max_bytes + 1` of text (utf-8, errors=replace), or `""` if absent."""
        raise NotImplementedError

    def materialize(self, container: str, relpath: str) -> tuple[Optional[str], bool]:
        """Return `(local_path, is_temp)` for callers needing a real local file. `(None, False)` if absent."""
        raise NotImplementedError

    def iter_relpaths(self, container: str) -> Iterator[str]:
        """Yield each artifact relpath present under `container` (for lazy staging)."""
        raise NotImplementedError

    def download(self, container: str, relpath: str, dest_abspath: str) -> None:
        """Copy one artifact to `dest_abspath` (creates parent dirs)."""
        raise NotImplementedError

    def put_file(self, local_path: str, container: str, relpath: str) -> None:
        """Write a local file into the store at `(container, relpath)`."""
        raise NotImplementedError


def _iter_file(path: str, chunk: int) -> Iterator[bytes]:
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            yield data


def _iter_bytes(payload: bytes, chunk: int) -> Iterator[bytes]:
    for idx in range(0, len(payload), chunk):
        yield payload[idx : idx + chunk]


class LocalFSStore(ArtifactStore):
    """Filesystem backend for single-node (`storage/analyses`) and shared NFS/local mount (`local_root`)."""

    def __init__(self, base_dir: str) -> None:
        self.base_dir = base_dir

    def _path(self, container: str, relpath: str) -> str:
        return os.path.join(self.base_dir, str(container), relpath)

    def exists(self, container: str, relpath: str) -> bool:
        return os.path.exists(self._path(container, relpath))

    def stream(self, container: str, relpath: str, chunk: int = 8192) -> tuple[Iterator[bytes], Optional[int]]:
        path = self._path(container, relpath)
        if not os.path.exists(path):
            raise ArtifactNotFound(relpath)
        return _iter_file(path, chunk), os.path.getsize(path)

    def read_text(self, container: str, relpath: str, max_bytes: int) -> str:
        path = self._path(container, relpath)
        if not os.path.exists(path):
            return ""
        with open(path, "r", errors="replace") as f:
            return f.read(max_bytes + 1)

    def materialize(self, container: str, relpath: str) -> tuple[Optional[str], bool]:
        path = self._path(container, relpath)
        return (path, False) if os.path.exists(path) else (None, False)

    def iter_relpaths(self, container: str) -> Iterator[str]:
        root = self._path(container, "")
        if not os.path.isdir(root):
            return
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                yield os.path.relpath(os.path.join(dirpath, fn), root)

    def download(self, container: str, relpath: str, dest_abspath: str) -> None:
        src = self._path(container, relpath)
        os.makedirs(os.path.dirname(dest_abspath), exist_ok=True)
        if os.path.realpath(src) != os.path.realpath(dest_abspath):
            shutil.copyfile(src, dest_abspath)

    def put_file(self, local_path: str, container: str, relpath: str) -> None:
        dest = self._path(container, relpath)
        dest_dir = os.path.dirname(dest)
        os.makedirs(dest_dir, exist_ok=True)
        if os.path.realpath(local_path) == os.path.realpath(dest):
            return
        fd, tmp = tempfile.mkstemp(dir=dest_dir, prefix=".part-")
        os.close(fd)
        try:
            shutil.copyfile(local_path, tmp)
            os.replace(tmp, dest)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise


class S3Store(ArtifactStore):
    """Any S3-compatible object store (AWS S3, MinIO, Ceph RGW, etc.) via `boto3`."""

    def __init__(
        self,
        bucket: str,
        region: str = "us-east-1",
        endpoint_url: str = "",
        access_key: str = "",
        secret_key: str = "",
    ) -> None:
        self.bucket = bucket
        self.region = region
        self.endpoint_url = endpoint_url or None
        self.access_key = access_key or None
        self.secret_key = secret_key or None
        self._cli: Any = None

    def _client(self) -> Any:
        if self._cli is None:
            import boto3

            kwargs: dict[str, Any] = {"region_name": self.region}
            if self.endpoint_url:
                kwargs["endpoint_url"] = self.endpoint_url
            if self.access_key and self.secret_key:
                kwargs["aws_access_key_id"] = self.access_key
                kwargs["aws_secret_access_key"] = self.secret_key
            self._cli = boto3.client("s3", **kwargs)
        return self._cli

    def _key(self, container: str, relpath: str) -> str:
        return f"{container}/{relpath}"

    def exists(self, container: str, relpath: str) -> bool:
        try:
            self._client().head_object(Bucket=self.bucket, Key=self._key(container, relpath))
            return True
        except Exception:
            return False

    def stream(self, container: str, relpath: str, chunk: int = 8192) -> tuple[Iterator[bytes], Optional[int]]:
        try:
            obj = self._client().get_object(Bucket=self.bucket, Key=self._key(container, relpath))
        except Exception as e:
            raise ArtifactNotFound(relpath) from e
        return obj["Body"].iter_chunks(chunk), obj.get("ContentLength")

    def read_text(self, container: str, relpath: str, max_bytes: int) -> str:
        try:
            obj = self._client().get_object(
                Bucket=self.bucket, Key=self._key(container, relpath), Range=f"bytes=0-{max_bytes}"
            )
            return obj["Body"].read().decode("utf-8", errors="replace")
        except Exception:
            return ""

    def materialize(self, container: str, relpath: str) -> tuple[Optional[str], bool]:
        tmp: Optional[str] = None
        try:
            obj = self._client().get_object(Bucket=self.bucket, Key=self._key(container, relpath))
            fd, tmp = tempfile.mkstemp(prefix="cape_objstore_")
            with os.fdopen(fd, "wb") as f:
                for c in obj["Body"].iter_chunks(65536):
                    f.write(c)
            return (tmp, True)
        except Exception:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            return (None, False)

    def iter_relpaths(self, container: str) -> Iterator[str]:
        prefix = f"{container}/"
        paginator = self._client().get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                rel = obj["Key"][len(prefix) :]
                if rel and not rel.endswith("/"):
                    yield rel

    def download(self, container: str, relpath: str, dest_abspath: str) -> None:
        os.makedirs(os.path.dirname(dest_abspath), exist_ok=True)
        self._client().download_file(self.bucket, self._key(container, relpath), dest_abspath)

    def put_file(self, local_path: str, container: str, relpath: str) -> None:
        self._client().upload_file(local_path, self.bucket, self._key(container, relpath))


class GCSStore(ArtifactStore):
    """Google Cloud Storage backend via `google-cloud-storage`.

    Supports Application Default Credentials (Workload Identity / GCE service account)
    or an explicit `credentials_path` JSON key file.
    """

    def __init__(
        self,
        bucket: str,
        project: str = "",
        credentials_path: str = "",
        endpoint_url: str = "",
    ) -> None:
        self.bucket_name = bucket
        self.project = project or None
        self.credentials_path = credentials_path or None
        self.endpoint_url = endpoint_url or None
        self._cli: Any = None
        self._bucket: Any = None

    def _get_bucket(self) -> Any:
        if self._bucket is None:
            from google.cloud import storage

            client_kwargs: dict[str, Any] = {}
            if self.project:
                client_kwargs["project"] = self.project
            if self.endpoint_url:
                from google.api_core.client_options import ClientOptions

                client_kwargs["client_options"] = ClientOptions(api_endpoint=self.endpoint_url)
            if self.credentials_path:
                self._cli = storage.Client.from_service_account_json(self.credentials_path, **client_kwargs)
            else:
                self._cli = storage.Client(**client_kwargs)
            self._bucket = self._cli.bucket(self.bucket_name)
        return self._bucket

    def _key(self, container: str, relpath: str) -> str:
        return f"{container}/{relpath}"

    def exists(self, container: str, relpath: str) -> bool:
        try:
            blob = self._get_bucket().blob(self._key(container, relpath))
            return bool(blob.exists())
        except Exception:
            return False

    def stream(self, container: str, relpath: str, chunk: int = 8192) -> tuple[Iterator[bytes], Optional[int]]:
        try:
            blob = self._get_bucket().blob(self._key(container, relpath))
            if not blob.exists():
                raise ArtifactNotFound(relpath)
            blob.reload()
            size = getattr(blob, "size", None)
            if hasattr(blob, "open"):
                fobj = blob.open("rb", chunk_size=max(chunk, 262144))

                def _gen() -> Iterator[bytes]:
                    try:
                        while True:
                            data = fobj.read(chunk)
                            if not data:
                                break
                            yield data
                    finally:
                        fobj.close()

                return _gen(), size
            raw = blob.download_as_bytes()
            return _iter_bytes(raw, chunk), len(raw)
        except ArtifactNotFound:
            raise
        except Exception as e:
            raise ArtifactNotFound(relpath) from e

    def read_text(self, container: str, relpath: str, max_bytes: int) -> str:
        try:
            blob = self._get_bucket().blob(self._key(container, relpath))
            data = blob.download_as_bytes(start=0, end=max_bytes)
            return data.decode("utf-8", errors="replace")
        except Exception:
            return ""

    def materialize(self, container: str, relpath: str) -> tuple[Optional[str], bool]:
        tmp: Optional[str] = None
        try:
            blob = self._get_bucket().blob(self._key(container, relpath))
            if not blob.exists():
                return (None, False)
            fd, tmp = tempfile.mkstemp(prefix="cape_gcs_")
            os.close(fd)
            blob.download_to_filename(tmp)
            return (tmp, True)
        except Exception:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            return (None, False)

    def iter_relpaths(self, container: str) -> Iterator[str]:
        prefix = f"{container}/"
        bucket = self._get_bucket()
        blobs = self._cli.list_blobs(bucket, prefix=prefix) if self._cli is not None else bucket.list_blobs(prefix=prefix)
        for blob in blobs:
            name = getattr(blob, "name", "")
            rel = name[len(prefix) :]
            if rel and not rel.endswith("/"):
                yield rel

    def download(self, container: str, relpath: str, dest_abspath: str) -> None:
        os.makedirs(os.path.dirname(dest_abspath), exist_ok=True)
        blob = self._get_bucket().blob(self._key(container, relpath))
        blob.download_to_filename(dest_abspath)

    def put_file(self, local_path: str, container: str, relpath: str) -> None:
        blob = self._get_bucket().blob(self._key(container, relpath))
        blob.upload_from_filename(local_path)


class AzureBlobStore(ArtifactStore):
    """Azure Blob Storage backend via `azure-storage-blob`."""

    def __init__(
        self,
        container_name: str,
        connection_string: str = "",
        account_url: str = "",
        credential: str = "",
    ) -> None:
        self.container_name = container_name
        self.connection_string = connection_string or None
        self.account_url = account_url or None
        self.credential = credential or None
        self._service: Any = None
        self._container_client: Any = None

    def _get_container_client(self) -> Any:
        if self._container_client is None:
            from azure.storage.blob import BlobServiceClient

            if self.connection_string:
                self._service = BlobServiceClient.from_connection_string(self.connection_string)
            else:
                cred: Any = self.credential
                if not cred:
                    try:
                        from azure.identity import DefaultAzureCredential

                        cred = DefaultAzureCredential()
                    except ImportError:
                        cred = None
                self._service = BlobServiceClient(account_url=self.account_url or "", credential=cred)
            self._container_client = self._service.get_container_client(self.container_name)
        return self._container_client

    def _key(self, container: str, relpath: str) -> str:
        return f"{container}/{relpath}"

    def exists(self, container: str, relpath: str) -> bool:
        try:
            blob_client = self._get_container_client().get_blob_client(self._key(container, relpath))
            return bool(blob_client.exists())
        except Exception:
            return False

    def stream(self, container: str, relpath: str, chunk: int = 8192) -> tuple[Iterator[bytes], Optional[int]]:
        try:
            blob_client = self._get_container_client().get_blob_client(self._key(container, relpath))
            props = blob_client.get_blob_properties()
            size = getattr(props, "size", None)
            downloader = blob_client.download_blob()
            return downloader.chunks(), size
        except Exception as e:
            raise ArtifactNotFound(relpath) from e

    def read_text(self, container: str, relpath: str, max_bytes: int) -> str:
        try:
            blob_client = self._get_container_client().get_blob_client(self._key(container, relpath))
            downloader = blob_client.download_blob(offset=0, length=max_bytes + 1)
            return downloader.readall().decode("utf-8", errors="replace")
        except Exception:
            return ""

    def materialize(self, container: str, relpath: str) -> tuple[Optional[str], bool]:
        tmp: Optional[str] = None
        try:
            blob_client = self._get_container_client().get_blob_client(self._key(container, relpath))
            downloader = blob_client.download_blob()
            fd, tmp = tempfile.mkstemp(prefix="cape_azure_")
            with os.fdopen(fd, "wb") as f:
                for c in downloader.chunks():
                    f.write(c)
            return (tmp, True)
        except Exception:
            if tmp is not None:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
            return (None, False)

    def iter_relpaths(self, container: str) -> Iterator[str]:
        prefix = f"{container}/"
        for blob in self._get_container_client().list_blobs(name_starts_with=prefix):
            name = getattr(blob, "name", "") or (blob.get("name", "") if isinstance(blob, dict) else "")
            rel = name[len(prefix) :]
            if rel and not rel.endswith("/"):
                yield rel

    def download(self, container: str, relpath: str, dest_abspath: str) -> None:
        os.makedirs(os.path.dirname(dest_abspath), exist_ok=True)
        blob_client = self._get_container_client().get_blob_client(self._key(container, relpath))
        downloader = blob_client.download_blob()
        with open(dest_abspath, "wb") as f:
            for c in downloader.chunks():
                f.write(c)

    def put_file(self, local_path: str, container: str, relpath: str) -> None:
        blob_client = self._get_container_client().get_blob_client(self._key(container, relpath))
        with open(local_path, "rb") as f:
            blob_client.upload_blob(f, overwrite=True)


def get_artifact_store(cfg: Any) -> tuple[ArtifactStore, bool]:
    """Return `(store, is_remote_store)` for the object-storage config.

    When `cfg.enabled` is False, returns `(LocalFSStore(storage/analyses), False)`.
    When `cfg.enabled` is True, dispatches on `cfg.backend` (`s3`, `gcs`, `azure`, `local`).
    """
    from lib.cuckoo.common.constants import CUCKOO_ROOT

    if not getattr(cfg, "enabled", False):
        return LocalFSStore(os.path.join(CUCKOO_ROOT, "storage", "analyses")), False

    backend = str(getattr(cfg, "backend", None) or getattr(cfg, "storage_backend", "s3") or "s3").strip().lower()
    local_root = getattr(cfg, "local_root", None) or getattr(cfg, "central_local_root", "")
    bucket = getattr(cfg, "bucket", None) or getattr(cfg, "s3_bucket", "")
    region = getattr(cfg, "region", None) or getattr(cfg, "s3_region", "us-east-1")
    endpoint_url = getattr(cfg, "endpoint_url", None) or getattr(cfg, "s3_endpoint_url", "")
    access_key = getattr(cfg, "access_key", None) or getattr(cfg, "s3_access_key", "")
    secret_key = getattr(cfg, "secret_key", None) or getattr(cfg, "s3_secret_key", "")

    if backend == "local" and local_root:
        return LocalFSStore(local_root), True
    if backend == "gcs":
        return (
            GCSStore(
                bucket=bucket,
                project=getattr(cfg, "gcp_project", ""),
                credentials_path=getattr(cfg, "gcp_credentials_path", ""),
                endpoint_url=endpoint_url,
            ),
            True,
        )
    if backend == "azure":
        return (
            AzureBlobStore(
                container_name=bucket,
                connection_string=getattr(cfg, "azure_connection_string", ""),
                account_url=getattr(cfg, "azure_account_url", "") or endpoint_url,
                credential=getattr(cfg, "azure_credential", "") or secret_key,
            ),
            True,
        )
    return S3Store(bucket, region, endpoint_url, access_key, secret_key), True
