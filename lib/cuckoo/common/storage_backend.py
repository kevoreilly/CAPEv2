"""Pluggable artifact-storage backend for central mode.

The central-mode artifact seam (lib/cuckoo/common/artifact_storage.py read side,
modules/reporting/centralstore.py write side) used boto3's S3 client with AWS defaults
directly — the ONLY hard AWS coupling in the central-mode CAPE code. This module pulls
that behind a small vendor-neutral interface so central mode runs on ANY S3-compatible
object store (AWS S3, MinIO, Ceph RGW, …) or a shared local/NFS mount, with the endpoint
and credentials supplied by config. Nothing AWS-shaped lives here — bucket/endpoint/region/
creds are values in [central_mode], injected at runtime.

A `container` is the per-analysis root (single-node: the storage/analyses/<task_id> dir;
central: the "<s3_prefix>/<job_id>" key prefix); `relpath` is the artifact path within it
(the caller validates it with _safe_relpath before passing it here). The stores are
Django-free — they return (byte-iterator, length) and the caller builds the HTTP response —
so this module is portable + unit-testable without the web stack.
"""
import os
import shutil
import tempfile


class ArtifactNotFound(Exception):
    """Raised by stream()/read bytes when an artifact key is absent."""


class ArtifactStore:
    """Abstract per-analysis object store. Backends implement raw object ops keyed by
    (container, relpath)."""

    def exists(self, container, relpath) -> bool:
        raise NotImplementedError

    def stream(self, container, relpath, chunk=8192):
        """Return (byte_iterator, content_length_or_None). Raise ArtifactNotFound if absent."""
        raise NotImplementedError

    def read_text(self, container, relpath, max_bytes):
        """Return up to max_bytes of text (utf-8, errors=replace), or "" if absent."""
        raise NotImplementedError

    def materialize(self, container, relpath):
        """Return (local_path, is_temp) for a caller that needs a real file (random access,
        external tool). is_temp=True means the caller must delete it. (None, False) if absent."""
        raise NotImplementedError

    def iter_relpaths(self, container):
        """Yield each artifact relpath present under `container` (for staging)."""
        raise NotImplementedError

    def download(self, container, relpath, dest_abspath):
        """Copy one artifact to dest_abspath (creates parent dirs). Best-effort raise on error."""
        raise NotImplementedError

    def put_file(self, local_path, container, relpath):
        """Write a local file into the store at (container, relpath)."""
        raise NotImplementedError


def _iter_file(path, chunk):
    with open(path, "rb") as f:
        while True:
            data = f.read(chunk)
            if not data:
                break
            yield data


class LocalFSStore(ArtifactStore):
    """Filesystem backend. Used for single-node (base=storage/analyses, container=<task_id>)
    AND for a central deployment on a shared local/NFS mount (base=central_local_root,
    container="<prefix>/<job_id>")."""

    def __init__(self, base_dir):
        self.base_dir = base_dir

    def _path(self, container, relpath):
        return os.path.join(self.base_dir, str(container), relpath)

    def exists(self, container, relpath) -> bool:
        return os.path.exists(self._path(container, relpath))

    def stream(self, container, relpath, chunk=8192):
        path = self._path(container, relpath)
        if not os.path.exists(path):
            raise ArtifactNotFound(relpath)
        return _iter_file(path, chunk), os.path.getsize(path)

    def read_text(self, container, relpath, max_bytes):
        path = self._path(container, relpath)
        if not os.path.exists(path):
            return ""
        with open(path, "r", errors="replace") as f:
            return f.read(max_bytes + 1)

    def materialize(self, container, relpath):
        path = self._path(container, relpath)
        return (path, False) if os.path.exists(path) else (None, False)

    def iter_relpaths(self, container):
        root = self._path(container, "")
        if not os.path.isdir(root):
            return
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                yield os.path.relpath(os.path.join(dirpath, fn), root)

    def download(self, container, relpath, dest_abspath):
        src = self._path(container, relpath)
        os.makedirs(os.path.dirname(dest_abspath), exist_ok=True)
        if os.path.realpath(src) != os.path.realpath(dest_abspath):
            shutil.copyfile(src, dest_abspath)

    def put_file(self, local_path, container, relpath):
        dest = self._path(container, relpath)
        dest_dir = os.path.dirname(dest)
        os.makedirs(dest_dir, exist_ok=True)
        if os.path.realpath(local_path) == os.path.realpath(dest):
            return
        # Write to a temp file in the SAME dir (same filesystem) then atomically rename, so a
        # concurrent reader (the central read seam staging from a shared/NFS mount) never observes
        # a half-written object at the final key. A direct copyfile would expose partial content.
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
    """Any S3-compatible object store via boto3. endpoint_url/creds are optional: empty
    endpoint_url -> AWS's default endpoint; empty creds -> boto3's default chain (IAM role
    on AWS). Set them to point at MinIO/Ceph/etc."""

    def __init__(self, bucket, region="us-east-1", endpoint_url="", access_key="", secret_key=""):
        self.bucket = bucket
        self.region = region
        self.endpoint_url = endpoint_url or None
        self.access_key = access_key or None
        self.secret_key = secret_key or None
        self._cli = None

    def _client(self):
        if self._cli is None:
            import boto3

            kwargs = {"region_name": self.region}
            if self.endpoint_url:
                kwargs["endpoint_url"] = self.endpoint_url
            if self.access_key and self.secret_key:
                kwargs["aws_access_key_id"] = self.access_key
                kwargs["aws_secret_access_key"] = self.secret_key
            self._cli = boto3.client("s3", **kwargs)
        return self._cli

    def _key(self, container, relpath):
        return f"{container}/{relpath}"

    def exists(self, container, relpath) -> bool:
        try:
            self._client().head_object(Bucket=self.bucket, Key=self._key(container, relpath))
            return True
        except Exception:
            return False

    def stream(self, container, relpath, chunk=8192):
        try:
            obj = self._client().get_object(Bucket=self.bucket, Key=self._key(container, relpath))
        except Exception:
            raise ArtifactNotFound(relpath)
        return obj["Body"].iter_chunks(chunk), obj.get("ContentLength")

    def read_text(self, container, relpath, max_bytes):
        try:
            obj = self._client().get_object(
                Bucket=self.bucket, Key=self._key(container, relpath), Range=f"bytes=0-{max_bytes}"
            )
            return obj["Body"].read().decode("utf-8", errors="replace")
        except Exception:
            return ""

    def materialize(self, container, relpath):
        # Whole body in one try so a mkstemp OSError (disk full / bad TEMP perms) can't escape and
        # break the (None, False) contract the caller relies on.
        tmp = None
        try:
            obj = self._client().get_object(Bucket=self.bucket, Key=self._key(container, relpath))
            fd, tmp = tempfile.mkstemp(prefix="cape_central_")
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

    def iter_relpaths(self, container):
        prefix = f"{container}/"
        paginator = self._client().get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for obj in page.get("Contents", []):
                rel = obj["Key"][len(prefix):]
                if rel and not rel.endswith("/"):
                    yield rel

    def download(self, container, relpath, dest_abspath):
        os.makedirs(os.path.dirname(dest_abspath), exist_ok=True)
        self._client().download_file(self.bucket, self._key(container, relpath), dest_abspath)

    def put_file(self, local_path, container, relpath):
        self._client().upload_file(local_path, self.bucket, self._key(container, relpath))


def get_artifact_store(cfg):
    """Return (store, is_central) for the central-mode config. Single-node (cfg.enabled
    False) -> LocalFSStore over storage/analyses. Central -> S3Store (default) or LocalFSStore
    when storage_backend='local' + a central_local_root is set."""
    from lib.cuckoo.common.constants import CUCKOO_ROOT

    if not cfg.enabled:
        return LocalFSStore(os.path.join(CUCKOO_ROOT, "storage", "analyses")), False
    if cfg.storage_backend == "local" and cfg.central_local_root:
        return LocalFSStore(cfg.central_local_root), True
    return S3Store(cfg.s3_bucket, cfg.s3_region, cfg.s3_endpoint_url, cfg.s3_access_key, cfg.s3_secret_key), True
