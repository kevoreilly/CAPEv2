"""Worker-side object-storage artifact uploader (`ObjectStorage` / `CentralStore`).

When `[object_storage] enabled = no` (default): no-op.
When `[object_storage] enabled = yes`: stamps `info.job_id` into `results["info"]` and
uploads the analysis artifact tree + Guacamole recordings to `<prefix>/<job_id>/<relpath>`
on the configured backend (`s3`, `gcs`, `azure`, or `local`).

Can be invoked automatically via `lib.tenancy.hooks.default_report_stamp_hook` (before
`mongodb.py` runs) or as a CAPEv2 `Report` plugin (`ObjectStorage` / `CentralStore`,
`order = 9998`).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Optional

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.tenancy.storage.artifact_storage import _SAFE_JOB_ID_RE, _is_safe_job_id, job_id_from_custom
from lib.tenancy.storage.config import (
    object_storage_bridge_required,
    object_storage_config,
    upload_target_realpath,
)
from lib.tenancy.storage.storage_backend import ArtifactStore, get_artifact_store

log = logging.getLogger(__name__)

_EXCLUDE_DIRS: set[str] = set()


def resolve_job_id(custom: Any, analysis_id: Any) -> str:
    """Resolve the object-storage `job_id` from `custom` (or `CAPE_MAIN_TASK_ID` / `local-<analysis_id>`)."""
    parsed = job_id_from_custom(custom)
    if parsed:
        return parsed
    main_tid = os.environ.get("CAPE_MAIN_TASK_ID")
    if main_tid:
        try:
            return f"ui-{int(main_tid)}"
        except (TypeError, ValueError):
            pass
    return f"local-{analysis_id}"


def _validate_backend_prereqs(cfg: Any) -> None:
    backend = str(getattr(cfg, "backend", None) or getattr(cfg, "storage_backend", "s3") or "s3").strip().lower()
    local_root = getattr(cfg, "local_root", None) or getattr(cfg, "central_local_root", "")
    bucket = getattr(cfg, "bucket", None) or getattr(cfg, "s3_bucket", "")

    if backend == "local" and bool(local_root):
        return
    if not bucket:
        raise CuckooReportError("object_storage: enabled but bucket is unset")
    if backend == "s3":
        try:
            import boto3  # noqa: F401
        except ImportError as e:
            raise CuckooReportError("object_storage: backend 's3' requires boto3") from e
    elif backend == "gcs":
        try:
            from google.cloud import storage  # noqa: F401
        except ImportError as e:
            raise CuckooReportError("object_storage: backend 'gcs' requires google-cloud-storage") from e
    elif backend == "azure":
        try:
            from azure.storage.blob import BlobServiceClient  # noqa: F401
        except ImportError as e:
            raise CuckooReportError("object_storage: backend 'azure' requires azure-storage-blob") from e


def _trusted_roots(base_real: str) -> list[str]:
    storage_root = os.path.dirname(os.path.dirname(base_real))
    return [
        os.path.realpath(os.path.join(storage_root, "binaries")),
        os.path.realpath(os.path.join(storage_root, "guacrecordings")),
    ]


def _upload_tree(store: ArtifactStore, container: str, analysis_path: Optional[str]) -> tuple[int, int]:
    if not analysis_path or not os.path.isdir(analysis_path):
        log.warning("object_storage: analysis_path missing or not a dir: %s", analysis_path)
        return 0, 0
    base_real = os.path.realpath(analysis_path)
    trusted = _trusted_roots(base_real)
    count = 0
    failed = 0
    for root, dirs, files in os.walk(analysis_path):
        dirs[:] = [d for d in dirs if d not in _EXCLUDE_DIRS and not os.path.islink(os.path.join(root, d))]
        for fn in files:
            full = os.path.join(root, fn)
            src = upload_target_realpath(full, base_real, trusted)
            if src is None:
                log.warning("object_storage: skipping out-of-tree/untrusted artifact %s", full)
                continue
            rel = os.path.relpath(full, analysis_path)
            try:
                store.put_file(src, container, rel)
                count += 1
            except Exception as e:
                failed += 1
                log.warning("object_storage: failed to upload %s -> %s/%s: %s", rel, container, rel, e)
    return count, failed


def _upload_guacrecordings(
    store: ArtifactStore,
    container: str,
    analysis_path: Optional[str],
    task_id: Any,
) -> tuple[int, int]:
    if not analysis_path:
        return 0, 0
    base_real = os.path.realpath(analysis_path)
    rec_root = os.path.join(os.path.dirname(os.path.dirname(base_real)), "guacrecordings")
    if not task_id or not os.path.isdir(rec_root):
        return 0, 0
    count = 0
    failed = 0
    prefix_match = f"{task_id}_"
    for fn in os.listdir(rec_root):
        if fn != str(task_id) and not fn.startswith(prefix_match):
            continue
        full = os.path.join(rec_root, fn)
        if os.path.islink(full) or not os.path.isfile(full):
            continue
        rel = f"guacrecordings/{fn}"
        try:
            store.put_file(full, container, rel)
            count += 1
        except Exception as e:
            failed += 1
            log.warning("object_storage: failed to upload recording %s -> %s/%s: %s", fn, container, rel, e)
    return count, failed


def _format_location(cfg: Any, job_id: str) -> str:
    backend = str(getattr(cfg, "backend", None) or getattr(cfg, "storage_backend", "s3") or "s3").strip().lower()
    local_root = getattr(cfg, "local_root", None) or getattr(cfg, "central_local_root", "")
    bucket = getattr(cfg, "bucket", None) or getattr(cfg, "s3_bucket", "")
    prefix = getattr(cfg, "prefix", None) or getattr(cfg, "s3_prefix", "results")
    if backend == "local" and local_root:
        return os.path.join(local_root, prefix, job_id) + os.sep
    scheme = {"gcs": "gs", "azure": "az"}.get(backend, "s3")
    return f"{scheme}://{bucket}/{prefix}/{job_id}/"


def _emit_done_marker(
    store: ArtifactStore,
    container: str,
    analysis_path: Optional[str],
    cfg: Any,
    job_id: str,
    uploaded: int,
) -> None:
    if not analysis_path or not os.path.isdir(analysis_path):
        return
    marker = os.path.join(analysis_path, ".centralstore.done")
    location = _format_location(cfg, job_id)
    payload = {
        "job_id": job_id,
        "location": location,
        "artifacts": uploaded,
        "ts": time.time(),
    }
    try:
        with open(marker, "w") as f:
            json.dump(payload, f)
    except Exception as e:
        log.warning("object_storage: could not write local done marker %s: %s", marker, e)
        return
    for attempt in range(3):
        try:
            store.put_file(marker, container, ".centralstore.done")
            return
        except Exception as e:
            log.warning(
                "object_storage: marker upload attempt %d/3 to %s/.centralstore.done failed: %s",
                attempt + 1,
                container,
                e,
            )
            if attempt < 2:
                time.sleep(0.25 * (attempt + 1))
    log.warning("object_storage: gave up uploading %s/.centralstore.done after 3 attempts", container)


class ObjectStorage(Report):
    """Ship analysis artifacts to object storage (`s3`, `gcs`, `azure`, `local`) and stamp `info.job_id`."""

    order = 9998

    def run(self, results: dict[str, Any]) -> None:
        cfg = object_storage_config()
        if not cfg.enabled:
            return

        info = results.setdefault("info", {})
        if info.get("_object_storage_uploaded"):
            return

        store, _is_remote = get_artifact_store(cfg)
        _validate_backend_prereqs(cfg)

        analysis_id = info.get("id")
        job_id = info.get("job_id") or resolve_job_id(info.get("custom"), analysis_id)
        if not _is_safe_job_id(job_id):
            raise CuckooReportError(
                f"object_storage: refusing unsafe job_id {job_id!r} (must match {_SAFE_JOB_ID_RE.pattern} and contain no '..')"
            )
        info["job_id"] = job_id

        _m = re.match(r"^ui-(\d+)$", job_id)
        if not _m and object_storage_bridge_required():
            raise CuckooReportError(
                f"object_storage: refusing non-bridged analysis (job_id={job_id!r}) under multitenancy -- "
                "tenant-isolated object-storage submission requires a bridged job_id (ui-<central_id>)"
            )
        if _m:
            info["id"] = int(_m.group(1))

        prefix = getattr(cfg, "prefix", None) or getattr(cfg, "s3_prefix", "results")
        container = f"{prefix}/{job_id}"
        uploaded, failed = self._upload_tree(store, container)
        rec_up, rec_failed = self._upload_guacrecordings(store, container, analysis_id)
        uploaded += rec_up
        failed += rec_failed
        log.info(
            "object_storage: uploaded %d artifacts (%d recordings) to %s/ (%d failed)",
            uploaded,
            rec_up,
            container,
            failed,
        )

        if failed == 0:
            _emit_done_marker(store, container, getattr(self, "analysis_path", None), cfg, job_id, uploaded)
            info["_object_storage_uploaded"] = True
        else:
            log.warning(
                "object_storage: %d upload(s) failed for job_id=%s; NOT marking done",
                failed,
                job_id,
            )

    def _trusted_roots(self, base_real: str) -> list[str]:
        return _trusted_roots(base_real)

    def _upload_tree(self, store: ArtifactStore, container: str) -> tuple[int, int]:
        return _upload_tree(store, container, getattr(self, "analysis_path", None))

    def _upload_guacrecordings(self, store: ArtifactStore, container: str, task_id: Any) -> tuple[int, int]:
        return _upload_guacrecordings(store, container, getattr(self, "analysis_path", None), task_id)


CentralStore = ObjectStorage


def upload_analysis_artifacts(results: dict[str, Any], analysis_path: Optional[str] = None) -> None:
    """Invoke `ObjectStorage` upload from the report hook when `[object_storage] enabled = yes`."""
    cfg = object_storage_config()
    if not cfg.enabled:
        return
    info = results.get("info")
    if not isinstance(info, dict) or info.get("_object_storage_uploaded"):
        return
    task_id = info.get("id")
    if analysis_path is None and task_id is not None:
        cand = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
        if os.path.isdir(cand):
            analysis_path = cand
    reporter = ObjectStorage()
    if analysis_path:
        reporter.set_path(analysis_path)
    reporter.run(results)
