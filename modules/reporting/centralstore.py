"""centralstore — worker-side ingest seam for central mode.

central_mode OFF (default): no-op. The worker behaves byte-for-byte single-node.

central_mode ON: stamp the broker-supplied global job_id into results.info.job_id
and push the analysis artifact tree to S3 at <prefix>/<job_id>/<rel>. Runs at
order 9998 — BEFORE the native mongodb reporting module (order 9999) — so the
report doc that mongodb.py writes to the central DocumentDB already carries
info.job_id. The DocumentDB write itself is the NATIVE mongodb.py path pointed at
DocumentDB via [mongodb] (tls=yes, retrywrites=no) — validated against live DocumentDB
(loop_saver/$set, calls chunking, files $addToSet, tenant_scope_idx). This module only adds the FS->S3 half
plus the job_id keying the read seam (artifact_storage.artifact_response) resolves.
"""
import logging
import os
import re

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.central_mode import central_mode_config, upload_target_realpath
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.storage_backend import get_artifact_store

log = logging.getLogger(__name__)

# job_id becomes an S3 key segment, so it must not contain path separators or
# traversal. The broker should stamp an authenticated job_id; this is the last
# line of defence against a tenant-supplied `custom` poisoning another job's
# prefix (audit CRITICAL-1). local-<int> fallback satisfies the allowlist.
# Must start with an alnum (no leading '.'/'-'/'_') AND contain no '..' run, so a
# value like '.', '..', '.foo' or 'a..b' can never collapse 'results/<job_id>/' to a
# parent ref ('results/../') in an S3 key or the local staging path. _is_safe_job_id
# applies both rules (the regex alone permitted '.'/'..').
_JOB_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def _is_safe_job_id(job_id):
    return bool(job_id) and _JOB_ID_RE.match(job_id) is not None and ".." not in job_id

# Upload the whole analysis tree to S3 (the "heavy detail" tier): shots, dropped
# files, pcap, procdump, AND reports/ (report.json/html/pdf are downloadable
# artifacts the filereport view serves). The DocumentDB report doc written by the
# native mongodb.py module is ADDITIVE (it powers the queryable UI tabs) — it does
# not replace the report files, so nothing is excluded here.
_EXCLUDE_DIRS = set()


def resolve_job_id(custom, analysis_id):
    """The broker passes the global job_id through the task `custom` field, carried
    all the way to reporting. Accept 'job_id=<v>' (optionally among other
    comma-separated k=v pairs) or a bare token. Fall back to 'local-<id>' so central
    mode also works when an analysis was submitted directly (no broker)."""
    if custom:
        text = str(custom)
        for part in text.split(","):
            part = part.strip()
            if part.startswith("job_id="):
                v = part.split("=", 1)[1].strip()
                if v:
                    return v
        token = text.strip()
        if token and "=" not in token and "," not in token:
            return token
    return f"local-{analysis_id}"


class CentralStore(Report):
    """Ship analysis artifacts to S3 + stamp the central job_id (central mode only)."""

    order = 9998  # before mongodb (9999): stamp info.job_id before the central DocumentDB write

    def run(self, results):
        cfg = central_mode_config()
        if not cfg.enabled:
            return  # single-node: no-op, behavior byte-for-byte unchanged

        store, _is_central = get_artifact_store(cfg)
        # Validate the configured backend's prerequisites up front so a misconfig fails
        # with one clean CuckooReportError, not N per-file upload failures (which would
        # leave the job retained-but-never-done). The S3 path (default storage_backend)
        # needs a bucket + boto3; the shared-mount path (storage_backend=local +
        # central_local_root) needs neither.
        using_local_mount = cfg.storage_backend == "local" and bool(cfg.central_local_root)
        if not using_local_mount:
            if not cfg.s3_bucket:
                raise CuckooReportError("centralstore: central_mode enabled but [central_mode] s3_bucket unset")
            try:
                import boto3  # noqa: F401
            except ImportError as e:
                raise CuckooReportError("centralstore: central mode requires boto3") from e

        info = results.setdefault("info", {})
        analysis_id = info.get("id")
        job_id = info.get("job_id") or resolve_job_id(info.get("custom"), analysis_id)
        if not _is_safe_job_id(job_id):
            # Refuse a job_id that could escape/poison another job's S3 prefix.
            raise CuckooReportError(
                "centralstore: refusing unsafe job_id %r (must match %s and contain no '..')"
                % (job_id, _JOB_ID_RE.pattern))
        info["job_id"] = job_id  # carried into the DocumentDB doc; read seam keys S3 by it

        # Align info.id to the CENTRAL task id when the broker assigned a
        # "ui-<central_task_id>" job_id (the central-submit-bridge does this). The
        # worker's local info.id is a per-worker sequence that collides across workers
        # and is meaningless to the central UI, which addresses every analysis by its
        # OWN task id. Rewriting info.id here (before mongodb.py at 9999 writes the doc)
        # makes the central DocumentDB doc resolvable by the central task id natively —
        # so the report view, all report-tab lookups, and the artifact seam work without
        # touching ~25 info.id call sites in the upstream-synced views.py.
        _m = re.match(r"^ui-(\d+)$", job_id)
        if _m:
            info["id"] = int(_m.group(1))

        # The per-analysis container the read seam resolves to (artifact_storage.
        # _store_and_container builds the same "<prefix>/<job_id>"). The raw object I/O
        # is the pluggable store (S3-compatible or shared mount); the symlink-exfil
        # guard + job_id keying stay here.
        container = f"{cfg.s3_prefix}/{job_id}"
        uploaded, failed = self._upload_tree(store, container)
        # Guac recordings live outside the analysis tree (top-level storage/
        # guacrecordings/), so they need their own pass. Fold their counts in so the
        # done marker — the cleanup purge gate — only fires once EVERYTHING this job
        # produced (tree + binaries + any recording) is confirmed in the central store.
        rec_up, rec_failed = self._upload_guacrecordings(store, container, analysis_id)
        uploaded += rec_up
        failed += rec_failed
        log.info("centralstore: uploaded %d artifacts (%d recordings) to %s/ (%d failed)",
                 uploaded, rec_up, container, failed)

        # Stamp a local marker ONLY when the whole tree is confirmed in S3. The worker's
        # cape-nvme-cleanup gate keys off this file: present => artifacts are durable in
        # the central stores => the local (ephemeral-NVMe) copy is safe to purge. On any
        # upload failure we leave no marker, so the analysis is retained until it is
        # re-confirmed or the worker recycles (24h) — never purged unconfirmed.
        if failed == 0:
            _emit_done_marker(store, container, self.analysis_path, cfg, job_id, uploaded)
        else:
            log.warning("centralstore: %d upload(s) failed for job_id=%s; NOT marking done "
                        "(local copy retained for cleanup safety)", failed, job_id)

    def _trusted_roots(self, base_real):
        """Content roots a sample-influenced symlink may legitimately resolve into:
        storage/binaries (the content-addressed sample/dropped-file store the analysis
        dir's `binary` symlink targets) and storage/guacrecordings. base_real is
        .../storage/analyses/<id>, so the storage root is two levels up."""
        storage_root = os.path.dirname(os.path.dirname(base_real))
        return [
            os.path.realpath(os.path.join(storage_root, "binaries")),
            os.path.realpath(os.path.join(storage_root, "guacrecordings")),
        ]

    def _upload_tree(self, store, container):
        base = self.analysis_path
        if not base or not os.path.isdir(base):
            log.warning("centralstore: analysis_path missing or not a dir: %s", base)
            return 0, 0
        base_real = os.path.realpath(base)
        trusted_roots = self._trusted_roots(base_real)
        count = 0
        failed = 0
        for root, dirs, files in os.walk(base):
            # don't descend symlinked dirs; drop excluded dirs
            dirs[:] = [d for d in dirs if d not in _EXCLUDE_DIRS and not os.path.islink(os.path.join(root, d))]
            for fn in files:
                full = os.path.join(root, fn)
                # A regular in-tree file uploads itself; a symlink into a trusted
                # content root (binary -> storage/binaries/<sha256>, a recording ->
                # storage/guacrecordings/) uploads its RESOLVED content under the
                # analysis-relative key. Anything resolving elsewhere (a planted
                # symlink to e.g. ~/.aws/credentials) returns None and is skipped —
                # the artifact-exfil guard stays intact (audit CRITICAL).
                src = upload_target_realpath(full, base_real, trusted_roots)
                if src is None:
                    log.warning("centralstore: skipping out-of-tree/untrusted artifact %s", full)
                    continue
                rel = os.path.relpath(full, base)
                try:
                    store.put_file(src, container, rel)
                    count += 1
                except Exception as e:
                    failed += 1
                    log.warning("centralstore: failed to upload %s -> %s/%s: %s", rel, container, rel, e)
        return count, failed

    def _upload_guacrecordings(self, store, container, task_id):
        """Ship Guacamole session recordings for this task. Recordings live in the
        top-level storage/guacrecordings/ (NOT inside the analysis tree, so the walk
        above never sees them) and are named '<task_id>_<session_id>' by the guac
        consumer. They only exist when an analyst live-viewed the VM mid-detonation,
        so this is usually a no-op; when present they upload under <job_id>/
        guacrecordings/<name> so the central store has them before the worker purges.
        """
        base_real = os.path.realpath(self.analysis_path)
        rec_root = os.path.join(os.path.dirname(os.path.dirname(base_real)), "guacrecordings")
        if not task_id or not os.path.isdir(rec_root):
            return 0, 0
        count = 0
        failed = 0
        prefix_match = f"{task_id}_"
        for fn in os.listdir(rec_root):
            # exact '<task_id>' or '<task_id>_<session>' — never a different task that
            # merely shares a leading digit (e.g. task 1 vs 15): require '_' boundary.
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
                log.warning("centralstore: failed to upload recording %s -> %s/%s: %s", fn, container, rel, e)
        return count, failed


def _emit_done_marker(store, container, analysis_path, cfg, job_id, uploaded):
    """Emit the analysis completion marker, in TWO places, once the whole tree is confirmed:

    1. LOCAL — storage/analyses/<id>/.centralstore.done. The worker's cape-nvme-cleanup purges
       only analyses carrying this file, so it can never delete a job that didn't reach the
       central store.
    2. CENTRAL STORE — uploaded as the FINAL object at <container>/.centralstore.done. The READ
       seam (artifact_storage._stage_tree) treats this key as the completion signal and only then
       caches .central_staged; WITHOUT the store copy `complete` is never True, so every central
       report view re-stages the entire tree from the store on every request. Uploaded last (and
       only when failed==0 upstream) so a listing taken mid-upload never shows the marker before
       the tree is complete.

    Best-effort: a marker failure never breaks reporting — the artifacts are already durable. If
    the local write fails there's nothing to upload; if the store upload fails the local gate
    still stands (cleanup stays safe) and the read side falls back to the per-file download seam."""
    import json
    import time

    if not analysis_path or not os.path.isdir(analysis_path):
        return
    marker = os.path.join(analysis_path, ".centralstore.done")
    # Backend-aware location string: s3://bucket/... for the S3 path, or the shared
    # mount's <root>/<prefix>/<job_id>/ for the local path. Informational only.
    if cfg.storage_backend == "local" and cfg.central_local_root:
        location = os.path.join(cfg.central_local_root, cfg.s3_prefix, job_id) + os.sep
    else:
        location = "s3://%s/%s/%s/" % (cfg.s3_bucket, cfg.s3_prefix, job_id)
    try:
        with open(marker, "w") as f:
            json.dump({
                "job_id": job_id,
                "location": location,
                "artifacts": uploaded,
                "ts": time.time(),
            }, f)
    except Exception as e:
        log.warning("centralstore: could not write local done marker %s: %s", marker, e)
        return  # nothing to upload if the local marker couldn't even be written
    # This is the SINGLE object that gates the read-side staging cache (artifact_storage.
    # _stage_tree). Reporting runs once and won't re-emit it, and the worker's cleanup gate (the
    # local marker) will let the ephemeral NVMe copy be purged — so a transient store hiccup here
    # would permanently disable that job's read cache with no self-heal. Retry a few times before
    # giving up; the tree itself is already durable, so this stays best-effort even on total failure.
    for attempt in range(3):
        try:
            store.put_file(marker, container, ".centralstore.done")
            return
        except Exception as e:
            log.warning("centralstore: marker upload attempt %d/3 to %s/.centralstore.done failed: %s",
                        attempt + 1, container, e)
            if attempt < 2:
                time.sleep(0.25 * (attempt + 1))
    log.warning("centralstore: gave up uploading %s/.centralstore.done after 3 attempts "
                "(read-side staging cache disabled for this job; artifacts still served per-file)", container)
