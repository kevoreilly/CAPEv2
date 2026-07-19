"""Central-mode artifact serving — the S3-backed counterparts of the analysis
download/serve views in web/analysis/views.py.

Kept in a SEPARATE module on purpose: views.py is heavily synced from upstream
CAPEv2 (cape/ subtree merges), so it carries only a thin
``if central_mode_config().enabled: return central_<view>(...)`` dispatch at the top
of each affected view. All the central-mode logic lives here, in a file upstream does
not have — so it never participates in a merge conflict, and we can take upstream
advancements with minimal friction.

These functions only run when central mode is ON, and only AFTER the upstream view's
decorator stack (require_task_visibility, ratelimit, auth, …) has already run — so the
relational task is authorized before we touch the central data plane. Single-node
behavior is entirely in views.py and is never reached through this module.
"""
import logging
import os

from django.shortcuts import render

log = logging.getLogger(__name__)


def central_job_id_for_task(task_id):
    """Resolve the broker job_id for a central task from its RDS `custom` field
    (the submit-bridge stamps custom='job_id=ui-<id>'). In the distributed topology
    the worker assigns its OWN local info.id (collides across workers), so the
    universal key for DocumentDB/S3 is info.job_id — NOT info.id. Returns None for a
    non-bridged task (caller falls back to info.id keying for seeded/single-node docs)."""
    # Resolve int() BEFORE the DB try: a non-numeric id (the filereport/full_memory \w+
    # routes) is bad INPUT, not an RDS error -- return None silently so it isn't logged as a
    # DB failure below. Mirrors the sibling _rds_job_id (artifact_storage.py, fixed in 3fa6fdb8/
    # 576d8a95); the two resolvers share job_id_from_custom and must not drift.
    try:
        tid = int(task_id)
    except (TypeError, ValueError):
        return None
    try:
        from analysis.views import db
        from lib.cuckoo.common.artifact_storage import job_id_from_custom

        t = db.view_task(tid)
        # Shared parser (lib.cuckoo.common.artifact_storage.job_id_from_custom) so the
        # web read seam and the lib staging resolver can't drift on the custom format
        # (job_id=ui-5,foo=bar -> "ui-5"; bare token accepted for non-bridged tasks).
        return job_id_from_custom(getattr(t, "custom", None) if t else None)
    except Exception:
        # A genuine non-bridged task returns None WITHOUT an exception (job_id_from_custom).
        # This except is a real RDS error (pool exhaustion / timeout) -- log it so a bridged
        # OWNER silently degraded to the scoped info.id fallback (their own not-yet-reconciled
        # doc lacks the unstamped arm there -> a brief owner-lockout during a DB blip) leaves a
        # signal, not a mystery. Matches _rds_job_id's log.exception on the artifact path.
        log.exception("central_job_id_for_task: RDS lookup failed for task %s; falling back to scoped resolution", tid)
        return None


def central_analysis_query(task_id, scope=None):
    """Mongo filter to fetch a task's analysis doc in central mode.

    PRIMARY key is info.job_id (globally unique) for a bridged task. centralstore also
    re-keys info.id to the unique central task id for every bridged job, so {info.id} is
    likewise unique in a real central deployment (every task arrives via the bridge) —
    which is why the report-tab loaders that query {info.id: task_id} resolve to exactly
    the authorized task's doc, not a colliding worker-local one. The info.id FALLBACK
    here (non-bridged / seeded / single-node docs, where a worker-local info.id can
    collide across workers) is ANDed with the viewer's `scope` (entitled_scope_filter)
    as defence-in-depth so a collision can't surface another tenant's doc (audit HIGH)."""
    jid = central_job_id_for_task(task_id)
    if jid:
        # Bridged: key on the globally-unique info.job_id (RDS-derived from the authorized
        # task's custom). But job_id comes from user-supplied `custom`, so it is NOT an
        # unforgeable authz token — AUTHORIZE the resolved doc against the viewer scope OR the
        # authorized owner's not-yet-reconciled doc. The unstamped arm (info.tenant_id null) MUST
        # be constrained to THIS task (info.id == the decorator-authorized task_id): every doc is
        # inserted unstamped and stamped later by the reconcile (and stranded on reconcile-skip),
        # so an UNCONSTRAINED null arm lets a forged custom job_id (ui-<victimN>) read a DIFFERENT
        # task's unstamped doc cross-tenant (adversarial-review HIGH). A bridged owner's doc is
        # re-keyed to its central id, so info.id == task_id still resolves the legit owner; a forged
        # job_id at another task's unstamped doc does not. A forged job_id -> another tenant's
        # STAMPED doc fails the scope arm too. scope None (see-all/break-glass/MT-off) = unrestricted.
        q = {"info.job_id": jid}
        if scope:
            try:
                _own_unstamped = {"$and": [{"info.tenant_id": None}, {"info.id": int(task_id)}]}
                q = {"$and": [q, {"$or": [scope, _own_unstamped]}]}
            except (TypeError, ValueError):
                q = {"$and": [q, scope]}  # non-numeric task id: drop the null arm (fail-closed)
        return q
    # Non-bridged FALLBACK (seeded/single-node/worker-local docs): info.id can collide
    # across workers, so AND the viewer scope as defence-in-depth against surfacing another
    # tenant's colliding doc (audit HIGH: cross-store id collision).
    q = {"info.id": int(task_id)}
    if scope:
        q = {"$and": [q, scope]}
    return q


def scoped_analysis_query(request, task_id, extra=None):
    """Central-mode-scoped Mongo filter for a per-task read of the shared 'analysis' collection.

    Shared seam for report(), the apiv2 report-family, the web report-tab loaders, and the compare
    seed reads. In central mode a colliding worker-local info.id (reconcile-skipped / direct-submit /
    seeded doc) can shadow another tenant's central task id in the shared DocumentDB (audit HIGH
    cross-store collision), so key on central_analysis_query -- which ANDs the viewer scope onto the
    non-bridged info.id fallback. Single-node / non-central: the bare info.id (behaviour unchanged).
    viewer_scope() fails CLOSED on a real resolution error, and this deliberately does NOT swallow
    that into an unscoped read.

    extra: additional AND constraints for reads that key on more than info.id (e.g.
    {"behavior.processes.process_id": pid}); merged with $and so the scoped filter still targets the
    right sub-document without dropping the collision defence.
    """
    from lib.cuckoo.common.central_mode import central_mode_config

    if central_mode_config().enabled:
        from analysis.central_scope import viewer_scope

        q = central_analysis_query(task_id, scope=viewer_scope(request.user))
    else:
        q = {"info.id": int(task_id)}
    return {"$and": [q, extra]} if extra else q


def central_delete_analysis(request, task_id):
    """Delete a task's Mongo analysis + call chunks, tenant-scoped in central mode.

    Single-node / non-central: delegates to the upstream mongo_delete_data(task_id) (unchanged).

    Central mode: a colliding worker-local / direct-submit / reconcile-skipped doc for another tenant can
    share this task's bare info.id (analysis) and task_id (calls) in the shared DocumentDB, so an unscoped
    mongo_delete_data would DESTROY that tenant's docs (audit MEDIUM cross-tenant destructive write). Instead
    resolve ONLY the caller's scope-matched analysis doc (scoped_analysis_query -> bridged info.job_id, else
    info.id AND viewer_scope) and delete it by _id plus its OWN call chunks by their ObjectIds (from
    behavior.processes[].calls) -- never by the bare task_id, which a colliding tenant's calls also carry.
    FAIL-CLOSED: if no scope-matched doc resolves, delete nothing on the Mongo side (the caller still removes
    the SQL row + the local storage tree).

    Documented residual: the upstream mongo_delete_data 'analysis' hook (remove_task_references_from_files)
    $pullAll's the bare task_id from the shared files collection's task-id backrefs; it is intentionally NOT
    run on this scoped path because keying on the bare task_id would re-introduce the same cross-tenant
    collision (pulling the id from a colliding tenant's file backrefs -> eventual GC of shared bytes).
    Precisely scoping it needs a tenant-qualified backref key (a files data-model change, tracked
    separately). The residual is a caller-side stale backref on the caller's OWN deleted task -- fail-safe,
    it never touches another tenant."""
    from lib.cuckoo.common.central_mode import central_mode_config

    if not central_mode_config().enabled:
        from dev_utils.mongodb import mongo_delete_data

        mongo_delete_data(task_id)
        return

    from dev_utils.mongodb import mongo_delete_many, mongo_find_one

    doc = mongo_find_one("analysis", scoped_analysis_query(request, task_id), {"_id": 1, "behavior.processes.calls": 1})
    if not doc:
        return  # fail-closed: no scope-matched doc for this caller
    call_ids = []
    for proc in (doc.get("behavior") or {}).get("processes", []) or []:
        call_ids.extend(proc.get("calls") or [])
    if call_ids:
        mongo_delete_many("calls", {"_id": {"$in": call_ids}})
    mongo_delete_many("analysis", {"_id": doc["_id"]})


def _task_sample_sha256(request, task_id):
    """The sha256 of THIS task's submitted sample (mongo target.file.sha256), scoped to
    the viewer. central S3 stores only this binary (key <job_id>/binary), not a by-hash
    store, so callers serving sample bytes must confirm the requested hash IS this."""
    from dev_utils.mongodb import mongo_find_one
    from analysis.central_scope import viewer_scope

    doc = mongo_find_one("analysis", central_analysis_query(task_id, scope=viewer_scope(request.user)),
                         {"target.file.sha256": 1, "_id": 0})
    return ((((doc or {}).get("target") or {}).get("file") or {}).get("sha256") or "").lower()


def central_stage_one(request, task_id, s3_relpath, dest_abspath):
    """Materialize ONE S3 artifact (<job_id>/<s3_relpath>) to an exact local path so an
    upstream zip path that reads that specific path works centrally. Used for memdumpzip
    (memory/ is excluded from the bulk stage) and staticzip (reads the global binaries
    store, OUTSIDE the analysis tree). Best-effort; never raises into the view."""
    import shutil

    from analysis.central_scope import viewer_scope
    from lib.cuckoo.common.artifact_storage import materialize_artifact

    if os.path.exists(dest_abspath):
        return
    src, is_temp = materialize_artifact(task_id, s3_relpath, scope=viewer_scope(request.user))
    if not src:
        return
    try:
        os.makedirs(os.path.dirname(dest_abspath), exist_ok=True)
        (shutil.move if is_temp else shutil.copy)(src, dest_abspath)
    except Exception:
        if is_temp:
            try:
                os.unlink(src)
            except OSError:
                pass


def central_stage_local(request, task_id):
    """Stage the S3 analysis tree into the local FS so an upstream view that reads
    storage/analyses/<task_id>/ directly works centrally without a per-file rewrite.
    Used for the zip-on-the-fly download bundles (zip_categories) — re-implementing
    CAPE's pyzipper/password/download_all archiving in the per-file S3 seam would be a
    lot of duplicated fork code, so instead we materialize the tree and let the
    upstream zip path below run byte-for-byte unchanged. Cached via the .central_staged
    marker (cheap on repeat); best-effort (never raises into the view)."""
    from analysis.central_scope import viewer_scope
    from lib.cuckoo.common.artifact_storage import ensure_local_analysis

    ensure_local_analysis(task_id, scope=viewer_scope(request.user))


def central_file_nl(request, category, task_id, dlfile):
    """Inline report assets: screenshots, bingraph, vba2graph (file_nl)."""
    from django.http import Http404

    from analysis.central_scope import viewer_scope
    from lib.cuckoo.common.artifact_storage import artifact_response

    # tenant-scope the S3/DocumentDB lookup as defence-in-depth against task_id
    # collisions across workers (audit HIGH).
    scope = viewer_scope(request.user)
    if category == "screenshot":
        cands = [(os.path.join("shots", dlfile + ext), dlfile + ext, cd) for ext, cd in ((".jpg", "image/jpeg"), (".png", "image/png"))]
    elif category == "bingraph":
        cands = [(os.path.join("bingraph", dlfile + "-ent.svg"), dlfile + "-ent.svg", "image/svg+xml")]
    elif category == "vba2graph":
        cands = [(os.path.join("vba2graph", "svg", f"{dlfile}.svg"), f"{dlfile}.svg", "image/svg+xml")]
    else:
        return render(request, "error.html", {"error": "Category not defined"})
    for relpath, fn, cd in cands:
        try:
            return artifact_response(task_id, relpath, cd, fn, scope=scope)
        except Http404:
            continue
    return render(request, "error.html", {"error": f"Could not find {category} {dlfile}"})


def central_filereport(request, task_id, fname):
    """Full analysis report download (filereport); fname is the resolved report file."""
    from django.http import Http404

    from analysis.central_scope import viewer_scope
    from lib.cuckoo.common.artifact_storage import artifact_response

    scope = viewer_scope(request.user)
    try:
        return artifact_response(task_id, f"reports/{fname}", "application/octet-stream", f"{task_id}_{fname}", scope=scope)
    except Http404:
        return render(request, "error.html", {"error": f"File not found: {fname}"})


def central_full_memory_dump(request, analysis_number, names):
    """Full memory dump / its strings (whole-file); names = candidate relpaths."""
    from django.http import Http404

    from analysis.central_scope import viewer_scope
    from lib.cuckoo.common.artifact_storage import artifact_response

    scope = viewer_scope(request.user)
    for name in names:
        try:
            return artifact_response(analysis_number, name, "application/octet-stream", name, scope=scope)
        except Http404:
            continue
    return render(request, "error.html", {"error": "File not found"})


def central_file(request, category, task_id, dlfile):
    """Main multi-category artifact download (file). Maps each category to its
    analysis-relative S3 relpath — the layout centralstore uploads to
    s3://<bucket>/results/<job_id>/<relpath>. On-the-fly bundles (zip_categories,
    pcapng) and search-driven *zipall sets aren't materialized in S3, so they return a
    clear central-mode error rather than a silent 404."""
    from django.http import Http404

    from analysis.central_scope import viewer_scope, viewer_can_view_sample
    from lib.cuckoo.common.artifact_storage import artifact_response
    from analysis.views import zip_categories

    OCTET = "application/octet-stream"
    PCAP = "application/vnd.tcpdump.pcap"

    if category in ("sample", "static"):
        # by-hash sample download: enforce the SAME visible-task-referencing-the-sample
        # boundary as single-node (audit CRITICAL). In central S3 the ONLY binary stored
        # for an analysis is THIS task's submitted sample (key <job_id>/binary) — it is
        # NOT a content-addressed by-hash store like single-node's storage/binaries/.
        # So serve <job_id>/binary only when the requested hash IS this task's sample;
        # otherwise return not-found rather than streaming the WRONG file's bytes under
        # the requested-hash name (review: wrong-artifact). dropped/related-by-hash from
        # S3 is a documented follow-on.
        if not viewer_can_view_sample(request.user, sha256=dlfile):
            return render(request, "error.html", {"error": "File not found"})
        if _task_sample_sha256(request, task_id) != dlfile.lower():
            return render(request, "error.html", {"error": "File not found"})
        spec = ("binary", dlfile, OCTET)
    elif category == "dropped":
        spec = (f"files/{dlfile}", dlfile, OCTET)
    elif category.startswith("CAPE") and category not in zip_categories:
        spec = (f"CAPE/{dlfile}", dlfile, OCTET)
    elif category == "pcap":
        spec = ("dump.pcap", f"{dlfile}.pcap", PCAP)
    elif category == "decrypted_pcap":
        spec = ("dump_decrypted.pcap", f"{dlfile}.pcap", PCAP)
    elif category == "mixed_pcap":
        spec = ("dump_mixed.pcap", f"{dlfile}.pcap", PCAP)
    elif category == "debugger_log":
        spec = (f"debugger/{dlfile}.log", f"{dlfile}.log", "text/plain")
    elif category.startswith("procdump") and category not in zip_categories:
        spec = (f"procdump/{dlfile}", dlfile, OCTET)
    elif category in ("memdump", "memdumpstrings"):
        ext = ".dmp" if category == "memdump" else ".dmp.strings"
        spec = (f"memory/{dlfile}{ext}", f"{dlfile}{ext}", OCTET)
    elif category == "rtf":
        spec = (f"rtf_objects/{dlfile}", dlfile, OCTET)
    elif category == "usage":
        spec = ("aux/usage.svg", "usage.svg", "image/svg+xml")
    elif category == "suricata":
        spec = (f"logs/files/{dlfile}", dlfile, OCTET)
    elif category == "zip":  # suricata dropped files bundle (pre-existing in tree)
        spec = ("logs/files.zip", "files.zip", "application/zip")
    elif category == "tlskeys":
        spec = ("tlsdump/tlsdump.log", "tlsdump.log", "text/plain")
    elif category == "sysmon":
        spec = ("sysmon/sysmon.data", "sysmon.data", OCTET)
    elif category == "evtx":
        # fn is wrapped as f"{task_id}_{fn}" below, so don't prefix task_id here (else
        # the download name doubles to "<id>_<id>_evtx.zip").
        spec = ("evtx/evtx.zip", "evtx.zip", "application/zip")
    elif category == "mitmdump":
        spec = ("mitmdump/dump.har", "dump.har", "text/plain")
    else:
        return render(request, "error.html", {
            "error": f"'{category}' is not yet available in central mode (server-side bundle/generated artifact)"})

    relpath, fn, cd = spec
    scope = viewer_scope(request.user)
    try:
        return artifact_response(task_id, relpath, cd, f"{task_id}_{fn}", scope=scope)
    except Http404:
        return render(request, "error.html", {"error": f"Could not find {category} {dlfile}"})


def central_open_procdump(request, task_id, origname):
    """Acquire the proc memory dump as a LOCAL file for the slicing logic in
    procdump(): stream memory/<origname> (or its .zip) from S3 to a temp. Returns
    (dumpfile_path, tmp_file_path, tmpdir) matching procdump's existing cleanup
    variables (it unlinks tmp_file_path + delete_folder(tmpdir)). (None, None, None)
    if the dump is absent."""
    import tempfile
    import zipfile

    from django.conf import settings

    from analysis.central_scope import viewer_scope
    from lib.cuckoo.common.artifact_storage import materialize_artifact

    scope = viewer_scope(request.user)
    dumpfile, is_temp = materialize_artifact(task_id, f"memory/{origname}", scope=scope)
    if dumpfile:
        return dumpfile, (dumpfile if is_temp else None), None

    zpath, zt = materialize_artifact(task_id, f"memory/{origname}.zip", scope=scope)
    if not zpath:
        return None, None, None
    tmpdir = tempfile.mkdtemp(prefix="capeprocdump_", dir=settings.TEMP_PATH)
    try:
        with zipfile.ZipFile(zpath, "r") as f:
            extracted = f.extract(origname, path=tmpdir)
    except Exception:
        # bad/corrupt zip or origname not a member: don't leak tmpdir (and the temp zip)
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)
        if zt:
            try:
                os.unlink(zpath)
            except OSError:
                pass
        return None, None, None
    if zt:
        try:
            os.unlink(zpath)
        except OSError:
            pass
    return extracted, extracted, tmpdir


def central_vtupload(request, category, task_id, filename, dlfile):
    """Upload a stored artifact to VirusTotal (vtupload): stream it from S3 to a temp,
    POST, clean up."""
    import base64

    import requests

    from analysis.central_scope import viewer_scope, viewer_can_view_sample
    from lib.cuckoo.common.artifact_storage import materialize_artifact
    from analysis.views import enabledconf, integrations_cfg

    if not (enabledconf["vtupload"] and integrations_cfg.virustotal.apikey):
        return render(request, "error.html", {"error": "VirusTotal upload is not enabled"})

    if category in ("sample", "static"):
        if not viewer_can_view_sample(request.user, sha256=dlfile):
            return render(request, "error.html", {"error": "File not found"})
        relpath = "binary"
    elif category == "dropped":
        relpath = f"files/{filename}"
    elif category in ("CAPE", "procdump"):
        relpath = f"{category}/{filename}"
    else:
        return render(request, "error.html", {"error": "Category not defined"})

    scope = viewer_scope(request.user)
    path, is_temp = materialize_artifact(task_id, relpath, scope=scope)
    if not path:
        return render(request, "error.html", {"error": "File not found"})
    try:
        headers = {"x-apikey": integrations_cfg.virustotal.apikey}
        with open(path, "rb") as fh:
            response = requests.post(
                "https://www.virustotal.com/api/v3/files", files={"file": (filename, fh)}, headers=headers,
                timeout=120,
            )
        if response.ok:
            vid = response.json().get("data", {}).get("id")
            if vid:
                hashbytes, _ = base64.b64decode(vid).split(b":")
                return render(
                    request, "success_vtup.html",
                    {"permalink": "https://www.virustotal.com/gui/file/{id}".format(id=hashbytes.decode())},
                )
        return render(request, "error.html", {"error": "Response code: {} - {}".format(response.status_code, response.reason)})
    except Exception as e:
        # network error / non-JSON VT response / malformed id: single-node vtupload wraps
        # the whole flow in try/except; mirror that so it renders an error, not a 500.
        return render(request, "error.html", {"error": "VirusTotal upload failed: {}".format(e)})
    finally:
        if is_temp:
            try:
                os.unlink(path)
            except OSError:
                pass


def central_pcapstream(request):
    """Per-connection pcap regeneration isn't materialized in S3 (the full pcap is)."""
    return render(request, "error.html", {
        "error": "Per-connection pcap stream is not yet available in central mode — download the full pcap instead"})


def central_on_demand(request):
    """On-demand re-processing is a worker/broker concern in central mode, not a UI action."""
    return render(request, "error.html", {
        "error": "On-demand detail generation is not available in central mode (re-processing is handled by workers)"})
