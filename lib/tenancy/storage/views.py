"""Object-storage-backed artifact serving views (`s3`, `gcs`, `azure`, `local`).

Invoked by `TenancyMiddleware.process_view` (`dispatch_object_storage_view`) when
`[object_storage] enabled = yes` (or `[central_mode] enabled = yes`), after task/sample
authorization has already succeeded.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional, Sequence

from django.shortcuts import render

log = logging.getLogger(__name__)


def central_job_id_for_task(task_id: Any) -> Optional[str]:
    """Resolve the broker `job_id` for a task from its SQL `custom` field."""
    try:
        tid = int(task_id)
    except (TypeError, ValueError):
        return None
    try:
        from analysis.views import db
        from lib.tenancy.storage.artifact_storage import job_id_from_custom

        t = db.view_task(tid)
        return job_id_from_custom(getattr(t, "custom", None) if t else None)
    except Exception:
        log.exception("central_job_id_for_task: DB lookup failed for task %s; falling back to scoped resolution", tid)
        return None


def central_analysis_query(task_id: Any, scope: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    """Mongo filter to fetch a task's analysis doc when object storage is enabled."""
    from lib.tenancy.storage.config import object_storage_bridge_required

    jid = central_job_id_for_task(task_id)
    if jid:
        q: dict[str, Any] = {"info.job_id": jid}
        if scope:
            try:
                if object_storage_bridge_required():
                    _own_unstamped = {
                        "$and": [{"info.job_id": jid}, {"info.tenant_id": None}, {"info.id": int(task_id)}]
                    }
                else:
                    _own_unstamped = {"$and": [{"info.tenant_id": None}, {"info.id": int(task_id)}]}
                q = {"$and": [q, {"$or": [scope, _own_unstamped]}]}
            except (TypeError, ValueError):
                q = {"$and": [q, scope]}
        return q

    if scope is not None and object_storage_bridge_required():
        try:
            tid = int(task_id)
            return {"$and": [{"info.id": tid}, {"info.job_id": f"ui-{tid}"}, scope]}
        except (TypeError, ValueError):
            return {"info.job_id": {"$in": []}}

    q = {"info.id": int(task_id)}
    if scope:
        q = {"$and": [q, scope]}
    return q


def scoped_analysis_query(
    request: Any,
    task_id: Any,
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Object-storage-scoped Mongo filter for a per-task read of the shared `'analysis'` collection."""
    from lib.tenancy.storage.config import object_storage_config

    if object_storage_config().enabled:
        from lib.tenancy.storage.scope import viewer_scope

        q = central_analysis_query(task_id, scope=viewer_scope(request.user))
    else:
        q = {"info.id": int(task_id)}
    return {"$and": [q, extra]} if extra else q


_TENANT_UNSET = object()


def central_delete_analysis(request: Any, task_id: Any, tenant_id: Any = _TENANT_UNSET) -> None:
    """Delete a task's Mongo analysis + call chunks, tenant-scoped when object storage is enabled."""
    from lib.tenancy.storage.config import object_storage_config, object_storage_own_analysis_filter

    if not object_storage_config().enabled:
        from dev_utils.mongodb import mongo_delete_data

        mongo_delete_data(task_id)
        return

    from dev_utils.mongodb import mongo_delete_many, mongo_find_one

    try:
        int(task_id)
    except (TypeError, ValueError):
        return

    if tenant_id is _TENANT_UNSET:
        try:
            from lib.cuckoo.core.database import Database
            from lib.tenancy.acl import get_task_acl

            db = Database()
            with db.session.begin():
                row = get_task_acl(db.session, int(task_id))
                _mine = row.tenant_id if row is not None else None
        except Exception:
            log.exception("object_storage delete: tenant lookup failed for task %s; leaving Mongo unchanged", task_id)
            return
    else:
        _mine = tenant_id

    doc = mongo_find_one(
        "analysis",
        object_storage_own_analysis_filter(task_id, _mine),
        {"_id": 1, "behavior.processes.calls": 1},
    )
    if not doc:
        log.warning("object_storage delete: no own analysis doc matched for task %s", task_id)
        return
    call_ids = []
    for proc in (doc.get("behavior") or {}).get("processes", []) or []:
        call_ids.extend(proc.get("calls") or [])
    if call_ids:
        mongo_delete_many("calls", {"_id": {"$in": call_ids}})
    mongo_delete_many("analysis", {"_id": doc["_id"]})


def _task_sample_sha256(request: Any, task_id: Any) -> str:
    from dev_utils.mongodb import mongo_find_one
    from lib.tenancy.storage.scope import viewer_scope

    doc = mongo_find_one(
        "analysis",
        central_analysis_query(task_id, scope=viewer_scope(request.user)),
        {"target.file.sha256": 1, "_id": 0},
    )
    return str((((doc or {}).get("target") or {}).get("file") or {}).get("sha256") or "").lower()


def central_stage_one(request: Any, task_id: Any, s3_relpath: str, dest_abspath: str) -> None:
    import shutil

    from lib.tenancy.storage.artifact_storage import materialize_artifact
    from lib.tenancy.storage.scope import viewer_scope

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


def central_stage_local(request: Any, task_id: Any) -> None:
    from lib.tenancy.storage.artifact_storage import ensure_local_analysis
    from lib.tenancy.storage.scope import viewer_scope

    ensure_local_analysis(task_id, scope=viewer_scope(request.user))


def central_file_nl(request: Any, category: str, task_id: Any, dlfile: str) -> Any:
    from django.http import Http404
    from lib.tenancy.storage.artifact_storage import artifact_response
    from lib.tenancy.storage.scope import viewer_scope

    scope = viewer_scope(request.user)
    if category == "screenshot":
        cands = [
            (os.path.join("shots", dlfile + ext), dlfile + ext, cd)
            for ext, cd in ((".jpg", "image/jpeg"), (".png", "image/png"))
        ]
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


def central_filereport(request: Any, task_id: Any, fname: str) -> Any:
    from django.http import Http404
    from lib.tenancy.storage.artifact_storage import artifact_response
    from lib.tenancy.storage.scope import viewer_scope

    scope = viewer_scope(request.user)
    try:
        return artifact_response(task_id, f"reports/{fname}", "application/octet-stream", f"{task_id}_{fname}", scope=scope)
    except Http404:
        return render(request, "error.html", {"error": f"File not found: {fname}"})


def central_full_memory_dump(request: Any, analysis_number: Any, names: Sequence[str]) -> Any:
    from django.http import Http404
    from lib.tenancy.storage.artifact_storage import artifact_response
    from lib.tenancy.storage.scope import viewer_scope

    scope = viewer_scope(request.user)
    for name in names:
        try:
            return artifact_response(analysis_number, name, "application/octet-stream", name, scope=scope)
        except Http404:
            continue
    return render(request, "error.html", {"error": "File not found"})


def central_file(request: Any, category: str, task_id: Any, dlfile: str) -> Any:
    from analysis.views import zip_categories
    from django.http import Http404
    from lib.tenancy.storage.artifact_storage import artifact_response
    from lib.tenancy.storage.scope import viewer_can_view_sample, viewer_scope

    OCTET = "application/octet-stream"
    PCAP = "application/vnd.tcpdump.pcap"

    if category in ("sample", "static"):
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
    elif category == "zip":
        spec = ("logs/files.zip", "files.zip", "application/zip")
    elif category == "tlskeys":
        spec = ("tlsdump/tlsdump.log", "tlsdump.log", "text/plain")
    elif category == "sysmon":
        spec = ("sysmon/sysmon.data", "sysmon.data", OCTET)
    elif category == "evtx":
        spec = ("evtx/evtx.zip", "evtx.zip", "application/zip")
    elif category == "mitmdump":
        spec = ("mitmdump/dump.har", "dump.har", "text/plain")
    else:
        return render(
            request,
            "error.html",
            {"error": f"'{category}' is not yet available in object storage mode (server-side bundle/generated artifact)"},
        )

    relpath, fn, cd = spec
    scope = viewer_scope(request.user)
    try:
        return artifact_response(task_id, relpath, cd, f"{task_id}_{fn}", scope=scope)
    except Http404:
        return render(request, "error.html", {"error": f"Could not find {category} {dlfile}"})


def central_open_procdump(
    request: Any,
    task_id: Any,
    origname: str,
) -> tuple[Optional[str], Optional[str], Optional[str]]:
    import tempfile
    import zipfile

    from django.conf import settings
    from lib.tenancy.storage.artifact_storage import materialize_artifact
    from lib.tenancy.storage.scope import viewer_scope

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


def central_vtupload(request: Any, category: str, task_id: Any, filename: str, dlfile: str) -> Any:
    import base64

    import requests
    from analysis.views import enabledconf, integrations_cfg
    from lib.tenancy.storage.artifact_storage import materialize_artifact
    from lib.tenancy.storage.scope import viewer_can_view_sample, viewer_scope

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
                "https://www.virustotal.com/api/v3/files",
                files={"file": (filename, fh)},
                headers=headers,
                timeout=120,
            )
        if response.ok:
            vid = response.json().get("data", {}).get("id")
            if vid:
                hashbytes, _ = base64.b64decode(vid).split(b":")
                return render(
                    request,
                    "success_vtup.html",
                    {"permalink": f"https://www.virustotal.com/gui/file/{hashbytes.decode()}"},
                )
        return render(request, "error.html", {"error": f"Response code: {response.status_code} - {response.reason}"})
    except Exception as e:
        return render(request, "error.html", {"error": f"VirusTotal upload failed: {e}"})
    finally:
        if is_temp:
            try:
                os.unlink(path)
            except OSError:
                pass


def central_pcapstream(request: Any) -> Any:
    return render(
        request,
        "error.html",
        {"error": "Per-connection pcap stream is not yet available in object storage mode — download the full pcap instead"},
    )


def central_on_demand(request: Any) -> Any:
    return render(
        request,
        "error.html",
        {"error": "On-demand detail generation is not available in object storage mode (re-processing is handled by workers)"},
    )
