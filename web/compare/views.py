# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.http import require_safe
from django.http import JsonResponse

sys.path.append(settings.CUCKOO_PATH)

import lib.cuckoo.common.compare as compare
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from web.tenancy_optional import can_view_task, multitenancy_config, viewer_for

# Shared central-mode cross-store info.id collision seam: the compare SEED reads authorize the SQL task
# (can_view_task) but must not resolve the Mongo doc by a bare info.id in central mode, where a colliding
# worker-local doc for another tenant can shadow the seed (audit MEDIUM). Same seam report() uses; the
# md5-pivot below is already tenant-scoped via entitled_scope_filter + can_view_task post-filter.
from analysis.central_views import scoped_analysis_query

enabledconf = {}
confdata = Config("reporting").get_config()
for item in confdata:
    if confdata[item]["enabled"] == "yes":
        enabledconf[item] = True
    else:
        enabledconf[item] = False

if enabledconf["mongodb"]:
    from dev_utils.mongodb import mongo_find, mongo_find_one

es_as_db = False
if enabledconf["elasticsearchdb"]:
    from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index, get_query_by_info_id, get_calls_index

    es_as_db = True
    essearch = confdata["elasticsearchdb"]["searchonly"]
    if essearch:
        es_as_db = False

    es = elastic_handler


# Conditional decorator for web authentication
class conditional_login_required:
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def left(request, left_id):
    # tenant isolation: caller must be able to read the seed analysis (hidden == missing).
    # No-op when multitenancy is disabled: fall through to the mongo/ES existence check
    # below so a mongo-only analysis (no SQL row) still renders exactly as upstream.
    if multitenancy_config().enabled:
        _seed = Database().view_task(int(left_id))
        if _seed is None or not can_view_task(request.user, _seed):
            return render(request, "error.html", {"error": "No analysis found with specified ID"})

    if enabledconf["mongodb"]:
        left = mongo_find_one("analysis", scoped_analysis_query(request, left_id), {"target": 1, "info": 1})
    if es_as_db:
        hits = es.search(index=get_analysis_index(), query=get_query_by_info_id(left_id))["hits"]["hits"]
        if hits:
            left = hits[-1]["_source"]
        else:
            left = None
    if not left:
        return render(request, "error.html", {"error": "No analysis found with specified ID"})

    # Select all analyses with same file hash — scoped to the viewer's entitled
    # tenants so the md5 pivot can't enumerate other tenants' analyses.
    from dashboard.views import entitled_scope_filter

    # Resolve sibling task IDs via the highly indexed 'files' collection first (avoiding full analysis collection scans)
    sha256 = left.get("target", {}).get("file", {}).get("sha256", "")
    md5 = left.get("target", {}).get("file", {}).get("md5", "")
    task_ids = []
    if enabledconf["mongodb"]:
        _file_match = {"sha256": sha256} if sha256 else {"md5": md5}
        file_doc = mongo_find_one("files", _file_match, {"_task_ids": 1, "_id": 0})
        if file_doc:
            task_ids = file_doc.get("_task_ids", [])

    _and = [{"info.id": {"$in": task_ids}}, {"info.id": {"$ne": int(left_id)}}]
    _scope = entitled_scope_filter(request.user)
    if _scope:
        _and.append(_scope)
    if enabledconf["mongodb"]:
        _raw = mongo_find("analysis", {"$and": _and}, {"target": 1, "info": 1})
        if not multitenancy_config().enabled:
            # If it's a real PyMongo cursor, materialize it to a list so that template length checks work.
            # If it's already a list or other mock (e.g. in pytest), preserve its identity.
            try:
                from pymongo.cursor import Cursor
                if isinstance(_raw, Cursor):
                    records = list(_raw)
                else:
                    records = _raw
            except ImportError:
                records = list(_raw)
        else:
            # Materialize the cursor: it is iterated TWICE below (collect ids, then
            # build records), and a PyMongo cursor is single-pass — leaving it lazy
            # exhausts it in the first loop and yields an always-empty `records`.
            _raw = list(_raw)
            # Defense-in-depth: post-filter each md5-pivot hit through can_view_task
            # (SQL-authoritative), symmetric with the ES branch below, so a mongo stamp
            # gap can't leak another tenant's analysis even if the query-layer scope
            # regresses. No-op for break-glass / shared / multitenancy disabled.
            _db = Database()
            _rids = []
            for _rec in _raw:
                _rid = (_rec.get("info") or {}).get("id")
                if _rid is not None:
                    try:
                        _rids.append(int(_rid))
                    except (ValueError, TypeError):
                        pass
            # Batch the visibility check in ONE SQL query (avoid an N+1 view_task per
            # md5-pivot record); list_tasks(visible_to=) returns only readable tasks.
            _visible = {t.id for t in _db.list_tasks(task_ids=_rids, visible_to=viewer_for(request.user))} if _rids else set()
            records = []
            for _rec in _raw:
                _rid = (_rec.get("info") or {}).get("id")
                try:
                    if _rid is not None and int(_rid) in _visible:
                        records.append(_rec)
                except (ValueError, TypeError):
                    continue
    if es_as_db:
        records = []
        q = {
            "query": {
                "bool": {
                    "must": [{"match": {"target.file.md5": left["target"]["file"]["md5"]}}],
                    "must_not": [{"match": {"info.id": left_id}}],
                }
            }
        }
        results = es.search(index=get_analysis_index(), body=q)["hits"]["hits"]
        if not multitenancy_config().enabled:
            # MT off: upstream behavior — append every hit, no visibility filter.
            for item in results:
                records.append(item["_source"])
        else:
            # tenant isolation: the mongo path filters via entitled_scope_filter; the
            # ES backend can't take that $match, so post-filter each hit through
            # can_view_task (no-op for break-glass / shared / multitenancy disabled).
            # Batch-resolve the visible set in ONE query (list_tasks(visible_to=))
            # instead of a view_task() per hit — same contract the mongo md5-pivot
            # path above uses.
            _db = Database()
            _tids = set()
            for item in results:
                _tid = (item["_source"].get("info") or {}).get("id")
                if _tid is not None:
                    try:
                        _tids.add(int(_tid))
                    except (ValueError, TypeError):
                        pass  # malformed id in a corrupt ES doc — skip, don't 500
            _visible = {t.id for t in _db.list_tasks(task_ids=list(_tids), visible_to=viewer_for(request.user))} if _tids else set()
            for item in results:
                _source = item["_source"]
                _tid = (_source.get("info") or {}).get("id")
                try:
                    if _tid is not None and int(_tid) in _visible:
                        records.append(_source)
                except (ValueError, TypeError):
                    continue

    data = {"title": "Compare", "left": left, "records": records}
    return render(request, "compare/left.html", data)


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def hash(request, left_id, right_hash):
    # tenant isolation: caller must be able to read the seed analysis (hidden == missing).
    # No-op when multitenancy is disabled: fall through to the mongo/ES existence check
    # below so a mongo-only analysis (no SQL row) still renders exactly as upstream.
    if multitenancy_config().enabled:
        _seed = Database().view_task(int(left_id))
        if _seed is None or not can_view_task(request.user, _seed):
            return render(request, "error.html", {"error": "No analysis found with specified ID"})

    if enabledconf["mongodb"]:
        left = mongo_find_one("analysis", scoped_analysis_query(request, left_id), {"target": 1, "info": 1})
    if es_as_db:
        hits = es.search(index=get_analysis_index(), query=get_query_by_info_id(left_id))["hits"]["hits"]
        if hits:
            left = hits[-1]["_source"]
        else:
            left = None
    if not left:
        return render(request, "error.html", {"error": "No analysis found with specified ID"})

    # Select all analyses with same file hash — scoped to the viewer's entitled
    # tenants so the md5 pivot can't enumerate other tenants' analyses.
    from dashboard.views import entitled_scope_filter

    hash_field = "target.file.md5"
    if len(right_hash) == 64:
        hash_field = "target.file.sha256"
    elif len(right_hash) == 40:
        hash_field = "target.file.sha1"

    # Resolve sibling task IDs via the highly indexed 'files' collection first (avoiding full analysis collection scans)
    task_ids = []
    if enabledconf["mongodb"]:
        _file_match = {hash_field.replace("target.file.", ""): right_hash}
        file_doc = mongo_find_one("files", _file_match, {"_task_ids": 1, "_id": 0})
        if file_doc:
            task_ids = file_doc.get("_task_ids", [])

    _and = [{"info.id": {"$in": task_ids}}, {"info.id": {"$ne": int(left_id)}}]
    _scope = entitled_scope_filter(request.user)
    if _scope:
        _and.append(_scope)
    if enabledconf["mongodb"]:
        _raw = mongo_find("analysis", {"$and": _and}, {"target": 1, "info": 1})
        if not multitenancy_config().enabled:
            # If it's a real PyMongo cursor, materialize it to a list so that template length checks work.
            # If it's already a list or other mock (e.g. in pytest), preserve its identity.
            try:
                from pymongo.cursor import Cursor
                if isinstance(_raw, Cursor):
                    records = list(_raw)
                else:
                    records = _raw
            except ImportError:
                records = list(_raw)
        else:
            # Materialize the cursor: it is iterated TWICE below (collect ids, then
            # build records), and a PyMongo cursor is single-pass — leaving it lazy
            # exhausts it in the first loop and yields an always-empty `records`.
            _raw = list(_raw)
            # Defense-in-depth: post-filter each md5-pivot hit through can_view_task
            # (SQL-authoritative), symmetric with the ES branch below, so a mongo stamp
            # gap can't leak another tenant's analysis even if the query-layer scope
            # regresses. No-op for break-glass / shared / multitenancy disabled.
            _db = Database()
            _rids = []
            for _rec in _raw:
                _rid = (_rec.get("info") or {}).get("id")
                if _rid is not None:
                    try:
                        _rids.append(int(_rid))
                    except (ValueError, TypeError):
                        pass
            # Batch the visibility check in ONE SQL query (avoid an N+1 view_task per
            # md5-pivot record); list_tasks(visible_to=) returns only readable tasks.
            _visible = {t.id for t in _db.list_tasks(task_ids=_rids, visible_to=viewer_for(request.user))} if _rids else set()
            records = []
            for _rec in _raw:
                _rid = (_rec.get("info") or {}).get("id")
                try:
                    if _rid is not None and int(_rid) in _visible:
                        records.append(_rec)
                except (ValueError, TypeError):
                    continue
    if es_as_db:
        records = []
        hash_field = "target.file.md5"
        if len(right_hash) == 64:
            hash_field = "target.file.sha256"
        elif len(right_hash) == 40:
            hash_field = "target.file.sha1"

        q = {
            "query": {
                "bool": {
                    "must": [{"match": {hash_field: right_hash}}],
                    "must_not": [{"match": {"info.id": left_id}}],
                }
            }
        }
        results = es.search(index=get_analysis_index(), body=q)["hits"]["hits"]
        if not multitenancy_config().enabled:
            # MT off: upstream behavior — append every hit, no visibility filter.
            for item in results:
                records.append(item["_source"])
        else:
            # tenant isolation: the mongo path filters via entitled_scope_filter; the
            # ES backend can't take that $match, so post-filter each hit through
            # can_view_task (no-op for break-glass / shared / multitenancy disabled).
            # Batch-resolve the visible set in ONE query (list_tasks(visible_to=))
            # instead of a view_task() per hit — same contract the mongo md5-pivot
            # path above uses.
            _db = Database()
            _tids = set()
            for item in results:
                _tid = (item["_source"].get("info") or {}).get("id")
                if _tid is not None:
                    try:
                        _tids.add(int(_tid))
                    except (ValueError, TypeError):
                        pass  # malformed id in a corrupt ES doc — skip, don't 500
            _visible = {t.id for t in _db.list_tasks(task_ids=list(_tids), visible_to=viewer_for(request.user))} if _tids else set()
            for item in results:
                _source = item["_source"]
                _tid = (_source.get("info") or {}).get("id")
                try:
                    if _tid is not None and int(_tid) in _visible:
                        records.append(_source)
                except (ValueError, TypeError):
                    continue

    # Select all analyses with specified file hash.
    return render(request, "compare/hash.html", {"left": left, "records": records, "hash": right_hash})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def both(request, left_id, right_id):
    # tenant isolation: caller must be able to read BOTH analyses (hidden == missing).
    # No-op when multitenancy is disabled: fall through to the mongo/ES lookups below
    # so mongo-only analyses (no SQL row) still render exactly as upstream.
    if multitenancy_config().enabled:
        _db = Database()
        for _tid in (left_id, right_id):
            _seed = _db.view_task(int(_tid))
            if _seed is None or not can_view_task(request.user, _seed):
                return render(request, "error.html", {"error": "No analysis found with specified ID"})

    if enabledconf["mongodb"]:
        _lf = scoped_analysis_query(request, left_id)
        _rf = scoped_analysis_query(request, right_id)
        left = mongo_find_one("analysis", _lf, {"target": 1, "info": 1, "summary": 1})
        right = mongo_find_one("analysis", _rf, {"target": 1, "info": 1, "summary": 1})
        # Execute comparison. Thread the SAME central-scoped filters into the percentage/summary helpers
        # (lib/cuckoo/common/compare.py) so their bare {info.id} reads can't surface a colliding tenant's
        # doc in central mode (audit MEDIUM); None-safe -> bare {info.id} single-node.
        counts = compare.helper_percentages_mongo(left_id, right_id, filter1=_lf, filter2=_rf)
        summary_compare = compare.helper_summary_mongo(left_id, right_id, filter1=_lf, filter2=_rf)
        summary_diff = compare.helper_different_summary_mongo(left_id, right_id, filter1=_lf, filter2=_rf)
    elif es_as_db:
        left_res = es.search(index=get_analysis_index(), query=get_query_by_info_id(left_id), _source=["target", "info"])["hits"]["hits"]
        right_res = es.search(index=get_analysis_index(), query=get_query_by_info_id(right_id), _source=["target", "info"])["hits"]["hits"]
        left = left_res[-1]["_source"] if left_res else None
        right = right_res[-1]["_source"] if right_res else None
        counts = compare.helper_percentages_elastic(es, left_id, right_id)
        summary_compare = compare.helper_summary_elastic(es, left_id, right_id)
        summary_diff = compare.helper_different_summary_elastic(es, left_id, right_id)

    categories = ["registry", "filesystem", "system", "network", "process", "services", "synchronization", "windows"]

    return render(
        request,
        "compare/both.html",
        {
            "left": left,
            "right": right,
            "left_counts": counts.get(left_id, {}),
            "right_counts": counts.get(right_id, {}),
            "summary": summary_compare,
            "summary_diff": summary_diff,
            "categories": categories,
        },
    )


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def diff(request, left_id, right_id):
    # tenant isolation: caller must be able to read both analyses (hidden == missing).
    # No-op when multitenancy is disabled: fall through to the mongo/ES existence check
    # below so a mongo-only analysis (no SQL row) still renders exactly as upstream.
    if multitenancy_config().enabled:
        _db = Database()
        _left_task = _db.view_task(int(left_id))
        _right_task = _db.view_task(int(right_id))
        if _left_task is None or not can_view_task(request.user, _left_task) or _right_task is None or not can_view_task(request.user, _right_task):
            return render(request, "error.html", {"error": "No analysis found with specified ID"})

    left, right = None, None
    if enabledconf["mongodb"]:
        left = mongo_find_one("analysis", scoped_analysis_query(request, left_id), {"target": 1, "info": 1, "behavior.processes": 1})
        right = mongo_find_one("analysis", scoped_analysis_query(request, right_id), {"target": 1, "info": 1, "behavior.processes": 1})
    elif es_as_db:
        left_results = es.search(index=get_analysis_index(), query=get_query_by_info_id(left_id), _source=["target", "info", "behavior.processes"])["hits"]["hits"]
        right_results = es.search(index=get_analysis_index(), query=get_query_by_info_id(right_id), _source=["target", "info", "behavior.processes"])["hits"]["hits"]
        left = left_results[-1]["_source"] if left_results else None
        right = right_results[-1]["_source"] if right_results else None

    if not left or not right:
        return render(request, "error.html", {"error": "Analysis not found"})

    return render(request, "compare/diff.html", {
        "left": left,
        "right": right,
        "left_id": left_id,
        "right_id": right_id
    })


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def diff_data(request, left_id, right_id):
    # tenant isolation: caller must be able to read both analyses (hidden == missing).
    # No-op when multitenancy is disabled.
    if multitenancy_config().enabled:
        _db = Database()
        _left_task = _db.view_task(int(left_id))
        _right_task = _db.view_task(int(right_id))
        if _left_task is None or not can_view_task(request.user, _left_task) or _right_task is None or not can_view_task(request.user, _right_task):
            return JsonResponse({"error": True, "error_value": "No analysis found with specified ID"}, status=403)

    left_pid = request.GET.get("left_pid")
    right_pid = request.GET.get("right_pid")

    if not left_pid or not right_pid or not left_pid.isdigit() or not right_pid.isdigit():
        return JsonResponse({"error": True, "error_value": "Invalid or missing PIDs"}, status=400)

    def fetch_calls(analysis_id, pid):
        record = None
        if enabledconf["mongodb"]:
            _q = scoped_analysis_query(request, analysis_id)
            if _q:
                _q["behavior.processes.process_id"] = int(pid)
            record = mongo_find_one("analysis", _q, {"behavior.processes.calls": 1})
        elif es_as_db:
            es_results = es.search(index=get_analysis_index(), body={"query": {"bool": {"must": [{"match": {"behavior.processes.process_id": pid}}, {"match": {"info.id": analysis_id}}]}}}, _source=["behavior.processes"])["hits"]["hits"]
            record = es_results[0]["_source"] if es_results else None

        if not record or "behavior" not in record or "processes" not in record["behavior"]:
            return []
        process = next((p for p in record["behavior"]["processes"] if p["process_id"] == int(pid)), None)
        if not process:
            return []

        all_calls = []
        for coid in process.get("calls", []):
            chunk = None
            if enabledconf["mongodb"]:
                chunk = mongo_find_one("calls", {"_id": coid})
            elif es_as_db:
                chunk_results = es.search(index=get_calls_index(), body={"query": {"match": {"_id": coid}}})["hits"]["hits"]
                chunk = chunk_results[0]["_source"] if chunk_results else None

            if chunk and "calls" in chunk:
                all_calls.extend(chunk["calls"])
        return all_calls

    left_calls = fetch_calls(left_id, left_pid)
    right_calls = fetch_calls(right_id, right_pid)

    # Basic Sequence Alignment Heuristic
    results = []
    i, j = 0, 0
    limit = 2000 # Limit for safety in PoC

    # Slice once outside loop to avoid O(N^2) copying penalty in condition
    left_calls = left_calls[:limit]
    right_calls = right_calls[:limit]

    while i < len(left_calls) or j < len(right_calls):
        l = left_calls[i] if i < len(left_calls) else None
        r = right_calls[j] if j < len(right_calls) else None

        if l and r and l["api"] == r["api"]:
            # Same API, check for argument differences
            type = "equal"
            if l.get("arguments") != r.get("arguments"):
                type = "changed"
            results.append({"type": type, "left": l, "right": r})
            i += 1
            j += 1
        elif l and not r:
            results.append({"type": "removed", "left": l, "right": None})
            i += 1
        elif r and not l:
            results.append({"type": "added", "left": None, "right": r})
            j += 1
        else:
            # DIVERGENCE: Try to resync (Lookahead 5 calls)
            found = False
            for look in range(1, 6):
                if i + look < len(left_calls) and r and left_calls[i+look]["api"] == r["api"]:
                    # Left has extra calls
                    for k in range(look):
                        results.append({"type": "removed", "left": left_calls[i+k], "right": None})
                    i += look
                    found = True
                    break
                if j + look < len(right_calls) and l and right_calls[j+look]["api"] == l["api"]:
                    # Right has extra calls
                    for k in range(look):
                        results.append({"type": "added", "left": None, "right": right_calls[j+k]})
                    j += look
                    found = True
                    break

            if not found:
                # Still no match, assume one removal and one addition
                results.append({"type": "changed", "left": l, "right": r})
                i += 1
                j += 1

    return JsonResponse({"results": results})


