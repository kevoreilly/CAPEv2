# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.http import require_safe

sys.path.append(settings.CUCKOO_PATH)

import lib.cuckoo.common.compare as compare
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.database import Database
from web.tenancy_optional import can_view_task, multitenancy_config, viewer_for

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
    from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index, get_query_by_info_id

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
        left = mongo_find_one("analysis", {"info.id": int(left_id)}, {"target": 1, "info": 1})
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

    _and = [{"target.file.md5": left["target"]["file"]["md5"]}, {"info.id": {"$ne": int(left_id)}}]
    _scope = entitled_scope_filter(request.user)
    if _scope:
        _and.append(_scope)
    if enabledconf["mongodb"]:
        _raw = mongo_find("analysis", {"$and": _and}, {"target": 1, "info": 1})
        if not multitenancy_config().enabled:
            # MT off: byte-for-byte upstream — assign the raw mongo cursor unchanged
            # (upstream did `records = mongo_find(...)`). Do NOT list()/intersect it:
            # compare/left.html + hash.html gate on `{% if records|length %}`, which is
            # 0 for a len-less PyMongo cursor, so listing it would render the sibling
            # table where upstream (cursor) hides it. Reproducing upstream — quirk and
            # all — is the invariant; an upstream compare-table fix is a separate PR.
            records = _raw
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
        left = mongo_find_one("analysis", {"info.id": int(left_id)}, {"target": 1, "info": 1})
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

    _and = [{"target.file.md5": left["target"]["file"]["md5"]}, {"info.id": {"$ne": int(left_id)}}]
    _scope = entitled_scope_filter(request.user)
    if _scope:
        _and.append(_scope)
    if enabledconf["mongodb"]:
        _raw = mongo_find("analysis", {"$and": _and}, {"target": 1, "info": 1})
        if not multitenancy_config().enabled:
            # MT off: byte-for-byte upstream — assign the raw mongo cursor unchanged
            # (upstream did `records = mongo_find(...)`). Do NOT list()/intersect it:
            # compare/left.html + hash.html gate on `{% if records|length %}`, which is
            # 0 for a len-less PyMongo cursor, so listing it would render the sibling
            # table where upstream (cursor) hides it. Reproducing upstream — quirk and
            # all — is the invariant; an upstream compare-table fix is a separate PR.
            records = _raw
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
                    "must": [{"match": {"target.file.md5": right_hash}}],
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
        left = mongo_find_one("analysis", {"info.id": int(left_id)}, {"target": 1, "info": 1, "summary": 1})
        right = mongo_find_one("analysis", {"info.id": int(right_id)}, {"target": 1, "info": 1, "summary": 1})
        # Execute comparison.
        counts = compare.helper_percentages_mongo(left_id, right_id)
        summary_compare = compare.helper_summary_mongo(left_id, right_id)
    elif es_as_db:
        left = es.search(index=get_analysis_index(), query=get_query_by_info_id(left_id), _source=["target", "info"])["hits"][
            "hits"
        ][-1]["_source"]
        right = es.search(index=get_analysis_index(), query=get_query_by_info_id(right_id), _source=["target", "info"])["hits"][
            "hits"
        ][-1]["_source"]
        counts = compare.helper_percentages_elastic(es, left_id, right_id)
        summary_compare = compare.helper_summary_elastic(es, left_id, right_id)

    return render(
        request,
        "compare/both.html",
        {
            "left": left,
            "right": right,
            "left_counts": counts[left_id],
            "right_counts": counts[right_id],
            "summary": summary_compare,
        },
    )
