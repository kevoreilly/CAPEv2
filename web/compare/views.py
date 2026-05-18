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

    # Select all analyses with same file hash.
    if enabledconf["mongodb"]:
        records = mongo_find(
            "analysis",
            {"$and": [{"target.file.md5": left["target"]["file"]["md5"]}, {"info.id": {"$ne": int(left_id)}}]},
            {"target": 1, "info": 1},
        )
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
        for item in results:
            records.append(item["_source"])

    data = {"title": "Compare", "left": left, "records": records}
    return render(request, "compare/left.html", data)


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def hash(request, left_id, right_hash):
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

    # Select all analyses with same file hash.
    if enabledconf["mongodb"]:
        records = mongo_find(
            "analysis",
            {"$and": [{"target.file.md5": left["target"]["file"]["md5"]}, {"info.id": {"$ne": int(left_id)}}]},
            {"target": 1, "info": 1},
        )
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
        for item in results:
            records.append(item["_source"])

    # Select all analyses with specified file hash.
    return render(request, "compare/hash.html", {"left": left, "records": records, "hash": right_hash})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def both(request, left_id, right_id):
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


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def diff(request, left_id, right_id):
    if enabledconf["mongodb"]:
        left = mongo_find_one("analysis", {"info.id": int(left_id)}, {"target": 1, "info": 1, "behavior.processes": 1})
        right = mongo_find_one("analysis", {"info.id": int(right_id)}, {"target": 1, "info": 1, "behavior.processes": 1})
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
    left_pid = request.GET.get("left_pid")
    right_pid = request.GET.get("right_pid")

    if not left_pid or not right_pid:
        return JsonResponse({"error": True, "error_value": "Missing PIDs"}, status=400)

    def fetch_calls(analysis_id, pid):
        if enabledconf["mongodb"]:
            record = mongo_find_one("analysis", {"info.id": int(analysis_id), "behavior.processes.process_id": int(pid)}, {"behavior.processes.calls": 1})
        elif es_as_db:
            es_results = es.search(index=get_analysis_index(), body={"query": {"bool": {"must": [{"match": {"behavior.processes.process_id": pid}}, {"match": {"info.id": analysis_id}}]}}}, _source=["behavior.processes"])["hits"]["hits"]
            record = es_results[0]["_source"] if es_results else None

        if not record or "behavior" not in record or "processes" not in record: return []
        process = next((p for p in record["behavior"]["processes"] if p["process_id"] == int(pid)), None)
        if not process: return []

        all_calls = []
        for coid in process["calls"]:
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
    # To keep it fast for PoC, we'll use a simple approach:
    # 1. Match identical API names
    # 2. If mismatch, lookahead to find next match
    results = []
    i, j = 0, 0
    limit = 2000 # Limit for safety in PoC

    while i < len(left_calls[:limit]) or j < len(right_calls[:limit]):
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


