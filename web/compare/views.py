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
