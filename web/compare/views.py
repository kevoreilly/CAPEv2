# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import sys

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_safe
from django.contrib.auth.decorators import login_required

sys.path.append(settings.CUCKOO_PATH)

import lib.cuckoo.common.compare as compare
from lib.cuckoo.common.config import Config

enabledconf = dict()
confdata = Config("reporting").get_config()
for item in confdata:
    if confdata[item]["enabled"] == "yes":
        enabledconf[item] = True
    else:
        enabledconf[item] = False

if enabledconf["mongodb"]:
    import pymongo

    # results_db = pymongo.MongoClient(settings.MONGO_HOST, settings.MONGO_PORT)[settings.MONGO_DB]
    results_db = pymongo.MongoClient(
        settings.MONGO_HOST, port=settings.MONGO_PORT, username=settings.MONGO_USER, password=settings.MONGO_PASS, authSource=settings.MONGO_DB
    )[settings.MONGO_DB]

es_as_db = False
if enabledconf["elasticsearchdb"]:
    from elasticsearch import Elasticsearch

    es_as_db = True
    essearch = Config("reporting").elasticsearchdb.searchonly
    if essearch:
        es_as_db = False
    baseidx = Config("reporting").elasticsearchdb.index
    fullidx = baseidx + "-*"
    es = Elasticsearch(hosts=[{"host": settings.ELASTIC_HOST, "port": settings.ELASTIC_PORT,}], timeout=60)

# Conditional decorator for web authentication
class conditional_login_required(object):
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
        left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    if es_as_db:
        hits = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % left_id)["hits"]["hits"]
        if hits:
            left = hits[-1]["_source"]
        else:
            left = None
    if not left:
        return render(request, "error.html", {"error": "No analysis found with specified ID"})

    # Select all analyses with same file hash.
    if enabledconf["mongodb"]:
        records = results_db.analysis.find(
            {"$and": [{"target.file.md5": left["target"]["file"]["md5"]}, {"info.id": {"$ne": int(left_id)}}]}, {"target": 1, "info": 1}
        )
    if es_as_db:
        records = list()
        results = es.search(
            index=fullidx, doc_type="analysis", q='target.file.md5: "%s" NOT info.id: "%s"' % (left["target"]["file"]["md5"], left_id)
        )["hits"]["hits"]
        for item in results:
            records.append(item["_source"])

    return render(request, "compare/left.html", {"left": left, "records": records})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def hash(request, left_id, right_hash):
    if enabledconf["mongodb"]:
        left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1})
    if es_as_db:
        hits = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % left_id)["hits"]["hits"]
        if hits:
            left = hits[-1]["_source"]
        else:
            left = None
    if not left:
        return render(request, "error.html", {"error": "No analysis found with specified ID"})

    # Select all analyses with same file hash.
    if enabledconf["mongodb"]:
        records = results_db.analysis.find(
            {"$and": [{"target.file.md5": left["target"]["file"]["md5"]}, {"info.id": {"$ne": int(left_id)}}]}, {"target": 1, "info": 1}
        )
    if es_as_db:
        records = list()
        results = es.search(index=fullidx, doc_type="analysis", q='target.file.md5: "%s" NOT info.id: "%s"' % (right_hash, left_id))["hits"][
            "hits"
        ]
        for item in results:
            records.append(item["_source"])

    # Select all analyses with specified file hash.
    return render(request, "compare/hash.html", {"left": left, "records": records, "hash": right_hash})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def both(request, left_id, right_id):
    if enabledconf["mongodb"]:
        left = results_db.analysis.find_one({"info.id": int(left_id)}, {"target": 1, "info": 1, "summary": 1})
        right = results_db.analysis.find_one({"info.id": int(right_id)}, {"target": 1, "info": 1, "summary": 1})
        # Execute comparison.
        counts = compare.helper_percentages_mongo(results_db, left_id, right_id)
        summary_compare = compare.helper_summary_mongo(results_db, left_id, right_id)
    if es_as_db:
        left = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % left_id)["hits"]["hits"][-1]["_source"]
        right = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % right_id)["hits"]["hits"][-1]["_source"]
        counts = compare.helper_percentages_elastic(es, left_id, right_id, fullidx)
        summary_compare = compare.summary_similarities(left, right)

    return render(
        request,
        "compare/both.html",
        {"left": left, "right": right, "left_counts": counts[left_id], "right_counts": counts[right_id], "summary": summary_compare},
    )
