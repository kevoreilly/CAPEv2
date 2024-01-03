# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
from typing import Dict

from lib.cuckoo.common.config import Config

repconf = Config("reporting")

if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_find_one

if repconf.elasticsearchdb.enabled:
    from dev_utils.elasticsearchdb import get_analysis_index, get_calls_index, get_query_by_info_id


def behavior_categories_percent(calls: Dict[str, str]) -> Dict[str, int]:
    catcounts = {}

    for call in calls:
        category = call.get("category", "none")
        catcounts[category] = catcounts.get(category, 0) + 1

    return catcounts


def combine_behavior_percentages(stats: dict) -> dict:
    # get all categories present
    cats = set()
    for v in stats.values():
        for v2 in v.values():
            cats |= set(v2.keys())

    sums = {}
    for tid in stats:
        sums[tid] = {}
        for cat in cats:
            sums[tid][cat] = sum(j.get(cat, 0) for j in stats[tid].values())
    totals = {k: sum(v.values()) for k, v in sums.items()}

    percentages = {}
    for tid in stats:
        percentages[tid] = {}
        for cat in cats:
            with contextlib.suppress(ZeroDivisionError):
                percentages[tid][cat] = round(sums[tid][cat] * 1.0 / totals[tid] * 100, 2)
    return percentages


def helper_percentages_mongo(tid1, tid2, ignore_categories: set = None) -> dict:
    if ignore_categories is None:
        ignore_categories = {"misc"}
    counts = {}

    for tid in (tid1, tid2):
        counts[tid] = {}

        pids_calls = mongo_find_one(
            "analysis", {"info.id": int(tid)}, {"behavior.processes.process_id": 1, "behavior.processes.calls": 1}
        )

        if not pids_calls:
            continue

        for pdoc in pids_calls["behavior"]["processes"]:
            pid = pdoc["process_id"]
            counts[tid][pid] = {}

            for coid in pdoc["calls"]:
                chunk = mongo_find_one("calls", {"_id": coid}, {"calls.category": 1})
                category_counts = behavior_categories_percent(chunk["calls"])
                for cat, count in category_counts.items():
                    if cat in ignore_categories:
                        continue
                    counts[tid][pid][cat] = counts[tid][pid].get(cat, 0) + count

    return combine_behavior_percentages(counts)


def helper_summary_mongo(tid1, tid2):
    left_sum, right_sum = None, None
    left_sum = mongo_find_one("analysis", {"info.id": int(tid1)}, {"behavior.summary": 1})
    right_sum = mongo_find_one("analysis", {"info.id": int(tid2)}, {"behavior.summary": 1})
    return get_similar_summary(left_sum, right_sum) if left_sum and right_sum else {}


def helper_percentages_elastic(es_obj, tid1, tid2, ignore_categories=None):
    if ignore_categories is None:
        ignore_categories = ["misc"]
    counts = {}

    for tid in (tid1, tid2):
        counts[tid] = {}
        results = es_obj.search(index=get_analysis_index(), query=get_query_by_info_id(tid))["hits"]["hits"]
        pids_calls = results[-1]["_source"] if results else None
        if not pids_calls:
            continue

        for pdoc in pids_calls["behavior"]["processes"]:
            pid = pdoc["process_id"]
            counts[tid][pid] = {}

            for coid in pdoc["calls"]:
                chunk = es_obj.search(index=get_calls_index(), body={"query": {"match": {"_id": coid}}})["hits"]["hits"][-1][
                    "_source"
                ]
                category_counts = behavior_categories_percent(chunk["calls"])
                for cat, count in category_counts.items():
                    if cat in ignore_categories:
                        continue
                    counts[tid][pid][cat] = counts[tid][pid].get(cat, 0) + count

    return combine_behavior_percentages(counts)


def helper_summary_elastic(es_obj, tid1, tid2):
    left_sum, right_sum = None, None
    buf = es_obj.search(index=get_analysis_index(), query=get_query_by_info_id(tid1))["hits"]["hits"]
    if buf:
        left_sum = buf[-1]["_source"]

    buf = es_obj.search(index=get_analysis_index(), query=get_query_by_info_id(tid2))["hits"]["hits"]
    if buf:
        right_sum = buf[-1]["_source"]

    return get_similar_summary(left_sum, right_sum) if left_sum and right_sum else {}


def get_similar_summary(left_sum, right_sum):
    ret = {}

    for summary in left_sum["behavior"]["summary"]:
        for item in left_sum["behavior"]["summary"][summary]:
            if item in right_sum["behavior"]["summary"][summary]:
                if summary not in list(ret.keys()):
                    ret[summary] = []
                ret[summary].append(item)

    return ret
