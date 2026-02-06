# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import copy
import datetime
import logging
import os
import re
from contextlib import suppress

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists

log = logging.getLogger(__name__)
repconf = Config("reporting")

CHUNK_CALL_SIZE = 100


if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_insert_one
elif repconf.elasticsearchdb.enabled:
    from elasticsearch.helpers import parallel_bulk

    from dev_utils.elasticsearchdb import get_daily_calls_index


def ensure_valid_utf8(obj):
    """Ensures that all strings are valid UTF-8 encoded, which is
    required by MongoDB to be able to store the JSON documents.
    @param obj: analysis results dictionary.
    """
    if not obj:
        return

    items = []
    if isinstance(obj, dict):
        items = obj.items()
    elif isinstance(obj, list):
        items = enumerate(obj)

    for k, v in items:
        # This type check is intentionally not done using isinstance(),
        # because bson.binary.Binary *is* a subclass of bytes/str, and
        # we do not want to convert that.
        if isinstance(v, str):
            try:
                v.encode()
            except UnicodeEncodeError:
                obj[k] = "".join(str(ord(_)) for _ in v).encode()
        elif isinstance(v, datetime.datetime):
            obj[k] = v.strftime("%Y-%m-%d %H:%M:%S")
        else:
            ensure_valid_utf8(v)


def get_json_document(results, analysis_path):
    # Create a copy of the dictionary. This is done in order to not modify
    # the original dictionary and possibly
    # compromise the following reporting modules.
    # We use a shallow copy of the top level and common sub-dicts to avoid
    # the extremely expensive deepcopy which often causes OOM on large reports.
    report = results.copy()

    # Manually copy sections that are often modified by reporting modules
    for section in (
        "info",
        "behavior",
        "network",
        "suricata",
        "target",
        "CAPE",
        "static",
        "procdump",
        "dropped",
        "strings",
        "signatures",
        "statistics",
        "memory",
    ):
        if section in report:
            try:
                if isinstance(report[section], dict):
                    report[section] = report[section].copy()
                elif isinstance(report[section], list):
                    report[section] = list(report[section])
            except Exception as e:
                log.warning("Failed to copy section %s: %s", section, e)
                if section == "memory":
                    log.error("Deleting 'memory' key from report due to copy failure")
                    del report["memory"]

    # Deeper copy for behavior processes to avoid modifying metadata
    if "behavior" in report and isinstance(report.get("behavior"), dict):
        if "processes" in report["behavior"]:
            report["behavior"]["processes"] = [p.copy() for p in report["behavior"]["processes"]]
        if "processtree" in report["behavior"]:
            try:
                report["behavior"]["processtree"] = copy.deepcopy(report["behavior"]["processtree"])
            except Exception as e:
                log.warning("Failed to deepcopy processtree: %s", e)

    if "network" not in report:
        report["network"] = {}

    # Add screenshot paths
    report["shots"] = []
    shots_path = os.path.join(analysis_path, "shots")
    if path_exists(shots_path):
        shots = [shot for shot in os.listdir(shots_path) if shot.endswith((".jpg", ".png"))]
        for shot_file in sorted(shots):
            shot_path = os.path.join(analysis_path, "shots", shot_file)
            screenshot = File(shot_path)
            if screenshot.valid():
                # Strip the extension as it's added later
                # in the Django view
                report["shots"].append(re.sub(r"\.(png|jpg)$", "", shot_file))

    # Calculate the mlist_cnt for display if present to reduce db load
    for entry in results.get("signatures", []) or []:
        if entry["name"] == "ie_martian_children":
            report["mlist_cnt"] = len(entry["data"])
        if entry["name"] == "office_martian_children":
            report["f_mlist_cnt"] = len(entry["data"])

    # Other info we want quick access to from the web UI

    if results.get("suricata", False):
        keywords = ("tls", "alerts", "files", "http", "ssh", "dns")
        keywords_dict = ("suri_tls_cnt", "suri_alert_cnt", "suri_file_cnt", "suri_http_cnt", "suri_ssh_cnt", "suri_dns_cnt")
        for keyword, keyword_value in zip(keywords, keywords_dict):
            if results["suricata"].get(keyword, 0):
                report[keyword_value] = len(results["suricata"][keyword])

    return report


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i : i + n]


def insert_calls(report, elastic_db=None, mongodb=False):
    ## Behaviour envolves storing stuffs in the DB
    # Store chunks of API calls in a different collection and reference
    # those chunks back in the report. In this way we should defeat the
    # issue with the oversized reports exceeding MongoDB's boundaries.
    # Also allows paging of the reports.
    new_processes = []
    for process in report.get("behavior", {}).get("processes", []) or []:
        new_process = dict(process)
        chunk = []
        chunks_ids = []

        # Upload for mongoDB
        # Loop on each process call.
        if mongodb:
            for _, call in enumerate(process["calls"]):
                chunk_id = None
                # If the chunk size is CHUNK_CALL_SIZE or if the loop is completed then store the chunk in DB.
                if len(chunk) == CHUNK_CALL_SIZE:
                    to_insert = {"pid": process["process_id"], "calls": chunk, "task_id": report["info"]["id"]}
                    with suppress(Exception):
                        chunk_id = mongo_insert_one("calls", to_insert).inserted_id
                    if chunk_id:
                        chunks_ids.append(chunk_id)
                    # Reset the chunk.
                    chunk = []
                # Append call to the chunk.
                chunk.append(call)

            # Store leftovers.
            if chunk:
                chunk_id = None
                to_insert = {"pid": process["process_id"], "calls": chunk, "task_id": report["info"]["id"]}
                with suppress(Exception):
                    chunk_id = mongo_insert_one("calls", to_insert).inserted_id
                if chunk_id:
                    chunks_ids.append(chunk_id)

        elif elastic_db is not None:
            # Upload with parallel bulk for elastic
            def gendata(p_call_chunks, process_id):
                for call_chunk in p_call_chunks:
                    yield {
                        "_index": get_daily_calls_index(),
                        "_op_type": "index",
                        "_source": {"pid": process_id, "calls": call_chunk},
                    }

            for res in parallel_bulk(elastic_db, gendata(chunks(process["calls"], CHUNK_CALL_SIZE), process["process_id"])):
                if res[0]:
                    chunks_ids.append(res[1]["index"]["_id"])

        # Add list of chunks.
        new_process["calls"] = chunks_ids
        new_processes.append(new_process)
    return new_processes
