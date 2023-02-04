# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from dev_utils.elasticsearchdb import get_daily_calls_index
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File

log = logging.getLogger(__name__)
repconf = Config("reporting")

if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_insert_one


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
        else:
            ensure_valid_utf8(v)


def get_json_document(results, analysis_path):
    # Create a copy of the dictionary. This is done in order to not modify
    # the original dictionary and possibly
    # compromise the following reporting modules.
    report = dict(results)

    if "network" not in report:
        report["network"] = {}

    # Add screenshot paths
    report["shots"] = []
    shots_path = os.path.join(analysis_path, "shots")
    if os.path.exists(shots_path):
        shots = [shot for shot in os.listdir(shots_path) if shot.endswith(".jpg")]
        for shot_file in sorted(shots):
            shot_path = os.path.join(analysis_path, "shots", shot_file)
            screenshot = File(shot_path)
            if screenshot.valid():
                # Strip the extension as it's added later
                # in the Django view
                report["shots"].append(shot_file.replace(".jpg", ""))

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
        # Loop on each process call.
        for _, call in enumerate(process["calls"]):
            # If the chunk size is 100 or if the loop is completed then store the chunk in DB.
            if len(chunk) == 100:
                to_insert = {"pid": process["process_id"], "calls": chunk}
                if mongodb:
                    try:
                        chunk_id = mongo_insert_one("calls", to_insert).inserted_id
                    except Exception as e:
                        chunk_id = None
                elif elastic_db is not None:
                    chunk_id = elastic_db.index(index=get_daily_calls_index(), body=to_insert)["_id"]
                else:
                    chunk_id = None
                if chunk_id:
                    chunks_ids.append(chunk_id)
                # Reset the chunk.
                chunk = []
            # Append call to the chunk.
            chunk.append(call)
        # Store leftovers.
        if chunk:
            to_insert = {"pid": process["process_id"], "calls": chunk}
            if mongodb:
                try:
                    chunk_id = mongo_insert_one("calls", to_insert).inserted_id
                except Exception as e:
                    chunk_id = None
            elif elastic_db is not None:
                chunk_id = elastic_db.index(index=get_daily_calls_index(), body=to_insert)["_id"]
            else:
                chunk_id = None

            if chunk_id:
                chunks_ids.append(chunk_id)

        # Add list of chunks.
        new_process["calls"] = chunks_ids
        new_processes.append(new_process)

    return new_processes
