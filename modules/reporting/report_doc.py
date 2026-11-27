# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import copy
import datetime
import logging
import os
import re
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists

log = logging.getLogger(__name__)
repconf = Config("reporting")

CHUNK_CALL_SIZE = 100
MAX_CALL_VALUE_LEN = 16384
MAX_MONGO_CALL_CHUNK_BYTES = 12 * 1024 * 1024
MAX_MONGO_BULK_BATCH_BYTES = 24 * 1024 * 1024

try:
    from bson import BSON as _BSON
except ImportError:
    _BSON = None


mongo_insert_many = None
if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_insert_many
# NB: pas de elif — mongodb ET elasticsearchdb peuvent etre actifs ensemble ;
# avec elif, parallel_bulk/get_daily_calls_index restent indefinis et le
# module ElasticSearchDB crashe (bug upstream).
if repconf.elasticsearchdb.enabled:
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


def _sanitize_call_data(obj, max_len: int | None = None, bytes_to_str: bool = False):
    """Sanitize UTF-8 and cap oversized call values using copy-on-write so caller data is not mutated."""
    if max_len is None:
        max_len = MAX_CALL_VALUE_LEN
    if isinstance(obj, str):
        if len(obj) > max_len:
            obj = f"{obj[:max_len]}...[truncated]"
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError:
            obj = obj.encode("utf-8", "replace").decode("utf-8")
        return obj
    if type(obj) is bytes:
        trimmed = obj[:max_len] if len(obj) > max_len else obj
        return str(trimmed) if bytes_to_str else trimmed
    if isinstance(obj, datetime.datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(obj, dict):
        new_dict = None
        for k, v in obj.items():
            raw_k = k if isinstance(k, (str, bytes)) else str(k)
            new_k = _sanitize_call_data(raw_k, max_len, bytes_to_str=True)
            if isinstance(new_k, str) and "\x00" in new_k:
                new_k = new_k.replace("\x00", "")
            new_v = _sanitize_call_data(v, max_len, bytes_to_str=bytes_to_str)
            if new_k is not k or new_v is not v:
                if new_dict is None:
                    new_dict = {}
                    for orig_k, orig_v in obj.items():
                        if orig_k is k:
                            break
                        new_dict[orig_k] = orig_v
                new_dict[new_k] = new_v
            elif new_dict is not None:
                new_dict[new_k] = new_v
        return new_dict if new_dict is not None else obj
    if isinstance(obj, list):
        new_list = None
        for idx, v in enumerate(obj):
            new_v = _sanitize_call_data(v, max_len, bytes_to_str=bytes_to_str)
            if new_v is not v:
                if new_list is None:
                    new_list = list(obj)
                new_list[idx] = new_v
        return new_list if new_list is not None else obj
    return obj


def _split_mongo_call_docs(pid, task_id, sanitized_calls, max_bytes=None):
    """Split already-sanitized calls recursively so each MongoDB chunk stays below max_bytes."""
    if max_bytes is None:
        max_bytes = MAX_MONGO_CALL_CHUNK_BYTES
    doc = {"pid": pid, "calls": sanitized_calls, "task_id": task_id}
    if _BSON is None or len(sanitized_calls) <= 1:
        return [doc]
    try:
        encoded_size = len(_BSON.encode(doc))
    except Exception:
        return [doc]
    if encoded_size <= max_bytes:
        return [doc]
    mid = len(sanitized_calls) // 2
    return _split_mongo_call_docs(pid, task_id, sanitized_calls[:mid], max_bytes=max_bytes) + _split_mongo_call_docs(
        pid, task_id, sanitized_calls[mid:], max_bytes=max_bytes
    )


def _build_mongo_call_docs(pid, task_id, call_chunk, max_bytes=None):
    """Build one or more MongoDB call-chunk documents bounded below MongoDB's 16 MiB BSON limit."""
    sanitized = _sanitize_call_data(call_chunk)
    return _split_mongo_call_docs(pid, task_id, sanitized, max_bytes=max_bytes)


def _estimate_bson_size(doc) -> int:
    """Return exact BSON byte length when bson is available, else a UTF-8 size estimate."""
    if _BSON is not None:
        try:
            return len(_BSON.encode(doc))
        except Exception:
            pass
    return len(str(doc).encode("utf-8", "replace"))


def _iter_mongo_wire_batches(docs, max_batch_bytes=None):
    """Group call-chunk documents into wire-safe sub-batches below MongoDB's maxMessageSizeBytes."""
    if max_batch_bytes is None:
        max_batch_bytes = MAX_MONGO_BULK_BATCH_BYTES
    batch = []
    batch_bytes = 0
    for doc in docs:
        doc_bytes = _estimate_bson_size(doc)
        if batch and batch_bytes + doc_bytes > max_batch_bytes:
            yield batch
            batch = [doc]
            batch_bytes = doc_bytes
        else:
            batch.append(doc)
            batch_bytes += doc_bytes
    if batch:
        yield batch


def _is_duplicate_key_error(exc) -> bool:
    """Return True if a MongoDB write error indicates duplicate _id (code 11000)."""
    if getattr(exc, "code", None) == 11000:
        return True
    details = getattr(exc, "details", None)
    if isinstance(details, dict):
        if details.get("code") == 11000:
            return True
        for err in details.get("writeErrors") or []:
            if isinstance(err, dict) and err.get("code") == 11000:
                return True
    return False


def insert_calls(report, elastic_db=None, mongodb=False):
    ## Behaviour envolves storing stuffs in the DB
    # Store chunks of API calls in a different collection and reference
    # those chunks back in the report. In this way we should defeat the
    # issue with the oversized reports exceeding MongoDB's boundaries.
    # Also allows paging of the reports.
    new_processes = []
    for process in report.get("behavior", {}).get("processes", []) or []:
        new_process = dict(process)
        chunks_ids = []

        # Upload for mongoDB
        if mongodb:
            to_insert_list = []
            for call_chunk in chunks(process["calls"], CHUNK_CALL_SIZE):
                to_insert_list.extend(_build_mongo_call_docs(process["process_id"], report["info"]["id"], call_chunk))
            for batch in _iter_mongo_wire_batches(to_insert_list):
                try:
                    res = mongo_insert_many("calls", batch)
                    if res and res.inserted_ids:
                        chunks_ids.extend(res.inserted_ids)
                except Exception as exc:
                    log.error(
                        "Failed to bulk-insert call chunks into MongoDB for task %s (PID %s): %s; falling back per-chunk",
                        report["info"]["id"],
                        process["process_id"],
                        exc,
                    )
                    details = getattr(exc, "details", None)
                    already_inserted = 0
                    failed_indices = set()
                    if isinstance(details, dict) and isinstance(details.get("nInserted"), int):
                        already_inserted = max(0, min(details["nInserted"], len(batch)))
                        for doc in batch[:already_inserted]:
                            if "_id" in doc:
                                chunks_ids.append(doc["_id"])
                        for err in details.get("writeErrors") or []:
                            if isinstance(err, dict) and isinstance(err.get("index"), int):
                                failed_indices.add(err["index"])
                    for idx, chunk_doc in enumerate(batch[already_inserted:], start=already_inserted):
                        if idx in failed_indices:
                            continue
                        try:
                            single_res = mongo_insert_many("calls", [chunk_doc])
                            if single_res and single_res.inserted_ids:
                                chunks_ids.extend(single_res.inserted_ids)
                        except Exception as single_exc:
                            if _is_duplicate_key_error(single_exc) and chunk_doc.get("_id") is not None:
                                chunks_ids.append(chunk_doc["_id"])
                            else:
                                log.error(
                                    "Failed to insert call chunk %d into MongoDB for task %s (PID %s): %s",
                                    idx,
                                    report["info"]["id"],
                                    process["process_id"],
                                    single_exc,
                                )

        elif elastic_db is not None:
            # Upload with parallel bulk for elastic
            def gendata(p_call_chunks, process_id):
                for call_chunk in p_call_chunks:
                    yield {
                        "_index": get_daily_calls_index(),
                        "_op_type": "index",
                        "_source": {
                            "pid": process_id,
                            "calls": _sanitize_call_data(call_chunk, bytes_to_str=True),
                        },
                    }

            for res in parallel_bulk(elastic_db, gendata(chunks(process["calls"], CHUNK_CALL_SIZE), process["process_id"])):
                if res[0]:
                    chunks_ids.append(res[1]["index"]["_id"])

        # Add list of chunks.
        new_process["calls"] = chunks_ids
        new_processes.append(new_process)
    return new_processes
