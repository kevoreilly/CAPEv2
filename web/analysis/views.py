# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import collections
import datetime
import json
import os
import sys
import tempfile
import zipfile
from contextlib import suppress
from io import BytesIO
from pathlib import Path
from urllib.parse import quote
from wsgiref.util import FileWrapper

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import BadRequest, PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_safe
from rest_framework.decorators import api_view

sys.path.append(settings.CUCKOO_PATH)

import modules.processing.network as network
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import ANALYSIS_BASE_PATH, CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists, path_get_size, path_mkdir, path_read_file, path_safe
from lib.cuckoo.common.utils import delete_folder, yara_detected
from lib.cuckoo.common.web_utils import category_all_files, my_rate_minutes, my_rate_seconds, perform_search, rateblock, statistics
from lib.cuckoo.core.database import TASK_PENDING, Database, Task
from modules.reporting.report_doc import CHUNK_CALL_SIZE

try:
    from django_ratelimit.decorators import ratelimit
except ImportError:
    try:
        from ratelimit.decorators import ratelimit
    except ImportError:
        print("missed dependency: poetry install")

from lib.cuckoo.common.webadmin_utils import disable_user

try:
    import re2 as re
except ImportError:
    import re

try:
    import requests

    HAVE_REQUEST = True
except ImportError:
    HAVE_REQUEST = False

try:
    import pyzipper

    HAVE_PYZIPPER = True
except ImportError:
    print("Missed dependency: poetry install")
    HAVE_PYZIPPER = False

TASK_LIMIT = 25

processing_cfg = Config("processing")
reporting_cfg = Config("reporting")
web_cfg = Config("web")

try:
    # On demand features
    HAVE_FLARE_CAPA = False
    if processing_cfg.flare_capa.on_demand:
        from lib.cuckoo.common.integrations.capa import HAVE_FLARE_CAPA, flare_capa_details
except (NameError, ImportError):
    print("Can't import FLARE-CAPA")

HAVE_STRINGS = False
if processing_cfg.strings.on_demand:
    from lib.cuckoo.common.integrations.strings import extract_strings

    HAVE_STRINGS = True

HAVE_VBA2GRAPH = False
if processing_cfg.vba2graph.on_demand:
    from lib.cuckoo.common.integrations.vba2graph import HAVE_VBA2GRAPH, vba2graph_func

HAVE_XLM_DEOBF = False
if processing_cfg.xlsdeobf.on_demand:
    from lib.cuckoo.common.integrations.XLMMacroDeobfuscator import HAVE_XLM_DEOBF, xlmdeobfuscate

HAVE_VIRUSTOTAL = False
if processing_cfg.virustotal.on_demand:
    from lib.cuckoo.common.integrations.virustotal import vt_lookup

    HAVE_VIRUSTOTAL = True

if reporting_cfg.bingraph.on_demand:
    try:
        from binGraph.binGraph import generate_graphs as bingraph_gen

        from modules.reporting.bingraph import bingraph_args_dict

        HAVE_BINGRAPH = True
    except ImportError:
        HAVE_BINGRAPH = False
else:
    HAVE_BINGRAPH = False

HAVE_FLOSS = False
if processing_cfg.floss.on_demand:
    from lib.cuckoo.common.integrations.floss import HAVE_FLOSS, Floss


# Used for displaying enabled config options in Django UI
enabledconf = {}
on_demand_conf = {}
for cfile in ("reporting", "processing", "auxiliary", "web", "distributed"):
    curconf = Config(cfile)
    confdata = curconf.get_config()
    for item in confdata:
        if "enabled" in confdata[item]:
            if confdata[item]["enabled"] == "yes":
                enabledconf[item] = True
                if confdata[item].get("on_demand", "no") == "yes":
                    on_demand_conf[item] = True
            else:
                enabledconf[item] = False

if enabledconf["mongodb"]:
    from bson.objectid import ObjectId

    from dev_utils.mongodb import mongo_aggregate, mongo_delete_data, mongo_find, mongo_find_one, mongo_update_one

es_as_db = False
essearch = False
if enabledconf["elasticsearchdb"]:
    from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index, get_calls_index, get_query_by_info_id

    essearch = Config("reporting").elasticsearchdb.searchonly
    if not essearch:
        es_as_db = True

    es = elastic_handler

DISABLED_WEB = True
# if elif else won't work here
if enabledconf["mongodb"] or enabledconf["elasticsearchdb"]:
    DISABLED_WEB = False

db = Database()

anon_not_viewable_func_list = (
    "file",
    "remove",
    # "search",
    "pending",
    "filtered_chunk",
    "search_behavior",
    "statistics_data",
)


# Conditional decorator for web authentication
class conditional_login_required:
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if settings.ANON_VIEW and func.__name__ not in anon_not_viewable_func_list:
            return func
        if not self.condition:
            return func
        return self.decorator(func)


def _path_safe(path: str) -> bool:
    if web_cfg.security.check_path_safe:
        return path_safe(path)

    return True


def get_tags_tasks(task_ids: list) -> str:
    for analysis in db.list_tasks(task_ids=task_ids):
        return analysis.tags_tasks


def get_task_package(task_id: int) -> str:
    task = db.view_task(task_id)
    task_dict = task.to_dict()
    return task_dict.get("package", "")


def get_analysis_info(db, id=-1, task=None):
    if not task:
        task = db.view_task(id)
    if not task:
        return None

    new = task.to_dict()
    if new["category"] in ("file", "pcap", "static") and new["sample_id"] is not None:
        new["sample"] = db.view_sample(new["sample_id"]).to_dict()
        filename = os.path.basename(new["target"])
        new.update({"filename": filename})

    new.update({"user_task_tags": get_tags_tasks([new["id"]])})

    if new.get("machine"):
        machine = new["machine"]
        machine = machine.strip(".vmx")
        machine = os.path.basename(machine)
        new.update({"machine": machine})

    rtmp = False

    if enabledconf["mongodb"]:
        rtmp = mongo_find_one(
            "analysis",
            {"info.id": int(new["id"])},
            {
                "info": 1,
                "target.file.virustotal.summary": 1,
                "malscore": 1,
                "detections": 1,
                "network.pcap_sha256": 1,
                "mlist_cnt": 1,
                "f_mlist_cnt": 1,
                "target.file.clamav": 1,
                "suri_tls_cnt": 1,
                "suri_alert_cnt": 1,
                "suri_http_cnt": 1,
                "suri_file_cnt": 1,
                "trid": 1,
                "_id": 0,
            },
            sort=[("_id", -1)],
        )

    if es_as_db:
        rtmp = es.search(
            index=get_analysis_index(),
            query=get_query_by_info_id(str(new["id"])),
            _source=[
                "info",
                "target.file.virustotal.summary",
                "malscore",
                "detections",
                "network.pcap_sha256",
                "mlist_cnt",
                "f_mlist_cnt",
                "target.file.clamav",
                "suri_tls_cnt",
                "suri_alert_cnt",
                "suri_http_cnt",
                "suri_file_cnt",
                "trid",
            ],
        )["hits"]["hits"]
        if len(rtmp) > 1:
            rtmp = rtmp[-1]["_source"]
        elif len(rtmp) == 1:
            rtmp = rtmp[0]["_source"]
        else:
            pass

    if rtmp:
        for keyword in (
            "detections",
            "mlist_cnt",
            "f_mlist_cnt",
            "suri_tls_cnt",
            "suri_alert_cnt",
            "suri_file_cnt",
            "suri_http_cnt",
            "mlist_cnt",
            "f_mlist_cnt",
            "malscore",
        ):
            if keyword in rtmp:
                new[keyword] = rtmp[keyword]

        if "info" in rtmp:
            for keyword in ("custom", "package"):
                if rtmp["info"].get(keyword, False):
                    new[keyword] = rtmp["info"][keyword]

            if enabledconf.get("display_shrike", False) and rtmp["info"].get("shrike_msg", False):
                new["shrike_msg"] = rtmp["info"]["shrike_msg"]
            if enabledconf.get("display_shrike", False) and rtmp["info"].get("shrike_msg", False):
                new["shrike_msg"] = rtmp["info"]["shrike_msg"]

        if "network" in rtmp and "pcap_sha256" in rtmp["network"]:
            new["pcap_sha256"] = rtmp["network"]["pcap_sha256"]

        if rtmp.get("target", {}).get("file", False):
            for keyword in ("clamav", "trid"):
                if rtmp["info"].get(keyword, False):
                    new[keyword] = rtmp["info"]["target"][keyword]
            if rtmp["target"]["file"].get("virustotal", {}).get("summary", False):
                new["virustotal_summary"] = rtmp["target"]["file"]["virustotal"]["summary"]

        if settings.MOLOCH_ENABLED:
            if settings.MOLOCH_BASE[-1] != "/":
                settings.MOLOCH_BASE += "/"
            new["moloch_url"] = (
                settings.MOLOCH_BASE
                + "?date=-1&expression=tags"
                + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE, new["id"]), safe="")
            )

    return new


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request, page=1):
    page = int(page)
    if page == 0:
        page = 1
    off = (page - 1) * TASK_LIMIT

    analyses_files = []
    analyses_urls = []
    analyses_pcaps = []
    analyses_static = []

    tasks_files = db.list_tasks(limit=TASK_LIMIT, offset=off, category="file", not_status=TASK_PENDING)
    tasks_static = db.list_tasks(limit=TASK_LIMIT, offset=off, category="static", not_status=TASK_PENDING)
    tasks_urls = db.list_tasks(limit=TASK_LIMIT, offset=off, category="url", not_status=TASK_PENDING)
    tasks_pcaps = db.list_tasks(limit=TASK_LIMIT, offset=off, category="pcap", not_status=TASK_PENDING)

    # Vars to define when to show Next/Previous buttons
    paging = {}
    paging["show_file_next"] = "show"
    paging["show_url_next"] = "show"
    paging["show_pcap_next"] = "show"
    paging["show_static_next"] = "show"
    paging["next_page"] = str(page + 1)
    paging["prev_page"] = str(page - 1)

    pages_files_num = 0
    pages_urls_num = 0
    pages_pcaps_num = 0
    pages_static_num = 0
    tasks_files_number = db.count_matching_tasks(category="file", not_status=TASK_PENDING) or 0
    tasks_static_number = db.count_matching_tasks(category="static", not_status=TASK_PENDING) or 0
    tasks_urls_number = db.count_matching_tasks(category="url", not_status=TASK_PENDING) or 0
    tasks_pcaps_number = db.count_matching_tasks(category="pcap", not_status=TASK_PENDING) or 0
    if tasks_files_number:
        pages_files_num = int(tasks_files_number / TASK_LIMIT + 1)
    if tasks_static_number:
        pages_static_num = int(tasks_static_number / TASK_LIMIT + 1)
    if tasks_urls_number:
        pages_urls_num = int(tasks_urls_number / TASK_LIMIT + 1)
    if tasks_pcaps_number:
        pages_pcaps_num = int(tasks_pcaps_number / TASK_LIMIT + 1)

    files_pages = []
    urls_pages = []
    pcaps_pages = []
    static_pages = []
    if pages_files_num < 11 or page < 6:
        files_pages = list(range(1, min(10, pages_files_num) + 1))
    elif page > 5:
        files_pages = list(range(min(page - 5, pages_files_num - 10) + 1, min(page + 5, pages_files_num) + 1))
    if pages_static_num < 11 or page < 6:
        static_pages = list(range(1, min(10, pages_static_num) + 1))
    elif page > 5:
        static_pages = list(range(min(page - 5, pages_static_num - 10) + 1, min(page + 5, pages_static_num) + 1))
    if pages_urls_num < 11 or page < 6:
        urls_pages = list(range(1, min(10, pages_urls_num) + 1))
    elif page > 5:
        urls_pages = list(range(min(page - 5, pages_urls_num - 10) + 1, min(page + 5, pages_urls_num) + 1))
    if pages_pcaps_num < 11 or page < 6:
        pcaps_pages = list(range(1, min(10, pages_pcaps_num) + 1))
    elif page > 5:
        pcaps_pages = list(range(min(page - 5, pages_pcaps_num - 10) + 1, min(page + 5, pages_pcaps_num) + 1))

    first_file = 0
    first_static = 0
    first_pcap = 0
    first_url = 0
    # On a fresh install, we need handle where there are 0 tasks.
    buf = db.list_tasks(limit=1, category="file", not_status=TASK_PENDING, order_by=Task.added_on.asc())
    if len(buf) == 1:
        first_file = db.list_tasks(limit=1, category="file", not_status=TASK_PENDING, order_by=Task.added_on.asc())[0].to_dict()[
            "id"
        ]
        paging["show_file_prev"] = "show"
    else:
        paging["show_file_prev"] = "hide"
    buf = db.list_tasks(limit=1, category="static", not_status=TASK_PENDING, order_by=Task.added_on.asc())
    if len(buf) == 1:
        first_static = db.list_tasks(limit=1, category="static", not_status=TASK_PENDING, order_by=Task.added_on.asc())[
            0
        ].to_dict()["id"]
        paging["show_static_prev"] = "show"
    else:
        paging["show_static_prev"] = "hide"
    buf = db.list_tasks(limit=1, category="url", not_status=TASK_PENDING, order_by=Task.added_on.asc())
    if len(buf) == 1:
        first_url = db.list_tasks(limit=1, category="url", not_status=TASK_PENDING, order_by=Task.added_on.asc())[0].to_dict()["id"]
        paging["show_url_prev"] = "show"
    else:
        paging["show_url_prev"] = "hide"
    buf = db.list_tasks(limit=1, category="pcap", not_status=TASK_PENDING, order_by=Task.added_on.asc())
    if len(buf) == 1:
        first_pcap = db.list_tasks(limit=1, category="pcap", not_status=TASK_PENDING, order_by=Task.added_on.asc())[0].to_dict()[
            "id"
        ]
        paging["show_pcap_prev"] = "show"
    else:
        paging["show_pcap_prev"] = "hide"

    if tasks_files:
        for task in tasks_files:
            new = get_analysis_info(db, task=task)
            if new["id"] == first_file:
                paging["show_file_next"] = "hide"
            if page <= 1:
                paging["show_file_prev"] = "hide"

            # Added =: Fix page navigation for pages after the first page
            else:
                paging["show_file_prev"] = "show"
            if db.view_errors(task.id):
                new["errors"] = True

            analyses_files.append(new)
    else:
        paging["show_file_next"] = "hide"

    if tasks_static:
        for task in tasks_static:
            new = get_analysis_info(db, task=task)
            if new["id"] == first_static:
                paging["show_static_next"] = "hide"
            if page <= 1:
                paging["show_static_prev"] = "hide"

            if db.view_errors(task.id):
                new["errors"] = True

            analyses_static.append(new)
    else:
        paging["show_static_next"] = "hide"

    if tasks_urls:
        for task in tasks_urls:
            new = get_analysis_info(db, task=task)
            if new["id"] == first_url:
                paging["show_url_next"] = "hide"
            if page <= 1:
                paging["show_url_prev"] = "hide"

            if db.view_errors(task.id):
                new["errors"] = True

            analyses_urls.append(new)
    else:
        paging["show_url_next"] = "hide"

    if tasks_pcaps:
        for task in tasks_pcaps:
            new = get_analysis_info(db, task=task)
            if new["id"] == first_pcap:
                paging["show_pcap_next"] = "hide"
            if page <= 1:
                paging["show_pcap_prev"] = "hide"

            if db.view_errors(task.id):
                new["errors"] = True

            analyses_pcaps.append(new)
    else:
        paging["show_pcap_next"] = "hide"

    paging["files_page_range"] = files_pages
    paging["static_page_range"] = static_pages
    paging["urls_page_range"] = urls_pages
    paging["pcaps_page_range"] = pcaps_pages
    paging["current_page"] = page
    analyses_files.sort(key=lambda x: x["id"], reverse=True)
    return render(
        request,
        "analysis/index.html",
        {
            "files": analyses_files,
            "static": analyses_static,
            "urls": analyses_urls,
            "pcaps": analyses_pcaps,
            "paging": paging,
            "config": enabledconf,
        },
    )


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def pending(request):
    # db = Database()
    tasks = db.list_tasks(status=TASK_PENDING)

    pending = []
    for task in tasks:
        # Some tasks do not have sample attributes
        sample = db.view_sample(task.sample_id)
        if sample:
            pending.append(
                {
                    "id": task.id,
                    "target": task.target,
                    "added_on": task.added_on,
                    "category": task.category,
                    "md5": sample.md5,
                    "sha256": sample.sha256,
                }
            )

    return render(request, "analysis/pending.html", {"tasks": pending, "count": len(pending)})


# @require_safe
# @conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
# @ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
# @ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
def _load_file(task_id, sha256, existen_details, name):
    filepath = False
    if name == "bingraph":
        filepath = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "bingraph", sha256 + "-ent.svg")

    elif name == "vba2graph":
        filepath = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "vba2graph", "svg", sha256 + ".svg")

    elif name == "debugger":
        debugger_log_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "debugger")
        if path_exists(debugger_log_path) and _path_safe(debugger_log_path):
            for log in os.listdir(debugger_log_path):
                if not log.endswith(".log"):
                    continue

                existen_details[int(log.strip(".log"))] = Path(os.path.join(debugger_log_path, log)).read_text()
    else:
        return existen_details

    if name in ("bingraph", "vba2graph"):
        if not filepath or not path_exists(filepath) or not _path_safe(filepath):
            return existen_details

        existen_details.setdefault(sha256, Path(filepath).read_text())

    return existen_details


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
# @ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
# @ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
def load_files(request, task_id, category):
    """Filters calls for call category.
    @param task_id: cuckoo task id
    """
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    if is_ajax and category in ("CAPE", "dropped", "behavior", "debugger", "network", "procdump", "procmemory", "memory"):
        data = {}
        debugger_logs = {}
        bingraph_dict_content = {}
        vba2graph_dict_content = {}
        # Search calls related to your PID.
        if enabledconf["mongodb"]:
            if category in ("behavior", "debugger"):
                data = mongo_find_one(
                    "analysis",
                    {"info.id": int(task_id)},
                    {"behavior.processes": 1, "behavior.processtree": 1, "detections2pid": 1, "info.tlp": 1, "_id": 0},
                )
                if category == "debugger":
                    data["debugger"] = data["behavior"]
            elif category == "network":
                data = mongo_find_one(
                    "analysis", {"info.id": int(task_id)}, {category: 1, "info.tlp": 1, "cif": 1, "suricata": 1, "_id": 0}
                )
            else:
                data = mongo_find_one("analysis", {"info.id": int(task_id)}, {category: 1, "info.tlp": 1, "_id": 0})
        elif enabledconf["elasticsearchdb"]:
            if category in ("behavior", "debugger"):
                data = elastic_handler.search(
                    index=get_analysis_index(),
                    query=get_query_by_info_id(task_id),
                    _source=["behavior.processes", "behavior.processtree", "info.tlp"],
                )["hits"]["hits"][0]["_source"]

                if category == "debugger":
                    data["debugger"] = data["behavior"]
            elif category == "network":
                data = elastic_handler.search(
                    index=get_analysis_index(),
                    query=get_query_by_info_id(task_id),
                    _source=[category, "suricata", "cif", "info.tlp"],
                )["hits"]["hits"][0]["_source"]
            else:
                data = elastic_handler.search(
                    index=get_analysis_index(), query=get_query_by_info_id(task_id), _source=[category, "info.tlp"]
                )["hits"]["hits"][0]["_source"]

        sha256_blocks = []
        if data:
            if category == "CAPE":
                sha256_blocks = data.get("CAPE", {}).get("payloads", [])
            if category in ("dropped", "procdump"):
                sha256_blocks = data.get(category, [])

        if (enabledconf["vba2graph"] or enabledconf["bingraph"]) and sha256_blocks:
            for block in sha256_blocks or []:
                if not block.get("sha256"):
                    continue
                if enabledconf["bingraph"]:
                    bingraph_dict_content = _load_file(task_id, block["sha256"], bingraph_dict_content, name="bingraph")
                if enabledconf["vba2graph"]:
                    vba2graph_dict_content = _load_file(task_id, block["sha256"], vba2graph_dict_content, name="vba2graph")

        if category == "debugger":
            debugger_logs = _load_file(task_id, "", debugger_logs, name="debugger")

        # ES isn't supported
        page = "analysis/{}/index.html".format(category)

        ajax_response = {
            category: data.get(category, {}),
            "tlp": data.get("info").get("tlp", ""),
            "id": task_id,
            "graphs": {
                "bingraph": {"enabled": enabledconf["bingraph"], "content": bingraph_dict_content},
                "vba2graph": {"enabled": enabledconf["vba2graph"], "content": vba2graph_dict_content},
            },
            "config": enabledconf,
            "tab_name": category,
            "on_demand": on_demand_conf,
        }

        if category == "debugger":
            ajax_response["debugger_logs"] = debugger_logs
        elif category == "network":
            ajax_response["domainlookups"] = {i["domain"]: i["ip"] for i in ajax_response.get("network", {}).get("domains", {})}
            ajax_response["suricata"] = data.get("suricata", {})
            ajax_response["cif"] = data.get("cif", [])
            tls_path = os.path.join(ANALYSIS_BASE_PATH, "analyses", str(task_id), "tlsdump", "tlsdump.log")
            if _path_safe(tls_path):
                ajax_response["tlskeys_exists"] = _path_safe(tls_path)
        elif category == "behavior":
            ajax_response["detections2pid"] = data.get("detections2pid", {})
        return render(request, page, ajax_response)

    else:
        raise PermissionDenied


def fetch_signature_call_data(task_id, requested_calls):
    try:
        requested_calls_by_pid = collections.defaultdict(lambda: collections.defaultdict(set))
        for requested_call in requested_calls:
            if requested_call.get("type") != "call":
                raise BadRequest("Only items whose 'type' is 'call' are accepted.")
            pid = requested_call["pid"]
            cid = requested_call["cid"]
            # Store the "page number" (i.e. chunk) and the index within that chunk of the
            # requested calls.
            # Group the calls within the same chunk together so we only have to
            # query once for each chunk.
            chunk_idx, call_idx = divmod(cid, CHUNK_CALL_SIZE)
            requested_calls_by_pid[pid][chunk_idx].add(call_idx)
    except (AttributeError, KeyError, TypeError, ValueError):
        raise BadRequest

    if enabledconf["mongodb"]:
        # First, get the list of ObjectID's for call chunks for each process.
        process_data = mongo_find_one(
            "analysis",
            {"info.id": task_id},
            {"behavior.processes.process_id": 1, "behavior.processes.calls": 1, "_id": 0},
        )
    elif es_as_db:
        process_data = es.search(
            index=get_analysis_index(),
            body={"query": {"bool": {"must": [{"match": {"info.id": task_id}}]}}},
            _source=["behavior.processes.process_id", "behavior.processes.calls"],
        )["hits"]["hits"][0]["_source"]
    else:
        return HttpResponse()

    # Organize it for quick lookup by PID.
    process_data_by_pid = {proc["process_id"]: proc["calls"] for proc in process_data["behavior"]["processes"]}

    calls_to_return = []
    try:
        # For each of the requested calls, look it up based on the ObjectID
        # referenced from the appropriate chunk in the process's calls and the
        # index within that chunk.
        for pid, chunk_ids in sorted(requested_calls_by_pid.items()):
            for chunk_idx, call_idxs in sorted(chunk_ids.items()):
                chunk_id = process_data_by_pid[pid][chunk_idx]
                if enabledconf["mongodb"]:
                    call_data = mongo_find_one(
                        "calls",
                        {"_id": chunk_id},
                        {"calls": 1, "_id": 0},
                    )
                elif es_as_db:
                    call_data = es.search(
                        index=get_calls_index(),
                        body={"query": {"bool": {"must": [{"match": {"_id": chunk_id}}]}}},
                        _source=["calls"],
                    )["hits"]["hits"][0]["_source"]
                else:
                    return HttpResponse()

                for call_idx in sorted(call_idxs):
                    calls_to_return.append(call_data["calls"][call_idx])
    except (KeyError, IndexError):
        raise BadRequest("Unable to find requested call.")

    return calls_to_return


@csrf_exempt
@require_POST
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def signature_calls(request, task_id):
    try:
        requested_calls = json.loads(request.body)
    except json.JSONDecodeError:
        raise BadRequest("Invalid JSON body.")

    if not requested_calls:
        return HttpResponse()

    try:
        if "call" in requested_calls[0]:
            calls_to_return = [requested_call["call"] for requested_call in requested_calls]
        else:
            calls_to_return = fetch_signature_call_data(int(task_id), requested_calls)
    except (AttributeError, IndexError, TypeError):
        raise BadRequest

    return render(request, "analysis/behavior/_chunk.html", {"chunk": {"calls": calls_to_return}})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def chunk(request, task_id, pid, pagenum):
    try:
        pid, pagenum = int(pid), int(pagenum) - 1
    except Exception:
        raise PermissionDenied

    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    if is_ajax:
        if enabledconf["mongodb"]:
            record = mongo_find_one(
                "analysis",
                {"info.id": int(task_id), "behavior.processes.process_id": pid},
                {"behavior.processes.process_id": 1, "behavior.processes.calls": 1, "_id": 0},
            )

        if es_as_db:
            record = es.search(
                index=get_analysis_index(),
                body={
                    "query": {
                        "bool": {"must": [{"match": {"behavior.processes.process_id": pid}}, {"match": {"info.id": task_id}}]}
                    }
                },
                _source=["behavior.processes.process_id", "behavior.processes.calls"],
            )["hits"]["hits"][0]["_source"]

        if not record:
            raise PermissionDenied

        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == pid:
                process = pdict
                break

        if not process:
            raise PermissionDenied

        if pagenum >= 0 and pagenum < len(process["calls"]):
            objectid = process["calls"][pagenum]
            if enabledconf["mongodb"]:
                chunk = mongo_find_one("calls", {"_id": ObjectId(objectid)})
            if es_as_db:
                chunk = es.search(index=get_calls_index(), body={"query": {"match": {"_id": objectid}}})["hits"]["hits"][0][
                    "_source"
                ]

        else:
            chunk = dict(calls=[])

        return render(request, "analysis/behavior/_chunk.html", {"chunk": chunk})
    else:
        raise PermissionDenied


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def filtered_chunk(request, task_id, pid, category, apilist, caller, tid):
    """Filters calls for call category.
    @param task_id: cuckoo task id
    @param pid: pid you want calls
    @param category: call category type
    @param apilist: comma-separated list of APIs to include, if preceded by ! specifies to exclude the list
    """
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    if is_ajax:
        # Search calls related to your PID.
        if enabledconf["mongodb"]:
            record = mongo_find_one(
                "analysis",
                {"info.id": int(task_id), "behavior.processes.process_id": int(pid)},
                {"behavior.processes.process_id": 1, "behavior.processes.calls": 1, "_id": 0},
            )
        if es_as_db:
            record = es.search(
                index=get_analysis_index(),
                body={
                    "query": {
                        "bool": {"must": [{"match": {"behavior.processes.process_id": pid}}, {"match": {"info.id": task_id}}]}
                    }
                },
                _source=["behavior.processes.process_id", "behavior.processes.calls"],
            )["hits"]["hits"][0]["_source"]

        if not record:
            raise PermissionDenied

        # Extract embedded document related to your process from response collection.
        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == int(pid):
                process = pdict

        if not process:
            raise PermissionDenied

        # Create empty process dict for AJAX view.
        filtered_process = {"process_id": pid, "calls": []}

        exclude = False
        apilist = apilist.strip()
        if len(apilist) and apilist[0] == "!":
            exclude = True
        apilist = apilist.lstrip("!")
        apis = apilist.split(",")
        apis[:] = [s.strip().lower() for s in apis if len(s.strip())]

        # Populate dict, fetching data from all calls and selecting only appropriate category/APIs.
        for call in process["calls"]:
            if enabledconf["mongodb"]:
                chunk = mongo_find_one("calls", {"_id": call})
            if es_as_db:
                chunk = es.search(index=get_calls_index(), body={"query": {"match": {"_id": call}}})["hits"]["hits"][0]["_source"]
            for call in chunk["calls"]:
                # filter by call or tid
                if caller != "null" or tid != "0":
                    if caller in ("null", call["caller"]) and tid in ("0", call["thread_id"]):
                        filtered_process["calls"].append(call)
                elif category in ("all", call["category"]):
                    if len(apis) > 0:
                        add_call = -1
                        for api in apis:
                            if call["api"].lower() == api:
                                if exclude:
                                    add_call = 0
                                else:
                                    add_call = 1
                                break
                        if (exclude and add_call != 0) or (not exclude and add_call == 1):
                            filtered_process["calls"].append(call)
                    else:
                        filtered_process["calls"].append(call)

        return render(request, "analysis/behavior/_chunk.html", {"chunk": filtered_process})
    else:
        raise PermissionDenied


def gen_moloch_from_suri_http(suricata):
    if suricata.get("http"):
        for e in suricata["http"]:
            if e.get("srcip"):
                e["moloch_src_ip_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])), safe="")
                )
            if e.get("dstip"):
                e["moloch_dst_ip_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])), safe="")
                )
            if e.get("dstport"):
                e["moloch_dst_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22tcp\x22" % (str(e["dstport"])), safe="")
                )
            if e.get("srcport"):
                e["moloch_src_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22tcp\x22" % (str(e["srcport"])), safe="")
                )
            if e.get("hostname"):
                e["moloch_http_host_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=host.http" + quote("\x3d\x3d\x22%s\x22" % (e["hostname"]), safe="")
                )
            if e.get("uri"):
                e["moloch_http_uri_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=http.uri"
                    + quote("\x3d\x3d\x22%s\x22" % (e["uri"].encode()), safe="")
                )
            if e.get("ua"):
                e["moloch_http_ua_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=http.user-agent"
                    + quote("\x3d\x3d\x22%s\x22" % (e["ua"].encode()), safe="")
                )
            if e.get("method"):
                e["moloch_http_method_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=http.method" + quote("\x3d\x3d\x22%s\x22" % (e["method"]), safe="")
                )
    return suricata


def gen_moloch_from_suri_alerts(suricata):
    if suricata.get("alerts"):
        for e in suricata["alerts"]:
            if e.get("srcip"):
                e["moloch_src_ip_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])), safe="")
                )
            if e.get("dstip"):
                e["moloch_dst_ip_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])), safe="")
                )
            if e.get("dstport"):
                e["moloch_dst_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dstport"]), e["protocol"].lower()), safe="")
                )
            if e.get("srcport"):
                e["moloch_src_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["srcport"]), e["protocol"].lower()), safe="")
                )
            if e.get("sid"):
                e["moloch_sid_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=tags"
                    + quote("\x3d\x3d\x22suri_sid\x3a%s\x22" % (e["sid"]), safe="")
                )
            if e.get("signature"):
                e["moloch_msg_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=tags"
                    + quote("\x3d\x3d\x22suri_msg\x3a%s\x22" % (re.sub(r"[\W]", "_", e["signature"])), safe="")
                )
    return suricata


def gen_moloch_from_suri_file_info(suricata):
    if suricata.get("files"):
        for e in suricata["files"]:
            if e.get("srcip"):
                e["moloch_src_ip_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])), safe="")
                )
            if e.get("dstip"):
                e["moloch_dst_ip_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])), safe="")
                )
            if e.get("dp"):
                e["moloch_dst_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dp"]), "tcp"), safe="")
                )
            if e.get("sp"):
                e["moloch_src_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["sp"]), "tcp"), safe="")
                )
            if e.get("http_uri"):
                e["moloch_uri_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=http.uri" + quote("\x3d\x3d\x22%s\x22" % (e["http_uri"]), safe="")
                )
            if e.get("http_host"):
                e["moloch_host_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=http.host" + quote("\x3d\x3d\x22%s\x22" % (e["http_host"]), safe="")
                )
            if "file_info" in e:
                if e["file_info"].get("clamav"):
                    e["moloch_clamav_url"] = (
                        settings.MOLOCH_BASE
                        + "?date=-1&expression=tags"
                        + quote("\x3d\x3d\x22clamav\x3a%s\x22" % (re.sub(r"[\W]", "_", e["file_info"]["clamav"])), safe="")
                    )
                if e["file_info"].get("md5"):
                    e["moloch_md5_url"] = (
                        settings.MOLOCH_BASE
                        + "?date=-1&expression=tags"
                        + quote("\x3d\x3d\x22md5\x3a%s\x22" % (e["file_info"]["md5"]), safe="")
                    )
                if e["file_info"].get("sha256"):
                    e["moloch_sha256_url"] = (
                        settings.MOLOCH_BASE
                        + "?date=-1&expression=tags"
                        + quote("\x3d\x3d\x22sha256\x3a%s\x22" % (e["file_info"]["sha256"]), safe="")
                    )
                if e["file_info"].get("yara"):
                    for sign in e["file_info"]["yara"]:
                        if "name" in sign:
                            sign["moloch_yara_url"] = (
                                settings.MOLOCH_BASE
                                + "?date=-1&expression=tags"
                                + quote("\x3d\x3d\x22yara\x3a%s\x22" % (sign["name"]), safe="")
                            )
    return suricata


def gen_moloch_from_suri_tls(suricata):
    if suricata.get("tls"):
        for e in suricata["tls"]:
            if e.get("srcip"):
                e["moloch_src_ip_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])), safe="")
                )
            if e.get("dstip"):
                e["moloch_dst_ip_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])), safe="")
                )
            if e.get("dstport"):
                e["moloch_dst_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dstport"]), "tcp"), safe="")
                )
            if e.get("srcport"):
                e["moloch_src_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["srcport"]), "tcp"), safe="")
                )
    return suricata


def gen_moloch_from_antivirus(virustotal):
    if virustotal and "scans" in virustotal:
        for key in virustotal["scans"]:
            if virustotal["scans"][key]["result"]:
                virustotal["scans"][key]["moloch"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression="
                    + quote("tags\x3d\x3d\x22VT:%s:%s\x22" % (key, virustotal["scans"][key]["result"]), safe="")
                )
    return virustotal


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def surialert(request, task_id):
    if enabledconf["mongodb"]:
        report = mongo_find_one("analysis", {"info.id": int(task_id)}, {"suricata.alerts": 1, "_id": 0}, sort=[("_id", -1)])
    elif es_as_db:
        report = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id), _source=["suricata.alerts"])["hits"][
            "hits"
        ]
        if len(report) == 0:
            report = None
        else:
            report = report[0]["_source"]
    else:
        report = None
    if not report:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE += "/"

        suricata = gen_moloch_from_suri_alerts(suricata)

    return render(request, "analysis/surialert.html", {"suricata": report["suricata"], "config": enabledconf})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def shrike(request, task_id):
    if enabledconf["mongodb"]:
        shrike = mongo_find_one(
            "analysis",
            {"info.id": int(task_id)},
            {"info.shrike_url": 1, "info.shrike_msg": 1, "info.shrike_sid": 1, "info.shrike_refer": 1, "_id": 0},
            sort=[("_id", -1)],
        )
    elif es_as_db:
        shrike = es.search(
            index=get_analysis_index(),
            query=get_query_by_info_id(task_id),
            _source=["info.shrike_url", "info.shrike_msg", "info.shrike_sid", "info.shrike_refer"],
        )["hits"]["hits"]
        if len(shrike) == 0:
            shrike = None
        else:
            shrike = shrike[0]["_source"]
    else:
        shrike = None

    if not shrike:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})

    return render(request, "analysis/shrike.html", {"shrike": shrike})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def surihttp(request, task_id):
    if enabledconf["mongodb"]:
        report = mongo_find_one("analysis", {"info.id": int(task_id)}, {"suricata.http": 1, "_id": 0}, sort=[("_id", -1)])
    elif es_as_db:
        report = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id), _source=["suricata.http"])["hits"][
            "hits"
        ]
        if len(report) == 0:
            report = None
        else:
            report = report[0]["_source"]
    else:
        report = None

    if not report:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE += "/"

        suricata = gen_moloch_from_suri_http(suricata)

    return render(request, "analysis/surihttp.html", {"analysis": report["suricata"], "config": enabledconf})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def suritls(request, task_id):
    if enabledconf["mongodb"]:
        report = mongo_find_one("analysis", {"info.id": int(task_id)}, {"suricata.tls": 1, "_id": 0}, sort=[("_id", -1)])
    elif es_as_db:
        report = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id), _source=["suricata.tls"])["hits"][
            "hits"
        ]
        if len(report) == 0:
            report = None
        else:
            report = report[0]["_source"]
    else:
        report = None

    if not report:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE += "/"

        suricata = gen_moloch_from_suri_tls(suricata)

    return render(request, "analysis/suritls.html", {"analysis": report["suricata"], "config": enabledconf})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def surifiles(request, task_id):
    if enabledconf["mongodb"]:
        report = mongo_find_one(
            "analysis", {"info.id": int(task_id)}, {"info.id": 1, "suricata.files": 1, "_id": 0}, sort=[("_id", -1)]
        )
    elif es_as_db:
        report = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id), _source=["suricata.files"])["hits"][
            "hits"
        ]
        if len(report) == 0:
            report = None
        else:
            report = report[0]["_source"]
    else:
        report = None

    if not report:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE += "/"

        suricata = gen_moloch_from_suri_file_info(suricata)

    return render(request, "analysis/surifiles.html", {"analysis": report["suricata"], "config": enabledconf})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def antivirus(request, task_id):
    if enabledconf["mongodb"]:
        rtmp = mongo_find_one(
            "analysis", {"info.id": int(task_id)}, {"virustotal": 1, "info.category": 1, "_id": 0}, sort=[("_id", -1)]
        )
    elif es_as_db:
        rtmp = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id), _source=["virustotal", "info.category"])[
            "hits"
        ]["hits"]
        if len(rtmp) == 0:
            rtmp = None
        else:
            rtmp = rtmp[0]["_source"]
    else:
        rtmp = None
    if not rtmp:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})
    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE += "/"
        if "virustotal" in rtmp:
            rtmp["virustotal"] = gen_moloch_from_antivirus(rtmp["virustotal"])

    return render(request, "analysis/antivirus.html", {"analysis": rtmp})


@csrf_exempt
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def search_behavior(request, task_id):
    if request.method == "POST":
        query = request.POST.get("search")
        results = []
        search_pid = None
        search_tid = None
        match = re.search(r"pid=(?P<search_pid>\d+)", query)
        if match:
            search_pid = int(match.group("search_pid"))
        match = re.search(r"tid=(?P<search_tid>\d+)", query)
        if match:
            search_tid = match.group("search_tid")

        if search_pid:
            query = query.replace("pid=" + str(search_pid), "")
        if search_tid:
            query = query.replace("tid=" + search_tid, "")

        query = query.strip()

        query = re.compile(re.escape(query))

        # Fetch anaylsis report
        if enabledconf["mongodb"]:
            record = mongo_find_one("analysis", {"info.id": int(task_id)}, {"behavior.processes": 1, "_id": 0})
        if es_as_db:
            esquery = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"][0]
            esidx = esquery["_index"]
            record = esquery["_source"]

        # Loop through every process
        for process in record["behavior"]["processes"]:
            if search_pid and process["process_id"] != search_pid:
                continue

            process_results = []

            if enabledconf["mongodb"]:
                chunks = mongo_find("calls", {"_id": {"$in": process["calls"]}})
            if es_as_db:
                # I don't believe ES has a similar function to MongoDB's $in
                # so we'll just iterate the call list and query appropriately
                chunks = []
                for callitem in process["calls"]:
                    data = es.search(index=esidx, oc_type="calls", q="_id: %s" % callitem)["hits"]["hits"][0]["_source"]
                    chunks.append(data)

            for chunk in chunks:
                for call in chunk.get("calls", []):
                    if search_tid and call["thread_id"] != search_tid:
                        continue
                    # TODO: ES can speed this up instead of parsing with
                    # Python regex.
                    if query.search(call["api"]):
                        process_results.append(call)
                    else:
                        for argument in call["arguments"]:
                            if query.search(argument["name"]) or query.search(argument["value"]):
                                process_results.append(call)
                                break

            if len(process_results) > 0:
                results.append({"process": process, "signs": process_results})

        return render(request, "analysis/behavior/_search_results.html", {"results": results})
    else:
        raise PermissionDenied


def split_signature_calls(report):
    """For each of the signatures in the given report, examine its "data" and separate out calls in to a "calls" key."""
    if report is None:
        return None
    for sig in report.get("signatures", []):
        if sig.get("new_data"):
            continue
        calls = []
        non_calls = []
        for datum in sig.pop("data", []):
            if datum.get("type") == "call":
                calls.append(datum)
            else:
                non_calls.append(datum)
        if calls:
            sig["calls"] = calls
        sig["data"] = non_calls

    return report


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
def report(request, task_id):
    network_report = False
    report = {}
    if enabledconf["mongodb"]:
        report = mongo_find_one(
            "analysis",
            {"info.id": int(task_id)},
            {"dropped": 0, "CAPE.payloads": 0, "procdump": 0, "procmemory": 0, "behavior.processes": 0, "network": 0, "memory": 0},
            sort=[("_id", -1)],
        )
        network_report = mongo_find_one(
            "analysis",
            {"info.id": int(task_id)},
            {"network.domains": 1, "network.dns": 1, "network.hosts": 1},
            sort=[("_id", -1)],
        )
        report = split_signature_calls(report)

    if es_as_db:
        query = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"][0]
        report = query["_source"]
        # Extract out data for Admin tab in the analysis page
        network_report = es.search(
            index=get_analysis_index(),
            query=get_query_by_info_id(task_id),
            _source=["network.domains", "network.dns", "network.hosts"],
        )["hits"]["hits"][0]["_source"]

        # Extract out data for Admin tab in the analysis page
        esdata = {"index": query["_index"], "id": query["_id"]}
        report["es"] = esdata
    if not report:
        if DISABLED_WEB:
            msg = "You need to enable Mongodb/ES to be able to use WEBGUI to see the analysis"
        else:
            msg = "The specified analysis does not exist or not finished yet."

        return render(request, "error.html", {"error": msg})

    if isinstance(report.get("CAPE"), dict) and report.get("CAPE", {}).get("configs", {}):
        report["malware_conf"] = report["CAPE"]["configs"]
    report["CAPE"] = 0
    report["dropped"] = 0
    report["procdump"] = 0
    report["memory"] = 0

    for key, value in (("dropped", "dropped"), ("procdump", "procdump"), ("CAPE.payloads", "CAPE"), ("procmemory", "procmemory")):
        if enabledconf["mongodb"]:
            try:
                report[value] = list(
                    mongo_aggregate(
                        "analysis",
                        [
                            {"$match": {"info.id": int(task_id)}},
                            {
                                "$project": {
                                    "_id": 0,
                                    f"{value}_size": {
                                        "$add": [
                                            {"$size": {"$ifNull": [f"${key}.{subkey}", []]}} for subkey in ("sha256", "file_ref")
                                        ]
                                    },
                                },
                            },
                        ],
                    )
                )[0][f"{value}_size"]
            except Exception:
                report[value] = 0

        elif es_as_db:
            try:
                report[value] = len(
                    es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id), _source=[f"{key}.sha256"])["hits"][
                        "hits"
                    ][0]["_source"].get(key)
                )
            except Exception as e:
                print(e)

    try:
        if enabledconf["mongodb"]:
            tmp_data = list(mongo_find("analysis", {"info.id": int(task_id), "memory": {"$exists": True}}))
            if tmp_data:
                report["memory"] = tmp_data[0]["_id"] or 0
        elif es_as_db:
            report["memory"] = len(
                es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id), _source=["memory"])["hits"]["hits"]
            )
    except Exception as e:
        print(e)

    reports_exist = False
    # check if we allow dl reports only to specific users
    if settings.ALLOW_DL_REPORTS_TO_ALL:
        reporting_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "reports")
        if path_exists(reporting_path) and os.listdir(reporting_path):
            reports_exist = True

    debugger_log_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "debugger")
    if path_exists(debugger_log_path) and os.listdir(debugger_log_path):
        report["debugger_logs"] = 1

    if settings.MOLOCH_ENABLED and "suricata" in report:
        suricata = report["suricata"]
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE += "/"
        report["moloch_url"] = (
            settings.MOLOCH_BASE
            + "?date=-1&expression=tags"
            + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE, task_id), safe="")
        )
        if isinstance(suricata, dict):
            suricata = gen_moloch_from_suri_http(suricata)
            suricata = gen_moloch_from_suri_alerts(suricata)
            suricata = gen_moloch_from_suri_file_info(suricata)
            suricata = gen_moloch_from_suri_tls(suricata)

    if settings.MOLOCH_ENABLED and "virustotal" in report:
        report["virustotal"] = gen_moloch_from_antivirus(report["virustotal"])

    vba2graph = False
    vba2graph_dict_content = {}
    # we don't want to do this for urls but we might as well check that the target exists
    if report.get("target", {}).get("file", {}).get("sha256"):
        vba2graph = processing_cfg.vba2graph.enabled
        vba2graph_svg_path = os.path.join(
            CUCKOO_ROOT, "storage", "analyses", str(task_id), "vba2graph", "svg", report["target"]["file"]["sha256"] + ".svg"
        )

        if path_exists(vba2graph_svg_path) and _path_safe(vba2graph_svg_path):
            vba2graph_dict_content.setdefault(report["target"]["file"]["sha256"], Path(vba2graph_svg_path).read_text())

    bingraph = reporting_cfg.bingraph.enabled
    bingraph_dict_content = {}
    bingraph_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "bingraph")
    if path_exists(bingraph_path):
        for file in os.listdir(bingraph_path):
            tmp_file = os.path.join(bingraph_path, file)
            bingraph_dict_content.setdefault(os.path.basename(tmp_file).split("-", 1)[0], Path(tmp_file).read_text())

    domainlookups = {}
    iplookups = {}
    if network_report.get("network", {}):
        report["network"] = network_report["network"]

        if "domains" in network_report["network"]:
            domainlookups = dict((i["domain"], i["ip"]) for i in network_report["network"]["domains"])
            iplookups = dict((i["ip"], i["domain"]) for i in network_report["network"]["domains"])
            for i in network_report["network"]["dns"]:
                for a in i["answers"]:
                    iplookups[a["data"]] = i["request"]

    if HAVE_REQUEST and enabledconf["distributed"]:
        try:
            res = requests.get(f"http://127.0.0.1:9003/task/{task_id}", timeout=3, verify=False)
            if res and res.ok:
                if "name" in res.json():
                    report["distributed"] = {}
                    report["distributed"]["name"] = res.json()["name"]
                    report["distributed"]["task_id"] = res.json()["task_id"]
        except Exception as e:
            print(e)

    stats_total = {
        "total": 0,
        "processing": 0,
        "signatures": 0,
        "reporting": 0,
    }
    for stats_category in ("processing", "signatures", "reporting"):
        total = 0.0
        for item in report.get("statistics", {}).get(stats_category, []) or []:
            total += item["time"]

        stats_total["total"] += total
        stats_total[stats_category] = "{:.2f}".format(total)

    stats_total["total"] = "{:.2f}".format(stats_total["total"])
    if HAVE_REQUEST and enabledconf["distributed"]:
        try:
            res = requests.get(f"http://127.0.0.1:9003/task/{task_id}", timeout=3, verify=False)
            if res and res.ok:
                res = res.json()
                if "name" in res:
                    report["distributed"] = {}
                    report["distributed"]["name"] = res["name"]
                    report["distributed"]["task_id"] = res["task_id"]
        except Exception as e:
            print(e)

    existent_tasks = {}
    if web_cfg.general.get("existent_tasks", False) and report.get("target", {}).get("file", {}).get("sha256"):
        records = perform_search("sha256", report["target"]["file"]["sha256"])
        for record in records:
            if record["info"]["id"] == report["info"]["id"]:
                continue
            existent_tasks[record["info"]["id"]] = record.get("detections")

    # process log per task if enabled:
    process_log_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "process.log")
    if web_cfg.general.expose_process_log and path_exists(process_log_path) and path_get_size(process_log_path):
        report["process_log"] = path_read_file(process_log_path, mode="text")

    return render(
        request,
        "analysis/report.html",
        {
            "analysis": report,
            # ToDo test
            "file": report.get("target", {}).get("file", {}),
            "id": report["info"]["id"],
            "tab_name": "static",
            "source_url": report["info"].get("source_url", ""),
            # till here
            "domainlookups": domainlookups,
            "iplookups": iplookups,
            "settings": settings,
            "config": enabledconf,
            "reports_exist": reports_exist,
            "stats_total": stats_total,
            "graphs": {
                "vba2graph": {"enabled": vba2graph, "content": vba2graph_dict_content},
                "bingraph": {"enabled": bingraph, "content": bingraph_dict_content},
            },
            "on_demand": on_demand_conf,
            "existent_tasks": existent_tasks,
        },
    )


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@csrf_exempt
@api_view(["GET"])
def file_nl(request, category, task_id, dlfile):
    base_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
    path = False
    if category == "screenshot":
        for ext, cd in ((".jpg", "image/jpeg"), (".png", "image/png")):
            file_name = dlfile + ext
            path = os.path.join(base_path, "shots", file_name)
            if path_exists(path):
                break
        else:
            return render(request, "error.html", {"error": f"Could not find screenshot {dlfile}"})

    elif category == "bingraph":
        file_name = dlfile + "-ent.svg"
        path = os.path.join(base_path, "bingraph", file_name)
        cd = "image/svg+xml"

    elif category == "vba2graph":
        file_name = f"{dlfile}.svg"
        path = os.path.join(base_path, "vba2graph", "svg", file_name)
        cd = "image/svg+xml"

    else:
        return render(request, "error.html", {"error": "Category not defined"})

    if path and not _path_safe(path):
        return render(request, "error.html", {"error": "File not found"})

    # Performance considerations
    # https://docs.djangoproject.com/en/4.1/ref/request-response/#streaminghttpresponse-objects
    file_size = Path(path).stat().st_size
    try:
        resp = StreamingHttpResponse(FileWrapper(open(path, "rb"), 8192), content_type=cd)
    except Exception:
        return render(request, "error.html", {"error": "File {} not found".format(path)})

    resp["Content-Length"] = file_size
    resp["Content-Disposition"] = "attachment; filename=" + file_name
    return resp


zip_categories = (
    "staticzip",
    "droppedzip",
    "CAPEzip",
    "procdumpzip",
    "memdumpzip",
    "networkzip",
    "pcapzip",
    "droppedzipall",
    "procdumpzipall",
    "CAPEzipall",
    "capeyarazipall",
)
category_map = {
    "CAPE": "CAPE",
    "procdump": "procdump",
    "dropped": "files",
}


def _file_search_all_files(search_category: str, search_term: str) -> list:
    path = []
    try:
        projection = {
            "info.parent_sample.path": 1,
            "info.parent_sample.cape_yara.name": 1,
            "target.file.path": 1,
            "target.file.cape_yara.name": 1,
            "dropped.path": 1,
            "dropped.cape_yara.name": 1,
            "procdump.path": 1,
            "procdump.cape_yara.name": 1,
            "CAPE.payloads.path": 1,
            "CAPE.payloads.cape_yara.name": 1,
            "info.parent_sample.extracted_files_tool.path": 1,
            "info.parent_sample.extracted_files_tool.cape_yara.name": 1,
            "target.file.extracted_files_tool.path": 1,
            "target.file.extracted_files_tool.cape_yara.name": 1,
            "dropped.extracted_files_tool.path": 1,
            "dropped.extracted_files_tool.cape_yara.name": 1,
            "procdump.extracted_files_tool.path": 1,
            "procdump.extracted_files_tool.cape_yara.name": 1,
            "CAPE.payloads.extracted_files_tool.path": 1,
            "CAPE.payloads.extracted_files_tool.cape_yara.name": 1,
        }
        records = perform_search(search_category, search_term, projection=projection)
        search_term = search_term.lower()
        for _, filepath, _, _ in yara_detected(search_term, records):
            if not path_exists(filepath):
                continue
            path.append(filepath)
    except ValueError as e:
        print("mongodb load", e)

    # remove any duplicated before return
    return list(set(path))


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@csrf_exempt
@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@api_view(["GET"])
def file(request, category, task_id, dlfile):
    file_name = dlfile
    cd = "application/octet-stream"
    path = ""
    mem_zip = False
    extmap = {
        "memdump": ".dmp",
        "memdumpstrings": ".dmp.strings",
    }

    if category in zip_categories and not HAVE_PYZIPPER:
        return render(request, "error.html", {"error": "Missed pyzipper library: poetry install"})

    if category in ("sample", "static", "staticzip"):
        path = os.path.join(CUCKOO_ROOT, "storage", "binaries", file_name)
    elif category in ("dropped", "droppedzip"):
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "files", file_name)
        # Self Extracted support folder
        if not path_exists(path):
            path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "selfextracted", file_name)
    elif category in ("droppedzipall", "procdumpzipall", "CAPEzipall"):
        if web_cfg.zipped_download.download_all:
            sub_cat = category.replace("zipall", "")
            path = category_all_files(
                task_id, sub_cat, os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), category_map[sub_cat])
            )
            file_name = f"{task_id}_{category}"
    elif category.startswith("CAPE"):
        buf = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "CAPE", file_name)
        if os.path.isdir(buf):
            dfile = min(os.listdir(buf), key=len)
            path = os.path.join(buf, dfile)
        else:
            path = buf
            if not path_exists(path):
                path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "selfextracted", file_name)
    elif category == "networkzip":
        buf = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "network", file_name)
        path = buf
    elif category.startswith("memdumpzip"):
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "memory", file_name + ".dmp")
        file_name += ".dmp"
    elif category in ("pcap", "pcapzip"):
        file_name += ".pcap"
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "dump.pcap")
        cd = "application/vnd.tcpdump.pcap"
    elif category == "debugger_log":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "debugger", str(dlfile) + ".log")
    elif category == "rtf":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "rtf_objects", file_name)
    elif category == "usage":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "aux", "usage.svg")
        file_name = "usage.svg"
        cd = "image/svg+xml"
    elif category in extmap:
        file_name += extmap[category]
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "memory", file_name)
        if not path_exists(path):
            file_name += ".zip"
            path += ".zip"
            cd = "application/zip"
    elif category == "dropped":
        buf = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "files", file_name)
        if os.path.isdir(buf):
            dfile = min(os.listdir(buf), key=len)
            path = os.path.join(buf, dfile)
        else:
            path = buf
    elif category.startswith("procdump"):
        buf = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "procdump", file_name)
        if os.path.isdir(buf):
            dfile = min(os.listdir(buf), key=len)
            path = os.path.join(buf, dfile)
        else:
            path = buf
    # Just for suricata dropped files currently
    elif category == "zip":
        file_name = "files.zip"
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "logs", "files.zip")
        cd = "application/zip"
    elif category == "suricata":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "logs", "files", file_name)
    elif category == "rtf":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "rtf_objects", file_name)
    elif category == "tlskeys":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "tlsdump", "tlsdump.log")
    elif category == "evtx":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "evtx", "evtx.zip")
        file_name = f"{task_id}_evtx.zip"
        cd = "application/zip"
    elif category == "capeyarazipall":
        # search in mongo and get the path
        if enabledconf["mongodb"] and web_cfg.zipped_download.download_all:
            path = _file_search_all_files(category.replace("zipall", ""), dlfile)
    else:
        return render(request, "error.html", {"error": "Category not defined"})

    if not isinstance(path, list):
        send_filename = f"{task_id + '_' if task_id not in os.path.basename(path) else ''}{os.path.basename(path)}"
        if category in zip_categories:
            send_filename += ".zip"
    else:
        send_filename = file_name + ".zip"

    if not path:
        return render(
            request,
            "error.html",
            {"error": "Files not found or option is not enabled in conf/web.conf -> [zipped_download] -> download_all"},
        )

    test_path = path
    if isinstance(path, list):
        test_path = path[0]

    if test_path and (not path_exists(test_path) or not _path_safe(test_path)):
        return render(request, "error.html", {"error": "File {} not found".format(os.path.basename(test_path))})

    try:
        if category in zip_categories:
            mem_zip = BytesIO()
            with pyzipper.AESZipFile(mem_zip, "w", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(settings.ZIP_PWD)
                if not isinstance(path, list):
                    path = [path]
                for file in path:
                    with open(file, "rb") as f:
                        zf.writestr(os.path.basename(file), f.read())
            mem_zip.seek(0)
            resp = StreamingHttpResponse(mem_zip, content_type=cd)
            resp["Content-Length"] = len(mem_zip.getvalue())
            file_name += ".zip"
            path = os.path.join(tempfile.gettempdir(), file_name)
            cd = "application/zip"
        else:
            resp = StreamingHttpResponse(FileWrapper(open(path, "rb"), 8091), content_type=cd)
            resp["Content-Length"] = Path(path).stat().st_size
        resp["Content-Disposition"] = f"attachment; filename={send_filename}"
        return resp
    except Exception as e:
        print(e)
        return render(request, "error.html", {"error": "File {} not found".format(os.path.basename(path))})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def procdump(request, task_id, process_id, start, end, zipped=False):
    origname = process_id + ".dmp"
    tmpdir = None
    tmp_file_path = None
    response = False
    if enabledconf["mongodb"]:
        analysis = mongo_find_one("analysis", {"info.id": int(task_id)}, {"procmemory": 1, "_id": 0}, sort=[("_id", -1)])
    if es_as_db:
        analysis = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"][0]["_source"]

    dumpfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "memory", origname)

    if not _path_safe(dumpfile):
        return render(request, "error.html", {"error": f"File not found: {os.path.basename(dumpfile)}"})

    if not path_exists(dumpfile):
        dumpfile += ".zip"
        if not path_exists(dumpfile):
            return render(request, "error.html", {"error": "File not found"})
        f = zipfile.ZipFile(dumpfile, "r")
        tmpdir = tempfile.mkdtemp(prefix="capeprocdump_", dir=settings.TEMP_PATH)
        tmp_file_path = f.extract(origname, path=tmpdir)
        f.close()
        dumpfile = tmp_file_path

    content_type = "application/octet-stream"

    if not path_exists(dumpfile):
        return render(request, "error.html", {"error": "File not found"})

    file_name = f"{process_id}_{int(start, 16):x}.dmp"
    with open(dumpfile, "rb") as file_item:
        for proc in analysis.get("procmemory", []) or []:
            if proc["pid"] == int(process_id):
                s = BytesIO()
                for memmap in proc["address_space"]:
                    for chunk in memmap["chunks"]:
                        if int(chunk["start"], 16) >= int(start, 16) and int(chunk["end"], 16) <= int(end, 16):
                            file_item.seek(chunk["offset"])
                            s.write(file_item.read(int(chunk["size"], 16)))
                s.seek(0)
                if zipped and HAVE_PYZIPPER:
                    mem_zip = BytesIO()
                    with pyzipper.AESZipFile(mem_zip, "w", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
                        zf.setpassword(settings.ZIP_PWD)
                        zf.writestr(file_name, s.getvalue())
                    file_name += ".zip"
                    content_type = "application/zip"
                    mem_zip.seek(0)
                    s = mem_zip
                response = StreamingHttpResponse(s, content_type=content_type)
                response["Content-Length"] = len(s.getvalue())
                response["Content-Disposition"] = "attachment; filename={0}".format(file_name)
                break

    with suppress(Exception):
        if tmp_file_path:
            Path(tmp_file_path).unlink()
        if tmpdir:
            delete_folder(tmpdir)

    if response:
        return response

    return render(request, "error.html", {"error": "File not found"})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def filereport(request, task_id, category):
    # check if allowed to download to all + if no if user has permissions
    if not settings.ALLOW_DL_REPORTS_TO_ALL and (
        request.user.is_anonymous
        or (
            hasattr(request.user, "userprofile")
            and hasattr(request.user.userprofile, "reports")
            and not request.user.userprofile.reports
        )
    ):
        return render(
            request,
            "error.html",
            {"error": "You don't have permissions to download reports. Ask admin to enable it for you in user profile."},
        )

    formats = {
        "protobuf": "report.protobuf",
        "json": "report.json",
        "html": "report.html",
        "htmlsummary": "summary-report.html",
        "pdf": "report.pdf",
        "maec": "report.maec-4.1.xml",
        "maec5": "report.maec-5.0.json",
        "metadata": "report.metadata.xml",
        "misp": "misp.json",
        "litereport": "lite.json",
        "cents": "cents.rules",
    }

    if category in formats:
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "reports", formats[category])

        if not _path_safe(path) or not path_exists(path):
            return render(request, "error.html", {"error": f"File not found: {formats[category]}"})

        response = HttpResponse(Path(path).read_bytes(), content_type="application/octet-stream")
        response["Content-Disposition"] = f"attachment; filename={task_id}_{formats[category]}"
        return response

    return render(request, "error.html", {"error": "File not found"}, status=404)


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def full_memory_dump_file(request, analysis_number):
    filename = False
    for name in ("memory.dmp", "memory.dmp.zip"):
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), name)
        if path_exists(path) and _path_safe(path):
            filename = name
            break

    if filename:
        content_type = "application/octet-stream"
        response = StreamingHttpResponse(FileWrapper(open(path, "rb"), 8192), content_type=content_type)
        response["Content-Length"] = os.path.getsize(path)
        response["Content-Disposition"] = f"attachment; filename={filename}"
        return response

    return render(request, "error.html", {"error": "File not found"})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def full_memory_dump_strings(request, analysis_number):
    filename = None
    for name in ("memory.dmp.strings", "memory.dmp.strings.zip"):
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), name)
        if path_exists(path):
            filename = name
            if not _path_safe(ANALYSIS_BASE_PATH):
                return render(request, "error.html", {"error": f"File not found: {name}"})
            break
    if filename:
        content_type = "application/octet-stream"
        response = StreamingHttpResponse(FileWrapper(open(path), 8192), content_type=content_type)
        response["Content-Length"] = os.path.getsize(path)
        response["Content-Disposition"] = "attachment; filename=%s" % filename
        return response

    return render(request, "error.html", {"error": "File not found"})


@csrf_exempt
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
def search(request, searched=""):
    if "search" in request.POST or "search" in request.GET or searched:
        term = ""
        if not searched:
            if request.POST.get("search"):
                searched = str(request.POST["search"])
            elif request.GET.get("search"):
                searched = str(request.GET["search"])

        if ":" in searched:
            term, value = searched.strip().split(":", 1)
        else:
            value = searched.strip()

        # Check on search size. But malscore, ID and package can be strings of less than 3 characters.
        if term not in {"malscore", "id", "ids", "package"} and len(value) < 3:
            return render(
                request,
                "analysis/search.html",
                {"analyses": None, "term": searched, "error": "Search term too short, minimum 3 characters required"},
            )

        # name:foo or name: foo
        value = value.lstrip()
        term = term.lower()

        if not term:
            value = value.lower()
            if re.match(r"^([a-fA-F\d]{32})$", value):
                term = "md5"
            elif re.match(r"^([a-fA-F\d]{40})$", value):
                term = "sha1"
            elif re.match(r"^([a-fA-F\d]{64})$", value):
                term = "sha256"
            elif re.match(r"^([a-fA-F\d]{96})$", value):
                term = "sha3"
            elif re.match(r"^([a-fA-F\d]{128})$", value):
                term = "sha512"

        if term == "ids":
            if all([v.strip().isdigit() for v in value.split(",")]):
                value = [int(v.strip()) for v in filter(None, value.split(","))]
            else:
                return render(
                    request,
                    "analysis/search.html",
                    {"analyses": None, "term": searched, "error": "Not all values are integers"},
                )

        # Escape forward slash characters
        if isinstance(value, str):
            value = value.replace("\\", "\\\\")

        term_only, value_only = term, value

        try:
            records = perform_search(term, value, user_id=request.user.id, privs=request.user.is_staff)
        except ValueError:
            if term:
                return render(
                    request,
                    "analysis/search.html",
                    {"analyses": None, "term": searched, "error": "Invalid search term: %s" % term},
                )
            else:
                return render(
                    request,
                    "analysis/search.html",
                    {"analyses": None, "term": None, "error": "Unable to recognize the search syntax"},
                )

        analyses = []
        for result in records or []:
            new = None
            if enabledconf["mongodb"] and enabledconf["elasticsearchdb"] and essearch and not term:
                new = get_analysis_info(db, id=int(result["_source"]["task_id"]))
            if enabledconf["mongodb"] and term and "info" in result:
                new = get_analysis_info(db, id=int(result["info"]["id"]))
            if es_as_db:
                new = get_analysis_info(db, id=int(result["info"]["id"]))
            if not new:
                continue
            analyses.append(new)

        return render(
            request,
            "analysis/search.html",
            {
                "analyses": analyses,
                "config": enabledconf,
                "term": searched,
                "error": None,
                "term_only": term_only,
                "value_only": value_only,
            },
        )
    return render(request, "analysis/search.html", {"analyses": None, "term": None, "error": None})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def remove(request, task_id):
    """Remove an analysis."""
    if not enabledconf["delete"] and not request.user.is_staff:
        return render(request, "success_simple.html", {"message": "buy a lot of whiskey to admin ;)"})

    if enabledconf["mongodb"]:
        mongo_delete_data(int(task_id))
        analyses_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id)
        if path_exists(analyses_path):
            delete_folder(analyses_path)
        message = "Task(s) deleted."
    if es_as_db:
        analyses = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"]
        if len(analyses) > 1:
            message = "Multiple tasks with this ID deleted."
        elif len(analyses) == 1:
            message = "Task deleted."
        if len(analyses) > 0:
            for analysis in analyses:
                esidx = analysis["_index"]
                esid = analysis["_id"]
                # Check if behavior exists
                if analysis["_source"]["behavior"]:
                    for process in analysis["_source"]["behavior"]["processes"]:
                        for call in process["calls"]:
                            es.delete(
                                index=esidx,
                                doc_type="calls",
                                id=call,
                            )
                # Delete the analysis results
                es.delete(
                    index=esidx,
                    doc_type="analysis",
                    id=esid,
                )
    elif essearch:
        # remove es search data
        analyses = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"]
        if len(analyses) > 1:
            message = "Multiple tasks with this ID deleted."
        elif len(analyses) == 1:
            message = "Task deleted."
        if len(analyses) > 0:
            for analysis in analyses:
                esidx = analysis["_index"]
                esid = analysis["_id"]
                # Delete the analysis results
                es.delete(
                    index=esidx,
                    doc_type="analysis",
                    id=esid,
                )

    db.delete_task(task_id)

    return render(request, "success_simple.html", {"message": message})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def pcapstream(request, task_id, conntuple):
    src, sport, dst, dport, proto = conntuple.split(",")
    sport, dport = int(sport), int(dport)

    if enabledconf["mongodb"]:
        conndata = mongo_find_one(
            "analysis",
            {"info.id": int(task_id)},
            {"network.sorted.tcp": 1, "network.sorted.udp": 1, "network.sorted_pcap_sha256": 1, "_id": 0},
            sort=[("_id", -1)],
        )

    if es_as_db:
        conndata = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"][0]["_source"]

    if not conndata:
        return render(request, "standalone_error.html", {"error": "The specified analysis does not exist"})

    try:
        if proto == "udp":
            connlist = conndata["network"]["sorted"]["udp"]
        else:
            connlist = conndata["network"]["sorted"]["tcp"]

        conns = [i for i in connlist if (i["sport"], i["dport"], i["src"], i["dst"]) == (sport, dport, src, dst)]
        stream = conns[0]
        offset = stream["offset"]
    except Exception:
        return render(request, "standalone_error.html", {"error": "Could not find the requested stream"})

    try:
        # if we do, build out the path to it
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "dump_sorted.pcap")

        if not path_exists(path) or not _path_safe(path):
            return render(request, "standalone_error.html", {"error": "The required sorted PCAP does not exist"})

        fobj = open(path, "rb")
    except Exception:
        return render(request, "standalone_error.html", {"error": "The required sorted PCAP does not exist"})

    packets = list(network.packets_for_stream(fobj, offset))
    fobj.close()

    return HttpResponse(json.dumps(packets), content_type="application/json")


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def comments(request, task_id):
    if request.method == "POST" and settings.COMMENTS:
        comment = request.POST.get("commentbox", "")
        if not comment:
            return render(request, "error.html", {"error": "No comment provided."})

        if enabledconf["mongodb"]:
            report = mongo_find_one("analysis", {"info.id": int(task_id)}, {"info.comments": 1, "_id": 0}, sort=[("_id", -1)])
        if es_as_db:
            query = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"][0]
            report = query["_source"]
            esid = query["_id"]
            esidx = query["_index"]
        if "comments" in report["info"]:
            curcomments = report["info"]["comments"]
        else:
            curcomments = []
        buf = {}
        buf["Timestamp"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        escape_map = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&apos;",
            "<": "&lt;",
            ">": "&gt;",
            "\n": "<br />",
        }
        buf["Data"] = "".join(escape_map.get(thechar, thechar) for thechar in comment)
        # status can be posted/removed
        buf["Status"] = "posted"
        curcomments.insert(0, buf)
        if enabledconf["mongodb"]:
            mongo_update_one("analysis", {"info.id": int(task_id)}, {"$set": {"info.comments": curcomments}})
        if es_as_db:
            es.update(index=esidx, id=esid, body={"doc": {"info": {"comments": curcomments}}})
        return redirect("report", task_id=task_id)

    return render(request, "error.html", {"error": "Invalid Method"})


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def vtupload(request, category, task_id, filename, dlfile):
    if enabledconf["vtupload"] and settings.VTDL_KEY:
        try:
            folder_name = False
            path = False
            if category in ("sample", "static"):
                path = os.path.join(CUCKOO_ROOT, "storage", "binaries", dlfile)
            elif category == "dropped":
                folder_name = "files"
            elif category in ("CAPE", "procdump"):
                folder_name = category

            if folder_name:
                path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, folder_name, filename)

            if not path or not _path_safe(path):
                return render(request, "error.html", {"error": f"File not found: {os.path.basename(path)}"})

            headers = {"x-apikey": settings.VTDL_KEY}
            files = {"file": (filename, open(path, "rb"))}
            response = requests.post("https://www.virustotal.com/api/v3/files", files=files, headers=headers)
            if response.ok:
                id = response.json().get("data", {}).get("id")
                if id:
                    hashbytes, _ = base64.b64decode(id).split(b":")
                    md5hash = hashbytes.decode()
                    return render(
                        request, "success_vtup.html", {"permalink": "https://www.virustotal.com/gui/file/{id}".format(id=md5hash)}
                    )
            else:
                return render(
                    request, "error.html", {"error": "Response code: {} - {}".format(response.status_code, response.reason)}
                )
        except Exception as err:
            return render(request, "error.html", {"error": err})


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def statistics_data(request, days=7):
    if days.isdigit():
        try:
            details = statistics(int(days))
        except Exception as e:
            # psycopg2.OperationalError
            print(e)
            return render(
                request, "error.html", {"error": "Please restart your database. Probably it had an update or it just down"}
            )
        return render(request, "statistics.html", {"statistics": details, "days": days})
    return render(request, "error.html", {"error": "Provide days as number"})


on_demand_config_mapper = {
    "bingraph": reporting_cfg,
    "flare_capa": processing_cfg,
    "vba2graph": processing_cfg,
    "xlsdeobf": processing_cfg,
    "strings": processing_cfg,
    "floss": processing_cfg,
}


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
def on_demand(request, service: str, task_id: str, category: str, sha256):
    """
    This aux function allows to generate some details on demand, this is specially useful for long running libraries and we don't need them in many cases due to scripted submissions
    @param service: Service for which we want to generate details
    @param task_id: ID of analysis
    @param category: Example: CAPE, procdump, etc
    @param sha256: file hash for which we want to generate details
    @return: redirect to the same webpage but with missed details included

    # 0. ensure that we not generating this data or data exist
    # 1. get file path
    # 2. call to func
    # 3. store results
    # 4. reload page
    """

    if service not in (
        "bingraph",
        "flare_capa",
        "vba2graph",
        "virustotal",
        "xlsdeobf",
        "strings",
        "floss",
    ) and not on_demand_config_mapper.get(service, {}).get(service, {}).get("on_demand"):
        return render(request, "error.html", {"error": "Not supported/enabled service on demand"})

    # Self Extracted support folder
    path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "selfextracted", sha256)

    if not path_exists(path):
        extractedfile = False
        if category == "static":
            path = os.path.join(ANALYSIS_BASE_PATH, "analyses", task_id, "binary")
            category = "target.file"
        elif category == "dropped":
            path = os.path.join(ANALYSIS_BASE_PATH, "analyses", task_id, "files", sha256)
        else:
            path = os.path.join(ANALYSIS_BASE_PATH, "analyses", task_id, category, sha256)
    else:
        category = "target.file"
        extractedfile = True

    if path and (not _path_safe(path) or not path_exists(path)):
        return render(request, "error.html", {"error": "File not found: {}".format(path)})

    details = False
    if service == "flare_capa" and HAVE_FLARE_CAPA:
        details = flare_capa_details(path, category.lower(), on_demand=True)
        if not details:
            details = {"msg": "No results"}

    elif service == "vba2graph" and HAVE_VBA2GRAPH:
        vba2graph_func(path, task_id, sha256, on_demand=True)

    elif service == "strings" and HAVE_STRINGS:
        details = extract_strings(path, on_demand=True)
        if not details:
            details = {"strings": "No strings extracted"}

    elif service == "virustotal" and HAVE_VIRUSTOTAL:
        details = vt_lookup("file", sha256, on_demand=True)
        if not details:
            details = {"msg": "No results"}

    elif service == "xlsdeobf" and HAVE_XLM_DEOBF:
        details = xlmdeobfuscate(path, task_id, on_demand=True)
        if not details:
            details = {"msg": "No results"}
    elif (
        service == "bingraph"
        and HAVE_BINGRAPH
        and reporting_cfg.bingraph.enabled
        and reporting_cfg.bingraph.on_demand
        and not path_exists(os.path.join(ANALYSIS_BASE_PATH, "analyses", task_id, "bingraph", sha256 + "-ent.svg"))
    ):
        bingraph_path = os.path.join(ANALYSIS_BASE_PATH, "analyses", task_id, "bingraph")
        if not path_exists(bingraph_path):
            path_mkdir(bingraph_path)
        try:
            bingraph_args_dict.update({"prefix": sha256, "files": [path], "save_dir": bingraph_path})
            try:
                bingraph_gen(bingraph_args_dict)
            except Exception as e:
                print("Can't generate bingraph for {}: {}".format(sha256, e))
        except Exception as e:
            print("Bingraph on demand error:", e)
    elif service == "floss" and HAVE_FLOSS:
        package = get_task_package(task_id)
        details = Floss(path, package, on_demand=True).run()
        if not details:
            details = {"msg": "No results"}
    if details:
        buf = mongo_find_one("analysis", {"info.id": int(task_id)}, {"_id": 1, category: 1})

        servicedata = {}
        if category == "CAPE":
            for block in buf[category].get("payloads", []) or []:
                if block.get("sha256") == sha256:
                    block[service] = details
                    break
            servicedata = buf[category]
        elif category in ("procdump", "procmemory", "dropped"):
            for block in buf[category] or []:
                if block.get("sha256") == sha256:
                    block[service] = details
                    break
            servicedata = buf[category]
        elif "target" in category:
            servicedata = buf.get("target", {}).get("file", {})
            if servicedata:
                if service == "xlsdeobf":
                    servicedata.setdefault("office", {}).setdefault("XLMMacroDeobfuscator", details)
                elif extractedfile:
                    for block in servicedata.get("extracted_files", []):
                        if block.get("sha256") == sha256:
                            block[service] = details
                            break
                else:
                    servicedata.setdefault(service, details)

        if servicedata:
            mongo_update_one("analysis", {"_id": ObjectId(buf["_id"])}, {"$set": {category: servicedata}})
        del details

    return redirect("report", task_id=task_id)


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def ban_all_user_tasks(request, user_id: int):
    if request.user.is_staff or request.user.is_superuser:
        db.ban_user_tasks(user_id)
        return HttpResponseRedirect(request.META.get("HTTP_REFERER", "/"))
    return render(request, "error.html", {"error": "Nice try! You don't have permission to ban user tasks"})


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def ban_user(request, user_id: int):
    if request.user.is_staff or request.user.is_superuser:
        success = disable_user(user_id)
        if success:
            return HttpResponseRedirect(request.META.get("HTTP_REFERER", "/"))
        else:
            return render(request, "error.html", {"error": f"Can't ban user id {user_id}"})
    return render(request, "error.html", {"error": "Nice try! You don't have permission to ban users"})


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def reprocess_task(request, task_id: int):
    if not settings.REPROCESS_TASKS:
        return HttpResponseRedirect(request.META.get("HTTP_REFERER", "/"))

    error, msg, _ = db.tasks_reprocess(task_id)
    if error:
        return render(request, "error.html", {"error": msg})
    else:
        return HttpResponseRedirect(request.META.get("HTTP_REFERER", "/"))
