# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function

import os
import sys
import zlib
import shutil
import json
import zipfile
import tempfile
import datetime
from io import BytesIO
from urllib.parse import quote

from django.conf import settings
from wsgiref.util import FileWrapper
from django.http import HttpResponse, StreamingHttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.views.decorators.http import require_safe
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
try:
    from django_ratelimit.decorators import ratelimit
except ImportError:
    try:
        from ratelimit.decorators import ratelimit
    except ImportError:
        print("missed dependency: pip3 install django-ratelimit -U")

from rest_framework.decorators import api_view

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, Task, TASK_PENDING
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT, ANALYSIS_BASE_PATH
from lib.cuckoo.common.web_utils import perform_malscore_search, perform_search, perform_ttps_search, my_rate_minutes, my_rate_seconds, rateblock, statistics
import modules.processing.network as network

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
    print("Missed dependency: pip3 install pyzipper -U")
    HAVE_PYZIPPER = False

TASK_LIMIT = 25

processing_cfg = Config("processing")
reporting_cfg = Config("reporting")

# On demand features
HAVE_FLARE_CAPA = False
if processing_cfg.flare_capa.on_demand:
    from lib.cuckoo.common.cape_utils import flare_capa_details, HAVE_FLARE_CAPA

HAVE_VBA2GRAPH = False
if processing_cfg.vba2graph.on_demand:
    from lib.cuckoo.common.cape_utils import vba2graph_func, HAVE_VBA2GRAPH


if reporting_cfg.bingraph.on_demand:
    try:
        from lib.cuckoo.common.graphs.binGraph.binGraph import generate_graphs as bingraph_gen
        from modules.reporting.bingraph import bingraph_args_dict
        HAVE_BINGRAPH = True
    except ImportError:
        HAVE_BINGRAPH = False
else:
    HAVE_BINGRAPH = False


# Used for displaying enabled config options in Django UI
enabledconf = dict()
for cfile in ["reporting", "processing", "auxiliary", "web"]:
    curconf = Config(cfile)
    confdata = curconf.get_config()
    for item in confdata:
        if "enabled" in confdata[item]:
            if confdata[item]["enabled"] == "yes":
                enabledconf[item] = True
            else:
                enabledconf[item] = False

if enabledconf["mongodb"]:
    import pymongo
    from bson.objectid import ObjectId

    results_db = pymongo.MongoClient(
        settings.MONGO_HOST, port=settings.MONGO_PORT, username=settings.MONGO_USER, password=settings.MONGO_PASS, authSource=settings.MONGO_DB
    )[settings.MONGO_DB]
es_as_db = False
essearch = False
if enabledconf["elasticsearchdb"]:
    from elasticsearch import Elasticsearch

    essearch = Config("reporting").elasticsearchdb.searchonly
    if not essearch:
        es_as_db = True
    baseidx = Config("reporting").elasticsearchdb.index
    fullidx = baseidx + "-*"
    es = Elasticsearch(hosts=[{"host": settings.ELASTIC_HOST, "port": settings.ELASTIC_PORT,}], timeout=60)

db = Database()

# Conditional decorator for web authentication
class conditional_login_required(object):
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)


def get_analysis_info(db, id=-1, task=None):
    if not task:
        task = db.view_task(id)
    if not task:
        return None

    new = task.to_dict()
    if new["category"] in ["file", "pcap", "static"] and new["sample_id"] != None:
        new["sample"] = db.view_sample(new["sample_id"]).to_dict()
        filename = os.path.basename(new["target"])
        new.update({"filename": filename})

    if "machine" in new and new["machine"]:
        machine = new["machine"]
        machine = machine.strip(".vmx")
        machine = os.path.basename(machine)
        new.update({"machine": machine})

    if enabledconf["mongodb"]:
        rtmp = results_db.analysis.find_one(
            {"info.id": int(new["id"])},
            {
                "info": 1,
                "virustotal_summary": 1,
                "info.custom": 1,
                "info.shrike_msg": 1,
                "malscore": 1,
                "detections": 1,
                "network.pcap_sha256": 1,
                "mlist_cnt": 1,
                "f_mlist_cnt": 1,
                "info.package": 1,
                "target.file.clamav": 1,
                "suri_tls_cnt": 1,
                "suri_alert_cnt": 1,
                "suri_http_cnt": 1,
                "suri_file_cnt": 1,
                "trid": 1,
                "_id": 0,
            },
            sort=[("_id", pymongo.DESCENDING)],
        )

    if es_as_db:
        rtmp = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % str(new["id"]))["hits"]["hits"]
        if len(rtmp) > 1:
            rtmp = rtmp[-1]["_source"]
        elif len(rtmp) == 1:
            rtmp = rtmp[0]["_source"]
        else:
            pass

    if rtmp:
        for keyword in (
            "detections",
            "virustotal_summary",
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

        if settings.MOLOCH_ENABLED:
            if settings.MOLOCH_BASE[-1] != "/":
                settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
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

    tasks_files = db.list_tasks(limit=TASK_LIMIT, offset=off, category="file", not_status=TASK_PENDING)
    tasks_files += db.list_tasks(limit=TASK_LIMIT, offset=off, category="static", not_status=TASK_PENDING)
    tasks_urls = db.list_tasks(limit=TASK_LIMIT, offset=off, category="url", not_status=TASK_PENDING)
    tasks_pcaps = db.list_tasks(limit=TASK_LIMIT, offset=off, category="pcap", not_status=TASK_PENDING)
    analyses_files = []
    analyses_urls = []
    analyses_pcaps = []

    # Vars to define when to show Next/Previous buttons
    paging = dict()
    paging["show_file_next"] = "show"
    paging["show_url_next"] = "show"
    paging["show_pcap_next"] = "show"
    paging["next_page"] = str(page + 1)
    paging["prev_page"] = str(page - 1)

    pages_files_num = 0
    pages_urls_num = 0
    pages_pcaps_num = 0
    tasks_files_number = db.count_matching_tasks(category="file", not_status=TASK_PENDING) or 0
    tasks_files_number += db.count_matching_tasks(category="static", not_status=TASK_PENDING) or 0
    tasks_urls_number = db.count_matching_tasks(category="url", not_status=TASK_PENDING) or 0
    tasks_pcaps_number = db.count_matching_tasks(category="pcap", not_status=TASK_PENDING) or 0
    if tasks_files_number:
        pages_files_num = int(tasks_files_number / TASK_LIMIT + 1)
    if tasks_urls_number:
        pages_urls_num = int(tasks_urls_number / TASK_LIMIT + 1)
    if tasks_pcaps_number:
        pages_pcaps_num = int(tasks_pcaps_number / TASK_LIMIT + 1)
    files_pages = []
    urls_pages = []
    pcaps_pages = []
    if pages_files_num < 11 or page < 6:
        files_pages = list(range(1, min(10, pages_files_num) + 1))
    elif page > 5:
        files_pages = list(range(min(page - 5, pages_files_num - 10) + 1, min(page + 5, pages_files_num) + 1))
    if pages_urls_num < 11 or page < 6:
        urls_pages = list(range(1, min(10, pages_urls_num) + 1))
    elif page > 5:
        urls_pages = list(range(min(page - 5, pages_urls_num - 10) + 1, min(page + 5, pages_urls_num) + 1))
    if pages_pcaps_num < 11 or page < 6:
        pcaps_pages = list(range(1, min(10, pages_pcaps_num) + 1))
    elif page > 5:
        pcaps_pages = list(range(min(page - 5, pages_pcaps_num - 10) + 1, min(page + 5, pages_pcaps_num) + 1))

    # On a fresh install, we need handle where there are 0 tasks.
    buf = db.list_tasks(limit=1, category="file", not_status=TASK_PENDING, order_by=Task.added_on.asc())
    if len(buf) == 1:
        first_file = db.list_tasks(limit=1, category="file", not_status=TASK_PENDING, order_by=Task.added_on.asc())[0].to_dict()["id"]
        paging["show_file_prev"] = "show"
    else:
        paging["show_file_prev"] = "hide"
    buf = db.list_tasks(limit=1, category="url", not_status=TASK_PENDING, order_by=Task.added_on.asc())
    if len(buf) == 1:
        first_url = db.list_tasks(limit=1, category="url", not_status=TASK_PENDING, order_by=Task.added_on.asc())[0].to_dict()["id"]
        paging["show_url_prev"] = "show"
    else:
        paging["show_url_prev"] = "hide"
    buf = db.list_tasks(limit=1, category="pcap", not_status=TASK_PENDING, order_by=Task.added_on.asc())
    if len(buf) == 1:
        first_pcap = db.list_tasks(limit=1, category="pcap", not_status=TASK_PENDING, order_by=Task.added_on.asc())[0].to_dict()["id"]
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

            if db.view_errors(task.id):
                new["errors"] = True

            analyses_files.append(new)
    else:
        paging["show_file_next"] = "hide"

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
    paging["urls_page_range"] = urls_pages
    paging["pcaps_page_range"] = pcaps_pages
    paging["current_page"] = page
    analyses_files.sort(key=lambda x: x["id"], reverse=True)
    return render(
        request,
        "analysis/index.html",
        {"files": analyses_files, "urls": analyses_urls, "pcaps": analyses_pcaps, "paging": paging, "config": enabledconf},
    )


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def pending(request):
    db = Database()
    tasks = db.list_tasks(inclide_hashes=True, status=TASK_PENDING)

    pending = []
    for task in tasks:
        pending.append({"target": task.target, "added_on": task.added_on, "category": task.category, "md5": task.sample.md5, "sha256": task.sample.sha256})

    return render(request, "analysis/pending.html", {"tasks": pending})


ajax_mongo_schema = {
    "CAPE": "CAPE",
    "CAPE_old": "CAPE",
    "dropped": "dropped",
    "debugger": "debugger",
    "behavior": "behavior",
    "network": "network",
    "procdump": "procdump",
}


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def load_files(request, task_id, category):
    """Filters calls for call category.
    @param task_id: cuckoo task id
    """
    #ToDo remove in CAPEv3
    if request.is_ajax() and category in ("CAPE", "CAPE_old", "dropped", "behavior", "debugger", "network", "procdump"):
        bingraph = False
        debugger_logs = dict()
        bingraph_dict_content = {}
        # Search calls related to your PID.
        if enabledconf["mongodb"]:
            if category in ("behavior", "debugger"):
                data = results_db.analysis.find_one({"info.id": int(task_id)}, {"behavior.processes": 1, "behavior.processtree": 1, "info.tlp": 1, "_id": 0},)
                if category == "debugger":
                    data["debugger"] = data["behavior"]
            elif category == "network":
                data = results_db.analysis.find_one({"info.id": int(task_id)}, {ajax_mongo_schema[category]: 1, "info.tlp": 1, "cif":1, "suricata":1, "_id": 0})
            else:
                data = results_db.analysis.find_one({"info.id": int(task_id)}, {ajax_mongo_schema[category]: 1, "info.tlp": 1, "_id": 0})

            if enabledconf["bingraph"]:
                bingraph_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "bingraph")
                if os.path.exists(bingraph_path):
                    if ajax_mongo_schema.get(category, "") in ("dropped", "procdump"):
                        for block in data.get(category, []):
                            print(block)
                            if not block.get("sha256"):
                                print("missed sha256", block)
                                continue
                            tmp_file = os.path.join(bingraph_path, block["sha256"] + "-ent.svg")
                            if os.path.exists(tmp_file):
                                with open(tmp_file, "r") as f:
                                    bingraph_dict_content.setdefault(block["sha256"], f.read())

                    if ajax_mongo_schema.get(category, "").startswith("CAPE"):
                        if isinstance(data.get("CAPE", {}), dict) and "payloads" in data.get("CAPE", {}):
                            cape_files = data.get("CAPE", {}).get("payloads", []) or []
                        #ToDo remove in CAPEv3
                        else:
                            cape_files = data.get("CAPE", []) or []
                        for block in cape_files:
                            if not block.get("sha256"):
                                continue
                            tmp_file = os.path.join(bingraph_path, block["sha256"] + "-ent.svg")
                            if os.path.exists(tmp_file):
                                with open(tmp_file, "r") as f:
                                    bingraph_dict_content.setdefault(block["sha256"], f.read())

                    if bingraph_dict_content:
                        bingraph = True
            if category == "debugger":
                debugger_log_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "debugger")
                if os.path.exists(debugger_log_path):
                    for log in os.listdir(debugger_log_path):
                        if not log.endswith(".log"):
                            continue
                        with open(os.path.join(debugger_log_path, log), "r") as f:
                            debugger_logs[int(log.strip(".log"))] = f.read()

        # ES isn't supported
        #ToDo remove in CAPEv3
        if category == "CAPE_old":
            page = "analysis/CAPE/index_old.html"
            category = "CAPE"
        else:
            page = "analysis/{}/index.html".format(category)

        ajax_response = {
            ajax_mongo_schema[category]: data.get(category, {}),
            "tlp": data.get("info").get("tlp", ""),
            "id": task_id,
            "bingraph": {"enabled": bingraph, "content": bingraph_dict_content},
            "config": enabledconf,
        }

        if category == "debugger":
            ajax_response["debugger_logs"] = debugger_logs
        elif category == "network":
            ajax_response["suricata"] = data.get("suricata", {})
            ajax_response["cif"] = data.get("cif", [])

        return render(request, page, ajax_response)

    else:
        raise PermissionDenied


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def chunk(request, task_id, pid, pagenum):
    try:
        pid, pagenum = int(pid), int(pagenum) - 1
    except:
        raise PermissionDenied

    if request.is_ajax():
        if enabledconf["mongodb"]:
            record = results_db.analysis.find_one(
                {"info.id": int(task_id), "behavior.processes.process_id": pid},
                {"behavior.processes.process_id": 1, "behavior.processes.calls": 1, "_id": 0},
            )

        if es_as_db:
            record = es.search(
                index=fullidx, doc_type="analysis", q='behavior.processes.process_id: "%s" and info.id:' '"%s"' % (pid, task_id)
            )["hits"]["hits"][0]["_source"]

        if not record:
            raise PermissionDenied

        process = None
        for pdict in record["behavior"]["processes"]:
            if pdict["process_id"] == pid:
                process = pdict

        if not process:
            raise PermissionDenied

        if pagenum >= 0 and pagenum < len(process["calls"]):
            objectid = process["calls"][pagenum]
            if enabledconf["mongodb"]:
                chunk = results_db.calls.find_one({"_id": ObjectId(objectid)})

            if es_as_db:
                chunk = es.search(index=fullidx, doc_type="calls", q='_id: "%s"' % objectid,)["hits"]["hits"][0]["_source"]
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
    if request.is_ajax():
        # Search calls related to your PID.
        if enabledconf["mongodb"]:
            record = results_db.analysis.find_one(
                {"info.id": int(task_id), "behavior.processes.process_id": int(pid)},
                {"behavior.processes.process_id": 1, "behavior.processes.calls": 1, "_id": 0},
            )
        if es_as_db:
            # print "info.id: \"%s\" and behavior.processes.process_id: \"%s\"" % (task_id, pid)
            record = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s" and behavior.processes.process_id: "%s"' % (task_id, pid),)["hits"]["hits"][0]["_source"]

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

        tid = int(tid)

        # Populate dict, fetching data from all calls and selecting only appropriate category/APIs.
        for call in process["calls"]:
            if enabledconf["mongodb"]:
                chunk = results_db.calls.find_one({"_id": call})
            if es_as_db:
                chunk = es.search(index=fullidx, doc_type="calls", q='_id: "%s"' % call)["hits"]["hits"][0]["_source"]
            for call in chunk["calls"]:
                # filter by call or tid
                if caller != "null" or tid != 0:
                    if call["caller"] == caller and call["thread_id"] == tid:
                        filtered_process["calls"].append(call)
                elif category == "all" or call["category"] == category:
                    if len(apis) > 0:
                        add_call = -1
                        for api in apis:
                            if call["api"].lower() == api:
                                if exclude is True:
                                    add_call = 0
                                else:
                                    add_call = 1
                                break
                        if (exclude == True and add_call != 0) or (exclude == False and add_call == 1):
                            filtered_process["calls"].append(call)
                    else:
                        filtered_process["calls"].append(call)

        return render(request, "analysis/behavior/_chunk.html", {"chunk": filtered_process})
    else:
        raise PermissionDenied


def gen_moloch_from_suri_http(suricata):
    if "http" in suricata and suricata["http"]:
        for e in suricata["http"]:
            if "srcip" in e and e["srcip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])), safe="")
            if "dstip" in e and e["dstip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])), safe="")
            if "dstport" in e and e["dstport"]:
                e["moloch_dst_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22tcp\x22" % (str(e["dstport"])), safe="")
                )
            if "srcport" in e and e["srcport"]:
                e["moloch_src_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22tcp\x22" % (str(e["srcport"])), safe="")
                )
            if "hostname" in e and e["hostname"]:
                e["moloch_http_host_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=host.http" + quote("\x3d\x3d\x22%s\x22" % (e["hostname"]), safe="")
                )
            if "uri" in e and e["uri"]:
                e["moloch_http_uri_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=http.uri" + quote("\x3d\x3d\x22%s\x22" % (e["uri"].encode("utf8")), safe="")
                )
            if "ua" in e and e["ua"]:
                e["moloch_http_ua_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=http.user-agent"
                    + quote("\x3d\x3d\x22%s\x22" % (e["ua"].encode("utf8")), safe="")
                )
            if "method" in e and e["method"]:
                e["moloch_http_method_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=http.method" + quote("\x3d\x3d\x22%s\x22" % (e["method"]), safe="")
                )
    return suricata


def gen_moloch_from_suri_alerts(suricata):
    if "alerts" in suricata and suricata["alerts"]:
        for e in suricata["alerts"]:
            if "srcip" in e and e["srcip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])), safe="")
            if "dstip" in e and e["dstip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])), safe="")
            if "dstport" in e and e["dstport"]:
                e["moloch_dst_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dstport"]), e["protocol"].lower()), safe="")
                )
            if "srcport" in e and e["srcport"]:
                e["moloch_src_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["srcport"]), e["protocol"].lower()), safe="")
                )
            if "sid" in e and e["sid"]:
                e["moloch_sid_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22suri_sid\x3a%s\x22" % (e["sid"]), safe="")
                )
            if "signature" in e and e["signature"]:
                e["moloch_msg_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=tags"
                    + quote("\x3d\x3d\x22suri_msg\x3a%s\x22" % (re.sub(r"[\W]", "_", e["signature"])), safe="")
                )
    return suricata


def gen_moloch_from_suri_file_info(suricata):
    if "files" in suricata and suricata["files"]:
        for e in suricata["files"]:
            if "srcip" in e and e["srcip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])), safe="")
            if "dstip" in e and e["dstip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])), safe="")
            if "dp" in e and e["dp"]:
                e["moloch_dst_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dp"]), "tcp"), safe="")
                )
            if "sp" in e and e["sp"]:
                e["moloch_src_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["sp"]), "tcp"), safe="")
                )
            if "http_uri" in e and e["http_uri"]:
                e["moloch_uri_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=http.uri" + quote("\x3d\x3d\x22%s\x22" % (e["http_uri"]), safe="")
                )
            if "http_host" in e and e["http_host"]:
                e["moloch_host_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=http.host" + quote("\x3d\x3d\x22%s\x22" % (e["http_host"]), safe="")
                )
            if "file_info" in e:
                if "clamav" in e["file_info"] and e["file_info"]["clamav"]:
                    e["moloch_clamav_url"] = (
                        settings.MOLOCH_BASE
                        + "?date=-1&expression=tags"
                        + quote("\x3d\x3d\x22clamav\x3a%s\x22" % (re.sub(r"[\W]", "_", e["file_info"]["clamav"])), safe="")
                    )
                if "md5" in e["file_info"] and e["file_info"]["md5"]:
                    e["moloch_md5_url"] = (
                        settings.MOLOCH_BASE
                        + "?date=-1&expression=tags"
                        + quote("\x3d\x3d\x22md5\x3a%s\x22" % (e["file_info"]["md5"]), safe="")
                    )
                if "sha256" in e["file_info"] and e["file_info"]["sha256"]:
                    e["moloch_sha256_url"] = (
                        settings.MOLOCH_BASE
                        + "?date=-1&expression=tags"
                        + quote("\x3d\x3d\x22sha256\x3a%s\x22" % (e["file_info"]["sha256"]), safe="")
                    )
                if "yara" in e["file_info"] and e["file_info"]["yara"]:
                    for sign in e["file_info"]["yara"]:
                        if "name" in sign:
                            sign["moloch_yara_url"] = (
                                settings.MOLOCH_BASE
                                + "?date=-1&expression=tags"
                                + quote("\x3d\x3d\x22yara\x3a%s\x22" % (sign["name"]), safe="")
                            )
    return suricata


def gen_moloch_from_suri_tls(suricata):
    if "tls" in suricata and suricata["tls"]:
        for e in suricata["tls"]:
            if "srcip" in e and e["srcip"]:
                e["moloch_src_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["srcip"])), safe="")
            if "dstip" in e and e["dstip"]:
                e["moloch_dst_ip_url"] = settings.MOLOCH_BASE + "?date=-1&expression=ip" + quote("\x3d\x3d%s" % (str(e["dstip"])), safe="")
            if "dstport" in e and e["dstport"]:
                e["moloch_dst_port_url"] = (
                    settings.MOLOCH_BASE
                    + "?date=-1&expression=port"
                    + quote("\x3d\x3d%s\x26\x26tags\x3d\x3d\x22%s\x22" % (str(e["dstport"]), "tcp"), safe="")
                )
            if "srcport" in e and e["srcport"]:
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
    report = results_db.analysis.find_one({"info.id": int(task_id)}, {"suricata.alerts": 1, "_id": 0}, sort=[("_id", pymongo.DESCENDING)])
    if not report:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"

        suricata = gen_moloch_from_suri_alerts(suricata)

    return render(request, "analysis/surialert.html", {"analysis": report, "config": enabledconf})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def shrike(request, task_id):
    shrike = results_db.analysis.find_one(
        {"info.id": int(task_id)},
        {"info.shrike_url": 1, "info.shrike_msg": 1, "info.shrike_sid": 1, "info.shrike_refer": 1, "_id": 0},
        sort=[("_id", pymongo.DESCENDING)],
    )
    if not shrike:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})

    return render(request, "analysis/shrike.html", {"shrike": shrike})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def surihttp(request, task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)}, {"suricata.http": 1, "_id": 0}, sort=[("_id", pymongo.DESCENDING)])
    if not report:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"

        suricata = gen_moloch_from_suri_http(suricata)

    return render(request, "analysis/surihttp.html", {"analysis": report, "config": enabledconf})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def suritls(request, task_id):
    report = results_db.analysis.find_one({"info.id": int(task_id)}, {"suricata.tls": 1, "_id": 0}, sort=[("_id", pymongo.DESCENDING)])
    if not report:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"

        suricata = gen_moloch_from_suri_tls(suricata)

    return render(request, "analysis/suritls.html", {"analysis": report, "config": enabledconf})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def surifiles(request, task_id):
    report = results_db.analysis.find_one(
        {"info.id": int(task_id)}, {"info.id": 1, "suricata.files": 1, "_id": 0}, sort=[("_id", pymongo.DESCENDING)]
    )
    if not report:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})

    suricata = report["suricata"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"

        suricata = gen_moloch_from_suri_file_info(suricata)

    return render(request, "analysis/surifiles.html", {"analysis": report, "config": enabledconf})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def antivirus(request, task_id):
    rtmp = results_db.analysis.find_one(
        {"info.id": int(task_id)}, {"virustotal": 1, "info.category": 1, "_id": 0}, sort=[("_id", pymongo.DESCENDING)]
    )
    if not rtmp:
        return render(request, "error.html", {"error": "The specified analysis does not exist"})
    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
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
        match = re.search("pid=(?P<search_pid>\d+)", query)
        if match:
            search_pid = int(match.group("search_pid"))
        match = re.search("tid=(?P<search_tid>\d+)", query)
        if match:
            search_tid = match.group("search_tid")

        if search_pid:
            query = query.replace("pid=" + str(search_pid), "")
        if search_tid:
            query = query.replace("tid=" + search_tid, "")

        query = query.strip()

        query = re.compile(query)

        # Fetch anaylsis report
        if enabledconf["mongodb"]:
            record = results_db.analysis.find_one({"info.id": int(task_id)}, {"behavior.processes": 1, "_id": 0})
        if es_as_db:
            esquery = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % task_id)["hits"]["hits"][0]
            esidx = esquery["_index"]
            record = esquery["_source"]

        # Loop through every process
        for process in record["behavior"]["processes"]:
            if search_pid and process["process_id"] != search_pid:
                continue

            process_results = []

            if enabledconf["mongodb"]:
                chunks = results_db.calls.find({"_id": {"$in": process["calls"]}})
            if es_as_db:
                # I don't believe ES has a similar function to MongoDB's $in
                # so we'll just iterate the call list and query appropriately
                chunks = list()
                for callitem in process["calls"]:
                    data = es.search(index=esidx, oc_type="calls", q="_id: %s" % callitem)["hits"]["hits"][0]["_source"]
                    chunks.append(data)

            for chunk in chunks:
                for call in chunk["calls"]:
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


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def report(request, task_id):
    network_report = False
    if enabledconf["mongodb"]:
        report = results_db.analysis.find_one({"info.id": int(task_id)}, {"dropped": 0, "CAPE.payloads": 0, "procdump": 0, "behavior.processes": 0, "network": 0}, sort=[("_id", pymongo.DESCENDING)])
        network_report = results_db.analysis.find_one({"info.id": int(task_id)}, {"network.domainlookups": 1, "network.iplookups": 1, "network.dns": 1, "network.hosts": 1}, sort=[("_id", pymongo.DESCENDING)])
    if es_as_db:
        query = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % task_id)["hits"]["hits"][0]
        report = query["_source"]
        # Extract out data for Admin tab in the analysis page
        esdata = {"index": query["_index"], "id": query["_id"]}
        report["es"] = esdata
    if not report:
        return render(request, "error.html", {"error": "The specified analysis does not exist or not finished yet"})

    if isinstance(report.get("CAPE"), dict) and report.get("CAPE", {}).get("configs", {}):
        report["malware_conf"] = report["CAPE"]["configs"]
    if enabledconf["compressresults"]:
        for keyword in ("CAPE", "procdump", "enhanced", "summary"):
            if report.get(keyword, False):
                try:
                    report[keyword] = json.loads(zlib.decompress(report[keyword]))
                except Exception:
                    pass
        if report.get("behavior", {}).get("summary", {}):
            try:
                report["behavior"]["summary"] = json.loads(zlib.decompress(report["behavior"]["summary"]))
            except Exception:
                pass
    children = 0
    if "CAPE_children" in report:
        children = report["CAPE_children"]

    try:
        report["dropped"] = list(
            results_db.analysis.aggregate([{"$match": {"info.id": int(task_id)}}, {"$project": {"_id": 0, "dropped_size": {"$size": "$dropped.sha256"}}}]))[0]["dropped_size"]
    except:
        report["dropped"] = 0

    try:
        tmp_data = list(results_db.analysis.aggregate([{"$match": {"info.id": int(task_id)}}, {"$project": {"_id": 0, "cape_size": {"$size": "$CAPE.payloads.sha256"}}}]))
        report["CAPE"] = tmp_data[0]["cape_size"]  or 0
        # ToDo remove in CAPEv3 *_old
        if not report["CAPE"]:
            tmp_data = list(results_db.analysis.aggregate([{"$match": {"info.id": int(task_id)}}, {"$project": {"_id": 0, "cape_size_old": {"$size": "$CAPE.sha256"}, "cape_conf_size_old": {"$size": "$CAPE.cape_config"}}}]))
            report["CAPE_old"] = tmp_data[0]["cape_size_old"] or tmp_data[0]["cape_conf_size_old"] or 0
    except Exception as e:
        print(e)
        report["CAPE"] = 0

    try:
        tmp_data = list(results_db.analysis.aggregate([{"$match": {"info.id": int(task_id)}}, {"$project": {"_id": 0, "procdump_size": {"$size": "$procdump.sha256"}}}]))
        report["procdump"] = tmp_data[0]["procdump_size"]  or 0
    except Exception as e:
        print(e)
        report["procdump_size"] = 0


    reports_exist = False
    reporting_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "reports")
    if os.path.exists(reporting_path) and os.listdir(reporting_path):
        reports_exist = True

    debugger_log_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "debugger")
    if os.path.exists(debugger_log_path) and os.listdir(debugger_log_path):
        report["debugger_logs"] = 1

    if settings.MOLOCH_ENABLED and "suricata" in report:
        suricata = report["suricata"]
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE = settings.MOLOCH_BASE + "/"
        report["moloch_url"] = (
            settings.MOLOCH_BASE + "?date=-1&expression=tags" + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE, task_id), safe="")
        )
        if isinstance(suricata, dict):
            suricata = gen_moloch_from_suri_http(suricata)
            suricata = gen_moloch_from_suri_alerts(suricata)
            suricata = gen_moloch_from_suri_file_info(suricata)
            suricata = gen_moloch_from_suri_tls(suricata)

    if settings.MOLOCH_ENABLED and "virustotal" in report:
        report["virustotal"] = gen_moloch_from_antivirus(report["virustotal"])

    vba2graph = processing_cfg.vba2graph.enabled
    vba2graph_svg_content = ""
    vba2graph_svg_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "vba2graph", "svg", "vba2graph.svg")
    if os.path.exists(vba2graph_svg_path):
        vba2graph_svg_content = open(vba2graph_svg_path, "rb").read().decode('utf8')

    bingraph = reporting_cfg.bingraph.enabled
    bingraph_dict_content = {}
    bingraph_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "bingraph")
    if os.path.exists(bingraph_path):
        for file in os.listdir(bingraph_path):
            tmp_file = os.path.join(bingraph_path, file)
            with open(tmp_file, "r") as f:
                bingraph_dict_content.setdefault(os.path.basename(tmp_file).split("-")[0], f.read())

    if network_report.get("network", {}):
        report["network"] = network_report["network"]

    return render(
        request,
        "analysis/report.html",
        {
            "analysis": report,
            "children": children,
            "domainlookups": network_report.get("network", {}).get("domainlookups", {}),
            "iplookups": network_report.get("network", {}).get("iplookups", {}),
            "settings": settings,
            "config": enabledconf,
            "reports_exist": reports_exist,
            "graphs": {
                "vba2graph": {"enabled": vba2graph, "content": vba2graph_svg_content},
                "bingraph": {"enabled": bingraph, "content": bingraph_dict_content},
            },
        },
    )


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@csrf_exempt
@api_view(['GET'])
def file_nl(request, category, task_id, dlfile):
    file_name = dlfile
    base_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
    path = False
    if category == "screenshot":
        file_name = file_name + ".jpg"
        path = os.path.join(base_path, "shots", file_name)
        cd = "image/jpeg"

    elif category == "bingraph":
        path = os.path.join(base_path, str(task_id), "bingraph", file_name + "-ent.svg")
        file_name = file_name + "-ent.svg"
        cd = "image/svg+xml"
    else:
        return render(request, "error.html", {"error": "Category not defined"})

    if path and not os.path.normpath(path).startswith(base_path):
        return render(request, "error.html", {"error": "File not found"})

    try:
        resp = StreamingHttpResponse(FileWrapper(open(path, "rb"), 8192), content_type=cd)
    except:
        return render(request, "error.html", {"error": "File {} not found".format(path)})

    resp["Content-Length"] = os.path.getsize(path)
    resp["Content-Disposition"] = "attachment; filename=" + file_name
    return resp

@require_safe
#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@csrf_exempt
@api_view(['GET'])
def file(request, category, task_id, dlfile):
    file_name = dlfile
    cd = ""
    mem_zip = False
    size = 0
    extmap = {
        "memdump": ".dmp",
        "memdumpstrings": ".dmp.strings",
    }

    if category == "sample":
        path = os.path.join(CUCKOO_ROOT, "storage", "binaries", dlfile)
    elif category in ("samplezip", "dropped", "droppedzip", "CAPE", "CAPEZIP", "procdump", "procdumpzip", "memdumpzip", "networkzip"):
        # ability to download password protected zip archives
        path = ""
        if category in ("sample", "samplezip"):
            path = os.path.join(CUCKOO_ROOT, "storage", "binaries", file_name)
        elif category in ("dropped", "droppedzip"):
            path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "files", file_name)
        elif category.startswith("CAPE"):
            buf = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "CAPE", file_name)
            if os.path.isdir(buf):
                dfile = min(os.listdir(buf), key=len)
                path = os.path.join(buf, dfile)
            else:
                path = buf
        elif category == "networkzip":
            buf = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "network", file_name)
            path = buf
        elif category.startswith("procdump"):
            path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "procdump", file_name)
        elif category.startswith("memdumpzip"):
            path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "memory", file_name + ".dmp")
            file_name += ".dmp"
        if path and not os.path.exists(path):
            return render(request, "error.html", {"error": "File {} not found".format(os.path.basename(path))})
        if category in ("samplezip", "droppedzip", "CAPEZIP", "procdumpzip", "memdumpzip", "networkzip"):
            if HAVE_PYZIPPER:
                mem_zip = BytesIO()
                with pyzipper.AESZipFile(mem_zip, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
                    zf.setpassword(settings.ZIP_PWD)
                    with open(path, "rb") as f:
                        zf.writestr(os.path.basename(path), f.read())
            else:
                return render(request, "error.html", {"error": "Missed pyzipper library"})
            file_name += ".zip"
            path = os.path.join(tempfile.gettempdir(), file_name)
            cd = "application/zip"
    elif category == "debugger_log":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "debugger", str(dlfile) + ".log")
    elif category == "rtf":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "rtf_objects", file_name)
    elif category == "pcap":
        file_name += ".pcap"
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "dump.pcap")
        cd = "application/vnd.tcpdump.pcap"
    elif category == "usage":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "aux", "usage.svg")
        file_name = "usage.svg"
        cd = "image/svg+xml"
    elif category in extmap:
        file_name += extmap[category]
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "memory", file_name)
        if not os.path.exists(path):
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
    elif category == "procdump":
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
        file_name = "file." + dlfile
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "logs", "files", file_name)
    elif category == "rtf":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "rtf_objects", file_name)
    else:
        return render(request, "error.html", {"error": "Category not defined"})

    if not cd:
        cd = "application/octet-stream"
    try:
        if category in ("samplezip", "droppedzip", "CAPEZIP", "procdumpzip", "memdumpzip", "networkzip"):
            if mem_zip:
                mem_zip.seek(0)
                resp = StreamingHttpResponse(mem_zip, content_type=cd)
                resp["Content-Length"] = len(mem_zip.getvalue())
        else:
            if not os.path.exists(path):
                 return render(request, "error.html", {"error": "File {} not found".format(os.path.basename(path))})
            resp = StreamingHttpResponse(FileWrapper(open(path, 'rb'), 8091), content_type=cd)
            resp["Content-Length"] = os.path.getsize(path)
        resp["Content-Disposition"] = "attachment; filename={0}".format(os.path.basename(path))
        return resp
    except Exception as e:
        print(e)
        return render(request, "error.html", {"error": "File {} not found".format(os.path.basename(path))})

    resp["Content-Length"] = size # os.path.getsize(path)
    resp["Content-Disposition"] = "attachment; filename=" + file_name
    if path.endswith(".zip") and os.path.exists(path):
        os.remove(path)
    return resp


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
def procdump(request, task_id, process_id, start, end):
    origname = process_id + ".dmp"
    tmpdir = None
    tmp_file_path = None
    response = False
    if enabledconf["mongodb"]:
        analysis = results_db.analysis.find_one({"info.id": int(task_id)}, {"procmemory": 1, "_id": 0}, sort=[("_id", pymongo.DESCENDING)])
    if es_as_db:
        analysis = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % task_id)["hits"]["hits"][0]["_source"]

    dumpfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "memory", origname)
    if not os.path.exists(dumpfile):
        dumpfile += ".zip"
        if not os.path.exists(dumpfile):
            return render(request, "error.html", {"error": "File not found"})
        f = zipfile.ZipFile(dumpfile, "r")
        tmpdir = tempfile.mkdtemp(prefix="capeprocdump_", dir=settings.TEMP_PATH)
        tmp_file_path = f.extract(origname, path=tmpdir)
        f.close()
        dumpfile = tmp_file_path
    try:
        file_item = open(dumpfile, "rb")
    except IOError:
        file_item = None

    file_name = "{0}_{1:x}.dmp".format(process_id, int(start, 16))

    if file_item and analysis and "procmemory" in analysis:
        for proc in analysis["procmemory"]:
            if proc["pid"] == int(process_id):
                s = BytesIO()
                for memmap in proc["address_space"]:
                    for chunk in memmap["chunks"]:
                        if int(chunk["start"], 16) >= int(start, 16) and int(chunk["end"], 16) <= int(end, 16):
                            file_item.seek(chunk["offset"])
                            s.write(file_item.read(int(chunk["size"], 16)))
                s.seek(0)
                size = len(s.getvalue())
                if size:
                    content_type = "application/octet-stream"
                    response = StreamingHttpResponse(s, content_type=content_type)
                    response["Content-Length"] = size
                    response["Content-Disposition"] = "attachment; filename={0}".format(file_name)
                    break


    if file_item:
        file_item.close()
    try:
        if tmp_file_path:
            os.unlink(tmp_file_path)
        if tmpdir:
            shutil.rmtree(tmpdir)
    except:
        pass

    if response:
        return response

    return render(request, "error.html", {"error": "File not found"})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
def filereport(request, task_id, category):
    formats = {
        "json": "report.json",
        "html": "report.html",
        "htmlsummary": "summary-report.html",
        "pdf": "report.pdf",
        "maec": "report.maec-4.1.xml",
        "maec5": "report.maec-5.0.json",
        "metadata": "report.metadata.xml",
        "misp": "misp.json",
    }

    if category in formats:
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "reports", formats[category])
        file_name = str(task_id) + "_" + formats[category]
        content_type = "application/octet-stream"

        if os.path.exists(file_path):
            response = HttpResponse(open(file_path, "rb").read(), content_type=content_type)
            response["Content-Disposition"] = "attachment; filename={0}".format(file_name)

            return response

        """
        elif enabledconf["distributed"]:
            # check for memdump on slave
            try:
                res = requests.get("http://127.0.0.1:9003/task/{task_id}".format(task_id=task_id), verify=False, timeout=30)
                if res and res.ok and res.json()["status"] == 1:
                    url = res.json()["url"]
                    dist_task_id = res.json()["task_id"]
                    return redirect(url.replace(":8090", ":8000")+"api/tasks/get/report/"+str(dist_task_id)+"/"+category+"/", permanent=True)
            except Exception as e:
                print(e)
        """
    return render(request, "error.html", {"error": "File not found"}, status=404)


@require_safe
@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def full_memory_dump_file(request, analysis_number):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp")
    if os.path.exists(file_path):
        filename = os.path.basename(file_path)
    elif os.path.exists(file_path + ".zip"):
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp.zip")
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
    elif enabledconf["distributed"]:
        # check for memdump on slave
        try:
            res = requests.get("http://127.0.0.1:9003/task/{task_id}".format(task_id=analysis_number), verify=False, timeout=30)
            if res and res.ok and res.json()["status"] == 1:
                url = res.json()["url"]
                dist_task_id = res.json()["task_id"]
                return redirect(url.replace(":8090", ":8000") + "api/tasks/get/fullmemory/" + str(dist_task_id) + "/", permanent=True)
        except Exception as e:
            print(e)
    if filename:
        content_type = "application/octet-stream"
        response = StreamingHttpResponse(FileWrapper(open(file_path), 8192), content_type=content_type)
        response["Content-Length"] = os.path.getsize(file_path)
        response["Content-Disposition"] = "attachment; filename=%s" % filename
        return response
    else:
        return render(request, "error.html", {"error": "File not found"})


@require_safe
@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def full_memory_dump_strings(request, analysis_number):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp.strings")
    filename = None
    if os.path.exists(file_path):
        filename = os.path.basename(file_path)
    else:
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(analysis_number), "memory.dmp.strings.zip")
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
    if filename:
        content_type = "application/octet-stream"
        response = StreamingHttpResponse(FileWrapper(open(file_path), 8192), content_type=content_type)
        response["Content-Length"] = os.path.getsize(file_path)
        response["Content-Disposition"] = "attachment; filename=%s" % filename
        return response
    else:
        return render(request, "error.html", {"error": "File not found"})


@csrf_exempt
@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def search(request):
    if "search" in request.POST:
        error = None

        try:
            term, value = request.POST["search"].strip().split(":", 1)
        except ValueError:
            term = ""
            value = request.POST["search"].strip()

        # Check on search size. But malscore can be a single digit number.
        if term != "malscore" and len(value) < 3:
            return render(request, "analysis/search.html", {"analyses": None, "term": request.POST["search"], "error": "Search term too short, minimum 3 characters required"},)

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
            elif re.match(r"^([a-fA-F\d]{128})$", value):
                term = "sha512"

        if term == "ids":
            if all([v.strip().isdigit() for v in value.split(",")]):
                value = [int(v.strip()) for v in filter(None, value.split(","))]
            else:
                return render(request, "analysis/search.html", {"analyses": None, "term": request.POST["search"], "error": "Not all values are integers"})

        try:
            if term == "malscore":
                records = perform_malscore_search(value)
            elif term == "ttp":
                records = perform_ttps_search(value)
            else:
                records = perform_search(term, value)
        except ValueError:
            if term:
                return render( request, "analysis/search.html", {"analyses": None, "term": request.POST["search"], "error": "Invalid search term: %s" % term},)
            else:
                return render(request, "analysis/search.html", {"analyses": None, "term": None, "error": "Unable to recognize the search syntax"})

        analyses = []
        for result in records or []:
            new = None
            if enabledconf["mongodb"] and enabledconf["elasticsearchdb"] and essearch and not term:
                new = get_analysis_info(db, id=int(result["_source"]["task_id"]))
            if enabledconf["mongodb"] and term:
                new = get_analysis_info(db, id=int(result["info"]["id"]))
            if es_as_db:
                new = get_analysis_info(db, id=int(result["_source"]["info"]["id"]))
            if not new:
                continue
            analyses.append(new)
        return render(
            request, "analysis/search.html", {"analyses": analyses, "config": enabledconf, "term": request.POST["search"], "error": None}
        )
    else:
        return render(request, "analysis/search.html", {"analyses": None, "term": None, "error": None})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def remove(request, task_id):
    """Remove an analysis.
    """
    if not enabledconf["delete"]:
        return render(request, "success_simple.html", {"message": "buy a lot of whyskey to admin ;)"})

    if enabledconf["mongodb"]:
        analyses = results_db.analysis.find({"info.id": int(task_id)}, {"_id": 1, "behavior.processes": 1})
        # Checks if more analysis found with the same ID, like if process.py was run manually.
        if analyses.count() > 1:
            message = "Multiple tasks with this ID deleted."
        elif analyses.count() == 1:
            message = "Task deleted."

        if analyses.count() > 0:
            # Delete dups too.
            for analysis in analyses:
                # Delete calls.
                for process in analysis.get("behavior", {}).get("processes", []):
                    for call in process["calls"]:
                        results_db.calls.remove({"_id": ObjectId(call)})
                # Delete analysis data.
                results_db.analysis.remove({"_id": ObjectId(analysis["_id"])})
            analyses_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id)
            if os.path.exists(analyses_path):
                shutil.rmtree(analyses_path)
        else:
            return render(request, "error.html", {"error": "The specified analysis does not exist"})
    if es_as_db:
        analyses = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % task_id)["hits"]["hits"]
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
                                index=esidx, doc_type="calls", id=call,
                            )
                # Delete the analysis results
                es.delete(
                    index=esidx, doc_type="analysis", id=esid,
                )
    elif essearch:
        # remove es search data
        analyses = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % task_id)["hits"]["hits"]
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
                    index=esidx, doc_type="analysis", id=esid,
                )

    db.delete_task(task_id)

    return render(request, "success_simple.html", {"message": message})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def pcapstream(request, task_id, conntuple):
    src, sport, dst, dport, proto = conntuple.split(",")
    sport, dport = int(sport), int(dport)

    if enabledconf["mongodb"]:
        conndata = results_db.analysis.find_one(
            {"info.id": int(task_id)},
            {"network.tcp": 1, "network.udp": 1, "network.sorted_pcap_sha256": 1, "_id": 0},
            sort=[("_id", pymongo.DESCENDING)],
        )

    if es_as_db:
        conndata = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % task_id)["hits"]["hits"][0]["_source"]

    if not conndata:
        return render(request, "standalone_error.html", {"error": "The specified analysis does not exist"})

    try:
        if proto == "udp":
            connlist = conndata["network"]["udp"]
        else:
            connlist = conndata["network"]["tcp"]

        conns = [i for i in connlist if (i["sport"], i["dport"], i["src"], i["dst"]) == (sport, dport, src, dst)]
        stream = conns[0]
        offset = stream["offset"]
    except:
        return render(request, "standalone_error.html", {"error": "Could not find the requested stream"})

    try:
        # This will check if we have a sorted PCAP
        test_pcap = conndata["network"]["sorted_pcap_sha256"]
        # if we do, build out the path to it
        pcap_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "dump_sorted.pcap")
        fobj = open(pcap_path, "rb")
    except Exception as e:
        # print str(e)
        return render(request, "standalone_error.html", {"error": "The required sorted PCAP does not exist"})

    packets = list(network.packets_for_stream(fobj, offset))
    fobj.close()

    return HttpResponse(json.dumps(packets), content_type="application/json")


@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def comments(request, task_id):
    if request.method == "POST" and settings.COMMENTS:
        comment = request.POST.get("commentbox", "")
        if not comment:
            return render(request, "error.html", {"error": "No comment provided."})

        if enabledconf["mongodb"]:
            report = results_db.analysis.find_one({"info.id": int(task_id)}, {"info.comments": 1, "_id": 0}, sort=[("_id", pymongo.DESCENDING)])
        if es_as_db:
            query = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % task_id)["hits"]["hits"][0]
            report = query["_source"]
            esid = query["_id"]
            esidx = query["_index"]
        if "comments" in report["info"]:
            curcomments = report["info"]["comments"]
        else:
            curcomments = list()
        buf = dict()
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
            results_db.analysis.update({"info.id": int(task_id)}, {"$set": {"info.comments": curcomments}}, upsert=False, multi=True)
        if es_as_db:
            es.update(index=esidx, doc_type="analysis", id=esid, body={"doc": {"info": {"comments": curcomments}}})
        return redirect("report", task_id=task_id)

    else:
        return render(request, "error.html", {"error": "Invalid Method"})


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def vtupload(request, category, task_id, filename, dlfile):
    if enabledconf["vtupload"] and settings.VTDL_PRIV_KEY:
        try:
            if category == "sample":
                path = os.path.join(CUCKOO_ROOT, "storage", "binaries", dlfile)
            elif category == "dropped":
                path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "files", filename)
            params = {"x-apikey": settings.VTDL_PRIV_KEY}
            files = {"file": (filename, open(path, "rb"))}
            response = requests.post("https://www.virustotal.com/api/v3/files", files=files, params=params)
            if response.ok:
                data = response.json().get("data", {})
                id = data.get("id")
                if id:
                    return render(request, "success_vtup.html", {"permalink": "https://www.virustotal.com/api/v3/analyses/{id}".format(id=id)})
                else:
                    return render(request, "error.html", {"error": "Response code: {}".format(response.json())})
        except Exception as err:
            return render(request, "error.html", {"error": err})
    else:
        return

@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def statistics_data(request, days=7):
    if days.isdigit():
        details = statistics(int(days))
        return render(request, "statistics.html", {"statistics": details, "days": days})
    else:
        return render(request, "error.html", {"error": "Provide days as number"})

on_demand_config_mapper = {
    "bingraph": reporting_cfg,
    "flare_capa": processing_cfg,
    "vba2graph": processing_cfg,
}

@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def on_demand(request, service: str, task_id: int, category: str, sha256):
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

    if service not in ("bingraph", "flare_capa", "vba2graph") and not on_demand_config_mapper.get(service, {}).get(service, {}).get("on_demand"):
        return render(request, "error.html", {"error": "Not supported/enabled service on demand"})

    if category == "static":
        path = os.path.join(ANALYSIS_BASE_PATH, str(task_id), "binary")
    else:
        path = os.path.join(ANALYSIS_BASE_PATH, str(task_id), category, sha256)

    if path and (not os.path.normpath(path).startswith(ANALYSIS_BASE_PATH) or not os.path.exists(path)):
        return render(request, "error.html", {"error": "File not found: {}".format(path)})

    details = False
    if service == "flare_capa" and HAVE_FLARE_CAPA:
        details = flare_capa_details(path, category.lower(), on_demand=True)

    elif service == "vba2graph" and HAVE_VBA2GRAPH:
        vba2graph_func(path, str(task_id), on_demand=True)

    elif service == "bingraph" and HAVE_BINGRAPH and reporting_cfg.bingraph.enabled and reporting_cfg.bingraph.on_demand and not os.path.exists(os.path.join(ANALYSIS_BASE_PATH, str(task_id), "bingraph", sha256+"-ent.svg")):
        bingraph_path = os.path.join(ANALYSIS_BASE_PATH, str(task_id), "bingraph")
        if not os.path.exists(bingraph_path):
            os.makedirs(bingraph_path)
        try:
            bingraph_args_dict.update({"prefix": sha256, "files": [path], "save_dir": bingraph_path})
            try:
                bingraph_gen(bingraph_args_dict)
            except Exception as e:
                print("Can't generate bingraph for {}: {}".format(sha256, e))
        except Exception as e:
            print("Bingraph on demand error:", e)

    if details:
        buf = results_db.analysis.find_one({"info.id": int(task_id)}, {"_id": 1, category: 1})
        if category == "CAPE":
            for block in buf[category].get("payloads", []) or []:
                if block.get("sha256") == sha256:
                    block[service] = details
                    break

        elif category == "static":
            if buf.get(category, {}):
                buf["static"][service] = details

        elif category == "procdump":
            for block in buf[category] or []:
                if block.get("sha256") == sha256:
                    block[service] = details
                    break

        results_db.analysis.update({"_id": ObjectId(buf["_id"])}, {"$set": {category: buf[category]}})
        del details

    return redirect("report", task_id=task_id)

