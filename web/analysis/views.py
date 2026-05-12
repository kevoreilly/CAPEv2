# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import collections
import datetime
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from contextlib import suppress
from functools import lru_cache
from io import BytesIO
from pathlib import Path
from urllib.parse import quote
from wsgiref.util import FileWrapper

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import BadRequest, PermissionDenied
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_safe
from rest_framework.authentication import SessionAuthentication
from rest_framework.decorators import api_view, authentication_classes

MONGO_DOCUMENT_TOO_LARGE_ERRORS = ()
try:
    from pymongo.errors import DocumentTooLarge

    MONGO_DOCUMENT_TOO_LARGE_ERRORS = (DocumentTooLarge,)
except ImportError:
    pass

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.common.pcap_utils import PcapToNg
import modules.processing.network as network
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import ANALYSIS_BASE_PATH, CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists, path_get_size, path_mkdir, path_read_file, path_safe
from lib.cuckoo.common.utils import delete_folder, yara_detected
from lib.cuckoo.common.web_utils import category_all_files, my_rate_minutes, my_rate_seconds, perform_search, rateblock, statistics
from lib.cuckoo.core.database import Database, TasksMixIn
from lib.cuckoo.core.data.task import TASK_PENDING, Task
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
integrations_cfg = Config("integrations")
web_cfg = Config("web")

try:
    # On demand features
    HAVE_FLARE_CAPA = False
    if integrations_cfg.flare_capa.on_demand:
        from lib.cuckoo.common.integrations.capa import HAVE_FLARE_CAPA, flare_capa_details
except (NameError, ImportError):
    print("Can't import FLARE-CAPA")

HAVE_STRINGS = False
if processing_cfg.strings.on_demand:
    from lib.cuckoo.common.integrations.strings import extract_strings

    HAVE_STRINGS = True

try:
    from evtx import PyEvtxParser

    HAVE_EVTX = True
except ImportError:
    HAVE_EVTX = False

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
if integrations_cfg.floss.on_demand:
    from lib.cuckoo.common.integrations.floss import HAVE_FLOSS, Floss

USE_SEVENZIP = False
if reporting_cfg.compression.compressiontool == "7zip":
    USE_SEVENZIP = True
    SEVENZIP_PATH = reporting_cfg.compression.sevenzippath.strip() or "/usr/bin/7z"

# Used for displaying enabled config options in Django UI
enabledconf = {}
on_demand_conf = {}
for cfile in ("integrations", "reporting", "processing", "auxiliary", "web", "distributed"):
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

db: TasksMixIn = Database()

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

    # Submitter-supplied free-form tags. Stored in postgres as one
    # comma-separated string; split (and trim) here so the list view can
    # render one badge per tag, matching the per-job report.
    raw_user_tags = get_tags_tasks([new["id"]]) or ""
    new.update({"user_task_tags": [t.strip() for t in raw_user_tags.split(",") if t.strip()]})

    # Submitter username for the "who submitted this task" column. user_id
    # 0 = anonymous; for any real user, look up the Django username
    # best-effort. Cheap enough per-task, not worth bulk-loading.
    submitter_username = ""
    user_id = new.get("user_id") or 0
    if user_id:
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            u = User.objects.filter(pk=user_id).only("username").first()
            if u:
                submitter_username = u.username
        except Exception:
            pass
    new["submitter_username"] = submitter_username

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
                "url.virustotal.summary": 1,
                "malscore": 1,
                "detections": 1,
                "network.pcap_sha256": 1,
                "mlist_cnt": 1,
                "f_mlist_cnt": 1,
                "target.file.clamav": 1,
                "target.file.cape_yara": 1,
                # The "YARA" column aggregates cape-emitted yara matches and
                # generic yara matches — tasks with only generic hits would
                # otherwise show null because cape_yara alone would be empty.
                "target.file.yara": 1,
                # File-level static fields (clamav, cape_yara, etc.) are
                # normalized out into a separate `files` collection keyed
                # by sha256; the denormalize_files mongo hook restores
                # them — but only if file_ref is in the projection. Pull
                # it explicitly so the hook can follow the reference.
                "target.file.file_ref": 1,
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
                "url.virustotal.summary",
                "malscore",
                "detections",
                "network.pcap_sha256",
                "mlist_cnt",
                "f_mlist_cnt",
                "target.file.clamav",
                "target.file.cape_yara",
                "target.file.yara",
                "target.file.file_ref",
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

        if "network" in rtmp and "pcap_sha256" in rtmp["network"]:
            new["pcap_sha256"] = rtmp["network"]["pcap_sha256"]

        if rtmp.get("target", {}).get("file", False):
            tfile = rtmp["target"]["file"]
            for keyword in ("clamav", "trid"):
                # Pre-existing bug: this used to read rtmp["info"][keyword]
                # which never exists — clamav / trid live under
                # target.file. So the column data never made it through.
                if tfile.get(keyword):
                    new[keyword] = tfile[keyword]
            # cape_yara and yara are lists of {"name": ..., "meta": {...}}
            # dicts. Merge them (preserving order, deduping by name) and
            # collapse to a list of names for the YARA column display —
            # tasks that only hit generic yara rules (no cape_yara) would
            # otherwise show null even though they have real YARA matches.
            seen_yara_names = set()
            yara_names = []
            for y in (tfile.get("cape_yara") or []) + (tfile.get("yara") or []):
                if not isinstance(y, dict):
                    continue
                n = y.get("name")
                if n and n not in seen_yara_names:
                    seen_yara_names.add(n)
                    yara_names.append(n)
            if yara_names:
                new["cape_yara"] = yara_names
            if tfile.get("virustotal", {}).get("summary", False):
                new["virustotal_summary"] = tfile["virustotal"]["summary"]

        if rtmp.get("url", {}).get("virustotal", {}).get("summary", False):
            new["virustotal_summary"] = rtmp["url"]["virustotal"]["summary"]

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

    tasks_files = db.list_tasks(limit=TASK_LIMIT, offset=off, category="file", not_status=TASK_PENDING, tags_tasks_not_like="audit")
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
            "title": "Recent Analysis",
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

    data = {"tasks": pending, "count": len(pending), "title": "Pending Tasks"}
    return render(request, "analysis/pending.html", data)


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


EVTX_LEVEL_MAP = {0: "Info", 1: "Critical", 2: "Error", 3: "Warning", 4: "Info", 5: "Verbose"}
EVTX_PAGE_SIZE = 100


def _evtx_member_display_name(member):
    name = os.path.splitext(member)[0].replace("%4", "/")
    # Strip snapshot prefix (e.g., "1_Security" -> "Security")
    if "_" in name:
        parts = name.split("_", 1)
        if parts[0].isdigit():
            name = parts[1]
    return name


def _flatten_evtx_detail(detail, prefix=""):
    items = []
    if isinstance(detail, dict):
        for key, value in detail.items():
            full_key = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, dict):
                items.extend(_flatten_evtx_detail(value, full_key))
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    item_key = f"{full_key}[{index}]"
                    if isinstance(item, dict):
                        items.extend(_flatten_evtx_detail(item, item_key))
                    else:
                        items.append({"key": item_key, "value": item})
            else:
                items.append({"key": full_key, "value": value})
    return items


def _compile_evtx_search_pattern(search_query):
    search_query = (search_query or "").strip()
    if not search_query:
        return None, ""

    try:
        return re.compile(search_query, re.IGNORECASE), ""
    except re.error as e:
        return None, str(e)


def _evtx_record_matches_search(search_pattern, raw_record):
    if not search_pattern:
        return True

    if not isinstance(raw_record, str):
        raw_record = str(raw_record)

    return bool(search_pattern.search(raw_record))


def _evtx_has_records(data):
    """Check if raw evtx file data contains any records by reading the header.
    EVTX header offset 24: NextRecordIdentifier (uint64). Starts at 1 for
    empty files, so > 1 means records exist."""
    if len(data) < 32 or data[:8] != b"ElfFile\x00":
        return False
    import struct
    next_record = struct.unpack_from("<Q", data, 24)[0]
    return next_record > 1


def _filetime_to_iso(ft):
    """Windows FILETIME (100-ns intervals since 1601-01-01) → ISO 8601 UTC.

    Most ETW providers we ingest emit FILETIME as either an int or a
    string-of-int. Anything that doesn't parse cleanly comes back as the
    raw value so the UI at least surfaces it. Negative deltas (clock
    skew, FILETIME=0 sentinels) yield empty string."""
    if ft in (None, ""):
        return ""
    try:
        ft = int(ft)
    except (TypeError, ValueError):
        return str(ft)
    if ft <= 0:
        return ""
    epoch_diff = 116444736000000000  # FILETIME ticks between 1601 and 1970
    micros = (ft - epoch_diff) // 10
    if micros < 0:
        return ""
    try:
        return datetime.datetime.utcfromtimestamp(micros / 1_000_000).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except (OSError, ValueError, OverflowError):
        return ""


def _build_pid_name_map(task_id):
    """PID → process-name lookup. Used by the ETW renderer to turn raw
    PIDs (which is all most ETW providers expose) into ``file.exe
    (4660)``-style display strings.

    Sources, richest to thinnest:
      1. ``behavior.processes`` — CAPE's API-monitor sees every process
         it instrumented, so this covers the malware-side processes
         most users care about.
      2. ``network_etw.connections_by_pid`` — sysmon + kernel-ETW;
         catches system processes (svchost, services) that the monitor
         doesn't instrument but that ETW logs against.
    Later sources fill in only PIDs the earlier ones didn't already
    name. Returns an empty dict when mongo isn't reachable.
    """
    if not enabledconf.get("mongodb"):
        return {}
    try:
        rec = mongo_find_one(
            "analysis",
            {"info.id": int(task_id)},
            {
                "behavior.processes.process_id": 1,
                "behavior.processes.process_name": 1,
                "behavior.processes.module_path": 1,
                "network_etw.connections_by_pid": 1,
                "_id": 0,
            },
        )
    except Exception:
        return {}
    rec = rec or {}
    out = {}
    for p in (rec.get("behavior", {}) or {}).get("processes", []) or []:
        pid = p.get("process_id")
        name = p.get("process_name") or ""
        if not name:
            mod = p.get("module_path") or ""
            name = mod.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if pid is not None and name:
            out[str(pid)] = name
    by_pid = (rec.get("network_etw", {}) or {}).get("connections_by_pid", {}) or {}
    for pid, info in by_pid.items():
        if str(pid) in out:
            continue
        name = info.get("process_name") or ""
        if not name:
            image = info.get("image", "") or ""
            name = image.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        if name:
            out[str(pid)] = name
    return out


def _load_etw_telemetry(task_id):
    """Read every ETW NDJSON / directory we collect in aux/ and project
    each into a per-source row shape suitable for tabular rendering.

    Returns a dict keyed by source name (`dns`, `network`, `wmi`,
    `threatintel`, `amsi`) — only includes keys whose underlying data
    file exists AND has at least one parseable record. The template
    iterates the dict to decide which sub-tabs to render.
    """
    base = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "aux")
    out = {
        "dns": [],
        "network": [],
        "wmi": [],
        "threatintel": [],
        # Drivers / devices the sample's processes touched via IRPs.
        # Deduped + noise-filtered so the BYOD signal isn't buried.
        "threatintel_drivers": [],
        # AllocVM events aggregated by (caller_pid, target_pid) — the
        # raw stream is firehose-noisy on self-process events.
        "threatintel_alloc_summary": [],
        "amsi": [],
    }
    pid_map = _build_pid_name_map(task_id)

    def _attach_proc(row, pid_field="pid"):
        pid = row.get(pid_field)
        if pid in (None, ""):
            row["process_name"] = ""
            return row
        row["process_name"] = pid_map.get(str(pid), "")
        return row

    def _iter_ndjson(path):
        if not path_exists(path) or os.path.getsize(path) == 0:
            return
        try:
            with open(path, "r", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            return

    # DNS-Client ETW — flat NDJSON, no per-record timestamp; use file order.
    for rec in _iter_ndjson(os.path.join(base, "dns_etw.json")):
        out["dns"].append(_attach_proc({
            "type": rec.get("QueryType", ""),
            "pid": rec.get("ProcessId", ""),
            "tid": rec.get("ThreadId", ""),
            "query": rec.get("QueryName", ""),
            "server": rec.get("DNS Server", ""),
        }))

    # Microsoft-Windows-Kernel-Network ETW — flat NDJSON with FILETIME.
    for rec in _iter_ndjson(os.path.join(base, "network_etw.json")):
        sip, sport = rec.get("src_ip", ""), rec.get("src_port", "")
        dip, dport = rec.get("dst_ip", ""), rec.get("dst_port", "")
        out["network"].append(_attach_proc({
            "time": _filetime_to_iso(rec.get("timestamp")),
            "pid": rec.get("pid", ""),
            "direction": rec.get("direction", ""),
            "protocol": rec.get("protocol", ""),
            "src": f"{sip}:{sport}" if sip else "",
            "dst": f"{dip}:{dport}" if dip else "",
            "event": rec.get("event_type", ""),
        }))

    # Microsoft-Windows-WMI-Activity ETW — events nested under `event.*`.
    for rec in _iter_ndjson(os.path.join(base, "wmi_etw.json")):
        ev = rec.get("event", {}) or {}
        hdr = ev.get("EventHeader", {}) or {}
        row = _attach_proc({
            "time": _filetime_to_iso(hdr.get("TimeStamp")),
            "pid": hdr.get("ProcessId", ""),
            "operation": ev.get("Operation", "") or ev.get("Task Name", ""),
            "namespace": ev.get("NamespaceName", ""),
            "user": ev.get("User", ""),
            "client_pid": ev.get("ClientProcessId", ""),
            "description": (ev.get("Description", "") or "")[:200],
        })
        # Resolve client_pid → name as a separate field; the WMI client
        # (i.e. who invoked WMI) is often more interesting than the
        # WMI provider's own PID.
        cp = row.get("client_pid")
        row["client_process_name"] = pid_map.get(str(cp), "") if cp not in ("", None) else ""
        out["wmi"].append(row)

    # Microsoft-Windows-Threat-Intelligence ETW — `[event_id, {event...}]`.
    # The provider is firehose-noisy: every process does VirtualAlloc
    # against itself constantly, and those events flood the JSON. The
    # signal is in the small subset that's either (a) cross-process
    # (CallingProcessId != TargetProcessId — classic injection
    # primitive) or (b) one of the few task names that don't fire on
    # benign self-ops (APC injection, thread-context, etc.). We split
    # the rendering into "suspicious" and "other" buckets so the
    # default view shows actionable events first.
    def _clean_iso(s):
        if not isinstance(s, str):
            return ""
        return s.replace("‎", "").replace("‏", "").strip()

    # Protection mask → symbolic name. Most-significant bit set ⇒
    # executable region (the high-signal flags for shellcode).
    _PROT_MAP = {
        0x01: "NOACCESS",
        0x02: "READONLY",
        0x04: "READWRITE",
        0x08: "WRITECOPY",
        0x10: "EXECUTE",
        0x20: "EXECUTE_READ",
        0x40: "EXECUTE_READWRITE",
        0x80: "EXECUTE_WRITECOPY",
    }
    def _prot_name(raw):
        try:
            v = int(str(raw), 0) if isinstance(raw, str) else int(raw)
        except (TypeError, ValueError):
            return ""
        # Mask off top-level page modifiers (GUARD/NOCACHE/WRITECOMBINE).
        base = v & 0xFF
        return _PROT_MAP.get(base, hex(v) if v else "")

    # Task names that are noise on self-process events. Anything outside
    # this set is rare enough that it's worth surfacing even when the
    # call is local.
    _NOISY_SELF_TASKS = {"KERNEL_THREATINT_TASK_ALLOCVM", "KERNEL_THREATINT_TASK_DRIVER_DEVICE"}

    # AllocationType bit-flags (MSDN VirtualAlloc).
    _ALLOC_FLAGS = [
        (0x00001000, "COMMIT"),
        (0x00002000, "RESERVE"),
        (0x00080000, "RESET"),
        (0x01000000, "RESET_UNDO"),
        (0x20000000, "LARGE_PAGES"),
        (0x00400000, "PHYSICAL"),
        (0x00100000, "TOP_DOWN"),
        (0x00200000, "WRITE_WATCH"),
    ]
    def _alloc_flags(raw):
        try:
            v = int(str(raw), 0) if isinstance(raw, str) else int(raw)
        except (TypeError, ValueError):
            return ""
        names = [name for bit, name in _ALLOC_FLAGS if v & bit]
        return "|".join(names) if names else (hex(v) if v else "")

    # Signature levels — short labels for the more interesting ones.
    # Source: SE_SIGNING_LEVEL_* enum in ntoskrnl. 0 (Unchecked) and
    # higher values up through 14 (Windows TCB / kernel-mode PPL).
    _SIG_LEVELS = {
        0: "Unchecked",
        1: "Unsigned",
        2: "Enterprise",
        3: "Custom-1",
        4: "Authenticode",
        5: "Custom-2",
        6: "Store",
        7: "Antimalware",
        8: "Microsoft",
        12: "Windows",
        14: "Windows-TCB",
    }
    def _sig_label(raw):
        try:
            v = int(raw)
        except (TypeError, ValueError):
            return ""
        # The TI provider packs the signature level into the low nibble
        # plus the section level into the high nibble — we only care
        # about the low one for the friendly label.
        return _SIG_LEVELS.get(v & 0x0F, str(v))

    # PPL protection levels — same idea (PsProtectedTypeNone, Light, Full).
    _PROT_TYPES = {
        0: "None",
        1: "Light",
        2: "Full",
    }
    _PROT_SIGNERS = {
        0: "None", 1: "Authenticode", 2: "CodeGen", 3: "Antimalware",
        4: "Lsa", 5: "Windows", 6: "WinTcb", 7: "WinSystem",
        8: "App",
    }
    def _ppl_label(raw):
        try:
            v = int(raw)
        except (TypeError, ValueError):
            return ""
        if v == 0:
            return "None"
        # Low 3 bits = type, next 4 bits = signer.
        ptype = v & 0x07
        signer = (v >> 4) & 0x0F
        return f"{_PROT_TYPES.get(ptype,'?')}-{_PROT_SIGNERS.get(signer,'?')}"

    def _vad_summary(ev, prefix):
        """Bundle the per-VAD fields the TI provider attaches alongside
        a virtual address (e.g., for ApcRoutine, ApcArgument1, Pc).
        Whether the address falls in a private RWX mapping vs a
        file-backed DLL is the smoking-gun signal for shellcode
        execution — flag that as `suspicious` when both conditions
        hold."""
        base = ev.get(f"{prefix}VadAllocationBase", "")
        prot_raw = ev.get(f"{prefix}VadAllocationProtect", "")
        region_type = ev.get(f"{prefix}VadRegionType", "")
        mmf = ev.get(f"{prefix}VadMmfName", "") or ""
        region_size = ev.get(f"{prefix}VadRegionSize", "")
        prot_name = _prot_name(prot_raw)
        non_file_backed = not mmf or mmf == "(null)"
        executable = "EXECUTE" in (prot_name or "")
        return {
            "alloc_base": base,
            "alloc_protect_raw": prot_raw,
            "alloc_protect": prot_name,
            "region_type": region_type,
            "region_size": region_size,
            "mmf_name": mmf,
            "suspicious": non_file_backed and executable,
        }

    for rec in _iter_ndjson(os.path.join(base, "threatintel_etw.json")):
        if not isinstance(rec, list) or len(rec) < 2:
            continue
        ev = rec[1] or {}
        hdr = ev.get("EventHeader", {}) or {}
        cp = ev.get("CallingProcessId", "")
        tp = ev.get("TargetProcessId", "")
        task_full = ev.get("Task Name", "")
        # Friendlier display name: drop the KERNEL_THREATINT_TASK_ prefix.
        task_short = task_full.removeprefix("KERNEL_THREATINT_TASK_") if task_full.startswith("KERNEL_THREATINT_TASK_") else task_full

        cross = bool(cp and tp and str(cp) != str(tp))
        suspicious = cross or task_full not in _NOISY_SELF_TASKS

        prot_raw = ev.get("ProtectionMask", "")
        evdesc = hdr.get("EventDescriptor", {}) or {}
        row = {
            "time": _filetime_to_iso(hdr.get("TimeStamp")),
            "task": task_short,
            "task_full": task_full,
            "event_id": evdesc.get("Id", ""),
            "calling_pid": cp,
            "target_pid": tp,
            "calling_create": _clean_iso(ev.get("CallingProcessCreateTime", "")),
            "base_address": ev.get("BaseAddress", ""),
            "region_size": ev.get("RegionSize", ""),
            "protection": prot_raw,
            "protection_name": _prot_name(prot_raw),
            "cross_process": cross,
            "suspicious": suspicious,
            # Extra fields for the click-to-expand detail panel ─────────
            "alloc_type_raw": ev.get("AllocationType", ""),
            "alloc_type": _alloc_flags(ev.get("AllocationType", "")),
            "calling_thread_id": ev.get("CallingThreadId", ""),
            "calling_thread_create": _clean_iso(ev.get("CallingThreadCreateTime", "")),
            "calling_sig_raw": ev.get("CallingProcessSignatureLevel", ""),
            "calling_sig": _sig_label(ev.get("CallingProcessSignatureLevel", "")),
            "target_sig_raw": ev.get("TargetProcessSignatureLevel", ""),
            "target_sig": _sig_label(ev.get("TargetProcessSignatureLevel", "")),
            "calling_ppl_raw": ev.get("CallingProcessProtection", ""),
            "calling_ppl": _ppl_label(ev.get("CallingProcessProtection", "")),
            "target_ppl_raw": ev.get("TargetProcessProtection", ""),
            "target_ppl": _ppl_label(ev.get("TargetProcessProtection", "")),
            "original_pid": ev.get("OriginalProcessId", ""),
            "kernel_thread_id": hdr.get("ThreadId", ""),
            "description": ev.get("Description", "") or "",
        }
        row["calling_process_name"] = pid_map.get(str(cp), "") if cp not in ("", None) else ""
        row["target_process_name"] = pid_map.get(str(tp), "") if tp not in ("", None) else ""
        # Trust delta: low-trust calling → higher-trust target = strong
        # signal regardless of cross_process. Tracks raw integer levels.
        try:
            cs = int(row["calling_sig_raw"]) & 0x0F if row["calling_sig_raw"] != "" else None
            ts = int(row["target_sig_raw"]) & 0x0F if row["target_sig_raw"] != "" else None
            if cs is not None and ts is not None and cs < ts and ts >= 6:
                row["trust_uplift"] = True
                # Trust uplift is also suspicious even if same-PID.
                row["suspicious"] = True
        except (TypeError, ValueError):
            pass

        # Task-specific extras — different operations carry different
        # fields. The detail panel renders whatever's set.
        if "QUEUEUSERAPC" in task_full:
            row["apc"] = {
                "routine": ev.get("ApcRoutine", ""),
                "routine_vad": _vad_summary(ev, "ApcRoutine"),
                "arg1": ev.get("ApcArgument1", ""),
                "arg1_vad": _vad_summary(ev, "ApcArgument1"),
                "arg2": ev.get("ApcArgument2", ""),
                "arg3": ev.get("ApcArgument3", ""),
                "target_thread_id": ev.get("TargetThreadId", ""),
                "target_thread_alertable": ev.get("TargetThreadAlertable", ""),
                "target_thread_create": _clean_iso(ev.get("TargetThreadCreateTime", "")),
            }
            # Either VAD landing in private RWX = strong injection signal.
            if row["apc"]["routine_vad"]["suspicious"] or row["apc"]["arg1_vad"]["suspicious"]:
                row["rwx_landing"] = True
        elif "SETTHREADCONTEXT" in task_full:
            row["thread_ctx"] = {
                "pc": ev.get("Pc", ""),
                "pc_vad": _vad_summary(ev, "Pc"),
                "sp": ev.get("Sp", ""),
                "lr": ev.get("Lr", ""),
                "fp": ev.get("Fp", ""),
                "context_flags": ev.get("ContextFlags", ""),
                "context_mask": ev.get("ContextMask", ""),
                "regs": [(f"R{i}", ev.get(f"Reg{i}", "")) for i in range(8)
                         if ev.get(f"Reg{i}", "") not in ("", None)],
                "target_thread_id": ev.get("TargetThreadId", ""),
                "target_thread_create": _clean_iso(ev.get("TargetThreadCreateTime", "")),
            }
            if row["thread_ctx"]["pc_vad"]["suspicious"]:
                row["rwx_landing"] = True
        elif "DRIVER_DEVICE" in task_full:
            row["driver_device"] = {
                "device_name": ev.get("DeviceName", ""),
                "driver_name": ev.get("DriverName", ""),
            }
            # Sketchy device names that aren't the common networking
            # / pipe stack — surface as suspicious.
            dev = (row["driver_device"]["device_name"] or "").lower()
            sketchy_devices = ("physicalmemory", "msr", "memorydiagnostics", "process",
                               "ntfs", "rawcdrom", "directx")
            if any(s in dev for s in sketchy_devices):
                row["suspicious"] = True
        out["threatintel"].append(row)

    # Post-process the firehose into two compact, high-signal views.
    #
    # 1. Drivers / Devices Accessed — dedup the DRIVER_DEVICE stream by
    #    (driver_name, device_name) and tag system-noise drivers
    #    (filter manager, raw FS) as `system_noise=True` so the template
    #    can collapse them. This is where BYOD jumps out: a non-system
    #    driver name in this list is almost always interesting.
    # 2. AllocVM summary — aggregate by (caller_pid, target_pid) so the
    #    1500+ same-process allocations collapse to one row per pair,
    #    with running counts of cross-process / RWX / large allocations.
    _SYSTEM_DRIVER_NOISE = {
        r"\driver\fltmgr",
        r"\driver\mountmgr",
        r"\driver\null",
        r"\driver\nsi",
        r"\filesystem\fltmgr",
        r"\filesystem\raw",
        r"\filesystem\ntfs",
        r"\filesystem\fastfat",
    }
    drivers_seen = {}
    alloc_pairs = {}
    for row in out["threatintel"]:
        tf = row.get("task_full", "")
        if "DRIVER_DEVICE" in tf:
            dd = row.get("driver_device") or {}
            drv = (dd.get("driver_name") or "").strip()
            dev = (dd.get("device_name") or "").strip()
            key = (drv.lower(), dev.lower())
            if key in drivers_seen:
                e = drivers_seen[key]
                e["hit_count"] += 1
                if row.get("calling_pid") not in e["pids"]:
                    e["pids"].append(row["calling_pid"])
            else:
                drivers_seen[key] = {
                    "driver_name": drv,
                    "device_name": dev,
                    "hit_count": 1,
                    "pids": [row.get("calling_pid")],
                    "system_noise": drv.lower() in _SYSTEM_DRIVER_NOISE,
                    "first_seen": row.get("time"),
                    "calling_process_name": row.get("calling_process_name", ""),
                }
        elif "ALLOCVM" in tf:
            cp = row.get("calling_pid") or "?"
            tp = row.get("target_pid") or "?"
            key = (str(cp), str(tp))
            entry = alloc_pairs.setdefault(
                key,
                {
                    "calling_pid": cp,
                    "target_pid": tp,
                    "calling_process_name": row.get("calling_process_name", ""),
                    "target_process_name": row.get("target_process_name", ""),
                    "count": 0,
                    "cross_process": str(cp) != str(tp),
                    "rwx": 0,
                    "large": 0,
                    "min_size": None,
                    "max_size": 0,
                    "first_seen": row.get("time"),
                },
            )
            entry["count"] += 1
            try:
                rs = int(str(row.get("region_size") or 0), 0) if isinstance(row.get("region_size"), str) else int(row.get("region_size") or 0)
            except (TypeError, ValueError):
                rs = 0
            if rs:
                if entry["min_size"] is None or rs < entry["min_size"]:
                    entry["min_size"] = rs
                if rs > entry["max_size"]:
                    entry["max_size"] = rs
                if rs >= 256 * 1024:
                    entry["large"] += 1
            # Only count RWX (PAGE_EXECUTE_READWRITE = 0x40) for cross-
            # process pairs. Same-process RWX counts get polluted on
            # CAPE-instrumented hosts because capemon's own hooking
            # creates RWX trampolines in every monitored process — so a
            # per-pid RWX tally for self pairs ends up close to 100%
            # and tells us nothing about the sample's behaviour. RWX
            # in *another* process's address space is the genuinely
            # interesting injection signal.
            if entry["cross_process"]:
                try:
                    pm = int(str(row.get("protection") or 0), 0) if isinstance(row.get("protection"), str) else int(row.get("protection") or 0)
                except (TypeError, ValueError):
                    pm = 0
                if pm == 0x40:
                    entry["rwx"] += 1

    # Sort drivers: non-noise first (alphabetical), then noise.
    out["threatintel_drivers"] = sorted(
        drivers_seen.values(),
        key=lambda d: (d["system_noise"], d["driver_name"].lower()),
    )
    # Sort alloc summary: cross-process pairs first, then by count desc.
    out["threatintel_alloc_summary"] = sorted(
        alloc_pairs.values(),
        key=lambda a: (not a["cross_process"], -a["count"]),
    )

    # Filter the per-event list down to genuine signal — drop self-process
    # noise AllocVMs (which is ~99% of the volume) and noise DRIVER_DEVICE
    # rows now that they're aggregated above. Anything cross-process,
    # trust-uplifted, RWX-landing, or with a non-noise task name stays.
    def _keep_event(r):
        tf = r.get("task_full", "")
        if "ALLOCVM" in tf:
            return bool(
                r.get("cross_process")
                or r.get("rwx_landing")
                or r.get("trust_uplift")
                or r.get("suspicious") is True
                and (r.get("cross_process") or r.get("rwx_landing"))
            )
        if "DRIVER_DEVICE" in tf:
            # Aggregated above — only keep individual rows for sketchy
            # devices (already marked `suspicious`) so the analyst can
            # see the calling thread / time per access.
            dd = r.get("driver_device") or {}
            if (dd.get("driver_name") or "").lower() in _SYSTEM_DRIVER_NOISE:
                return False
            return r.get("suspicious", False)
        return True
    out["threatintel"] = [r for r in out["threatintel"] if _keep_event(r)]

    # AMSI ETW — `aux/amsi_etw/amsi.jsonl` is the canonical event stream
    # (one AMSI scan per JSON line). Every record carries `appname`,
    # `contentname`, `contentsize`, `hash`, and a `dump_path` that
    # points to a per-buffer file in the same directory containing the
    # actual scanned content (PowerShell/VBScript/JScript body, .NET
    # IL bytes, etc.). We read the JSONL for metadata and resolve each
    # dump_path to load the real script body for the expandable view.
    #
    # Older deployments without the JSONL fall back to a dir scan, but
    # in that case we have no metadata so we can only show hash + body.
    AMSI_MAX_BYTES = 5 * 1024 * 1024
    amsi_dir = os.path.join(base, "amsi_etw")
    amsi_jsonl = os.path.join(amsi_dir, "amsi.jsonl")
    analysis_root = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))

    def _read_blob(rel_or_abs):
        # dump_path is recorded as `aux/amsi_etw/<sha>.txt` (relative to
        # the analysis root). Anchor it there and refuse anything that
        # tries to escape.
        candidate = os.path.normpath(os.path.join(analysis_root, rel_or_abs))
        if not candidate.startswith(analysis_root + os.sep):
            return "", 0, False
        try:
            sz = os.path.getsize(candidate)
            with open(candidate, "r", errors="replace") as fh:
                body = fh.read(AMSI_MAX_BYTES)
            return body, sz, sz > AMSI_MAX_BYTES
        except OSError:
            return "", 0, False

    seen_blob_paths = set()
    if os.path.isfile(amsi_jsonl):
        for rec in _iter_ndjson(amsi_jsonl):
            hdr = rec.get("EventHeader", {}) or {}
            dump_path = rec.get("dump_path", "")
            body, body_size, truncated = ("", 0, False)
            if dump_path:
                body, body_size, truncated = _read_blob(dump_path)
                seen_blob_paths.add(os.path.basename(dump_path))
            row = _attach_proc({
                "time": _filetime_to_iso(hdr.get("TimeStamp")),
                "pid": hdr.get("ProcessId", ""),
                "app": rec.get("appname", ""),
                "content_name": rec.get("contentname", "") or "(inline scriptblock)",
                "content_size": rec.get("contentsize", "") or rec.get("originalsize", ""),
                "hash": rec.get("hash", ""),
                "scan_status": rec.get("scanStatus", ""),
                "scan_result": rec.get("scanResult", ""),
                "body": body,
                "body_size": body_size,
                "truncated": truncated,
            })
            out["amsi"].append(row)

    # Orphan-blob pass — pick up any `<sha256>.txt` file in the dir that
    # the JSONL didn't reference (older runs without amsi.jsonl, or
    # blobs whose metadata was lost). Render with whatever we know
    # (sha + body) so they're not invisible.
    if os.path.isdir(amsi_dir):
        for fname in sorted(os.listdir(amsi_dir)):
            if fname == "amsi.jsonl" or fname in seen_blob_paths:
                continue
            full = os.path.join(amsi_dir, fname)
            if not os.path.isfile(full):
                continue
            try:
                sz = os.path.getsize(full)
                with open(full, "r", errors="replace") as fh:
                    body = fh.read(AMSI_MAX_BYTES)
            except OSError:
                continue
            out["amsi"].append({
                "time": "",
                "pid": "",
                "process_name": "",
                "app": "(orphan blob)",
                "content_name": "(no JSONL metadata)",
                "content_size": str(sz),
                "hash": fname.rsplit(".", 1)[0],
                "scan_status": "",
                "scan_result": "",
                "body": body,
                "body_size": sz,
                "truncated": sz > AMSI_MAX_BYTES,
            })

    # Drop empty sources so the template doesn't render hollow tabs.
    return {k: v for k, v in out.items() if v}


def _list_evtx_members(zip_path):
    """List safe EVTX members from an archive, grouped by channel.
    Snapshot-prefixed files (e.g., 1_Security.evtx, 2_Security.evtx) are
    grouped under one channel entry. Channels where no file contains any
    records are excluded."""
    channel_members = {}
    channel_has_records = {}
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for member in zf.namelist():
                normalized = member.replace("\\", "/")
                if normalized != os.path.basename(normalized):
                    continue
                if not normalized.lower().endswith(".evtx"):
                    continue
                channel = _evtx_member_display_name(normalized)
                if channel not in channel_members:
                    channel_members[channel] = []
                    channel_has_records[channel] = False
                channel_members[channel].append(normalized)
                if not channel_has_records[channel]:
                    # Read just the first 32 bytes to check the header
                    header = zf.read(member)[:32]
                    if _evtx_has_records(header):
                        channel_has_records[channel] = True
    except Exception:
        return []

    members = []
    for channel, member_list in sorted(channel_members.items()):
        if not channel_has_records.get(channel, False):
            continue
        member_list.sort()
        members.append({
            "member": member_list[0],
            "members": member_list,
            "channel": channel,
        })
    return members


@lru_cache(maxsize=128)
def _load_evtx_noise_filters():
    """Load analyzer noise filter sets from sigma filters config."""
    parents = set()
    images = set()
    paths = set()
    try:
        for fp in ["data/sigma/filters_local.json", "data/sigma/filters.json"]:
            full = os.path.join(CUCKOO_ROOT, fp)
            if os.path.exists(full):
                with open(full) as f:
                    data = json.load(f)
                pf = data.get("pre_filters", {})
                for p in pf.get("exclude_parent_processes", []):
                    parents.add(p.lower())
                for p in pf.get("exclude_image_processes", []):
                    images.add(p.lower())
                for p in pf.get("exclude_target_paths", []):
                    paths.add(p.lower())
    except Exception:
        pass
    if not parents:
        parents = {"icacls.exe", "python.exe", "wevtutil.exe"}
    if not images:
        images = {"wevtutil.exe", "conhost.exe"}
    return parents, images, paths


def _load_evtx_channel_page_cached(zip_path, member, page, page_size, mtime, search_query=""):
    del mtime
    events = []
    total_events = 0
    search_pattern, search_error = _compile_evtx_search_pattern(search_query)
    if search_error:
        return {
            "member": member,
            "channel": _evtx_member_display_name(member),
            "events": [],
            "page": 1,
            "page_size": page_size,
            "total_events": 0,
            "total_pages": 0,
            "search_query": search_query,
            "error": f"Invalid regex: {search_error}",
        }

    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Find all members for this channel (handles snapshot-prefixed names)
            channel = _evtx_member_display_name(member)
            members_to_extract = []
            for m in zf.namelist():
                if _evtx_member_display_name(m) == channel and m.lower().endswith(".evtx"):
                    members_to_extract.append(m)
            if not members_to_extract:
                raise ValueError(f"No EVTX members found for channel: {channel}")
            members_to_extract.sort(key=lambda x: int(x.split("_")[0]) if "_" in x and x.split("_")[0].isdigit() else x)

            real_tmpdir = os.path.realpath(tmpdir)
            for m in members_to_extract:
                normalized = m.replace("\\", "/")
                if normalized != os.path.basename(normalized):
                    continue
                target = os.path.realpath(os.path.join(tmpdir, normalized))
                if not target.startswith(real_tmpdir + os.sep) and target != real_tmpdir:
                    continue
                zf.extract(normalized, tmpdir)

        # Parse all extracted evtx files for this channel in order (preserving numeric sort)
        evtx_paths = [
            os.path.join(tmpdir, m) for m in members_to_extract
            if os.path.exists(os.path.join(tmpdir, m))
        ]

        # Chain records from all snapshot files
        def _iter_all_records():
            for ep in evtx_paths:
                try:
                    p = PyEvtxParser(ep)
                    yield from p.records_json()
                except Exception:
                    pass

        parser_iter = _iter_all_records()
        start_index = max(page - 1, 0) * page_size
        end_index = start_index + page_size

        _ANALYZER_PARENTS, _ANALYZER_IMAGES, _ANALYZER_PATHS = _load_evtx_noise_filters()

        for record in parser_iter:
            try:
                evt = json.loads(record["data"])
            except (json.JSONDecodeError, KeyError, TypeError):
                total_events += 1
                continue

            event_data = evt.get("Event", {})

            skip = False
            # Skip events from the CAPE analyzer process
            _ed = event_data.get("EventData", {})
            if isinstance(_ed, dict):
                _parent = _ed.get("ParentProcessName", "")
                if isinstance(_parent, str):
                    _pname = _parent.rsplit("\\", 1)[-1].lower()
                    if _pname in _ANALYZER_PARENTS:
                        continue
                _image = _ed.get("Image", "")
                if isinstance(_image, str):
                    _iname = _image.rsplit("\\", 1)[-1].lower()
                    if _iname in _ANALYZER_IMAGES:
                        continue
                _target = _ed.get("TargetFilename", _ed.get("TargetFileName", ""))
                if isinstance(_target, str) and _target:
                    _tlow = _target.lower()
                    for _ep in _ANALYZER_PATHS:
                        if _ep in _tlow:
                            skip = True
                            break
                    if skip:
                        continue

            if not _evtx_record_matches_search(search_pattern, record.get("data", "")):
                continue

            total_events += 1
            index = total_events - 1
            if index < start_index or index >= end_index:
                continue

            try:
                system = event_data.get("System", {})

                event_id_raw = system.get("EventID", "")
                if isinstance(event_id_raw, dict):
                    event_id = event_id_raw.get("#text", 0)
                else:
                    event_id = event_id_raw

                level_num = system.get("Level", 4)
                try:
                    level_num = int(level_num)
                except (TypeError, ValueError):
                    level_num = 4
                level = EVTX_LEVEL_MAP.get(level_num, "Info")

                time_created = system.get("TimeCreated", {})
                if isinstance(time_created, dict):
                    timestamp = time_created.get("#attributes", {}).get("SystemTime", "")
                else:
                    timestamp = str(time_created)

                provider = system.get("Provider", {})
                if isinstance(provider, dict):
                    provider_name = provider.get("#attributes", {}).get("Name", "")
                else:
                    provider_name = str(provider)

                detail = event_data.get("EventData", event_data.get("UserData", {}))
                flat_detail = _flatten_evtx_detail(detail)
                events.append(
                    {
                        "timestamp": timestamp,
                        "event_id": event_id,
                        "level": level,
                        "level_num": level_num,
                        "provider": provider_name,
                        "computer": system.get("Computer", ""),
                        "detail": detail,
                        "flat_detail": flat_detail,
                        "detail_summary": "; ".join(f"{item['key']}={item['value']}" for item in flat_detail),
                    }
                )
            except (json.JSONDecodeError, KeyError, TypeError):
                continue

    return {
        "member": member,
        "channel": _evtx_member_display_name(member),
        "events": events,
        "page": page,
        "page_size": page_size,
        "total_events": total_events,
        "total_pages": (total_events + page_size - 1) // page_size,
        "search_query": search_query,
    }


@lru_cache(maxsize=256)
def _count_evtx_channel_events_cached(zip_path, member, mtime):
    """Count events for a channel, applying the same noise filters as the page loader."""
    del mtime
    if not HAVE_EVTX:
        return None

    _ANALYZER_PARENTS, _ANALYZER_IMAGES, _ANALYZER_PATHS = _load_evtx_noise_filters()

    count = 0
    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(zip_path, "r") as zf:
            channel = _evtx_member_display_name(member)
            members_to_extract = []
            for m in zf.namelist():
                if _evtx_member_display_name(m) == channel and m.lower().endswith(".evtx"):
                    members_to_extract.append(m)
            if not members_to_extract:
                raise ValueError(f"No EVTX members found for channel: {channel}")
            members_to_extract.sort()

            real_tmpdir = os.path.realpath(tmpdir)
            for m in members_to_extract:
                normalized = m.replace("\\", "/")
                if normalized != os.path.basename(normalized):
                    continue
                target = os.path.realpath(os.path.join(tmpdir, normalized))
                if not target.startswith(real_tmpdir + os.sep) and target != real_tmpdir:
                    continue
                zf.extract(normalized, tmpdir)

        evtx_paths = sorted(
            os.path.join(tmpdir, m) for m in members_to_extract
            if os.path.exists(os.path.join(tmpdir, m))
        )

        for ep in evtx_paths:
            try:
                p = PyEvtxParser(ep)
                for record in p.records_json():
                    try:
                        evt = json.loads(record["data"])
                    except (json.JSONDecodeError, KeyError, TypeError):
                        count += 1
                        continue

                    event_data = evt.get("Event", {})
                    _ed = event_data.get("EventData", {})
                    if isinstance(_ed, dict):
                        _parent = _ed.get("ParentProcessName", "")
                        if isinstance(_parent, str) and _parent.rsplit("\\", 1)[-1].lower() in _ANALYZER_PARENTS:
                            continue
                        _image = _ed.get("Image", "")
                        if isinstance(_image, str) and _image.rsplit("\\", 1)[-1].lower() in _ANALYZER_IMAGES:
                            continue
                        _target = _ed.get("TargetFilename", _ed.get("TargetFileName", ""))
                        if isinstance(_target, str) and _target:
                            _tlow = _target.lower()
                            if any(_ep in _tlow for _ep in _ANALYZER_PATHS):
                                continue
                    count += 1
            except Exception:
                pass

    return count


def _load_evtx_channel_page(zip_path, member, page, page_size=EVTX_PAGE_SIZE, search_query=""):
    if not HAVE_EVTX:
        return {"member": member, "channel": _evtx_member_display_name(member), "error": "EVTX parser is not installed on the web node."}

    try:
        page = max(int(page), 1)
    except (TypeError, ValueError):
        page = 1

    try:
        mtime = os.path.getmtime(zip_path)
        return _load_evtx_channel_page_cached(zip_path, member, page, page_size, mtime, search_query)
    except Exception:
        return None


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
# @ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
# @ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
def load_files(request, task_id, category):
    """Filters calls for call category.
    @param task_id: cuckoo task id
    """
    is_ajax = request.headers.get("x-requested-with") == "XMLHttpRequest"
    if is_ajax and category in (
        "CAPE",
        "dropped",
        "behavior",
        "strace",
        "debugger",
        "network",
        "procdump",
        "procmemory",
        "memory",
        "tracee",
        "eventlogs",
        "etw",
    ):
        data = {}
        debugger_logs = {}
        bingraph_dict_content = {}
        vba2graph_dict_content = {}
        # Search calls related to your PID.
        if enabledconf["mongodb"]:
            if category in ("behavior", "debugger", "strace"):
                data = mongo_find_one(
                    "analysis",
                    {"info.id": int(task_id)},
                    {"behavior.processes": 1, "behavior.processtree": 1, "detections2pid": 1, "info.tlp": 1, "_id": 0},
                )
                if category == "debugger":
                    data["debugger"] = data["behavior"]
                if category == "strace":
                    data["strace"] = data["behavior"]
            elif category == "tracee":
                data = mongo_find_one("analysis", {"info.id": int(task_id)}, {category: 1, "info.tlp": 1, "_id": 0})
                tmp = data["tracee"]
                data["tracee"] = {}
                data["tracee"]["rawData"] = tmp
                with open("/opt/CAPEv2/data/linux/linux-syscalls.json", "r") as f:
                    data["tracee"]["syscalls_decoded"] = json.load(f)
                    data["tracee"]["syscalls_decoded"]["syscalls"].extend(
                        [
                            {"name": "stdio_over_socket", "cat": "SIGNATURISED"},
                            {"name": "k8s_api_connection", "cat": "SIGNATURISED"},
                            {"name": "aslr_inspection", "cat": "SIGNATURISED"},
                            {"name": "proc_mem_code_injection", "cat": "SIGNATURISED"},
                            {"name": "docker_abuse", "cat": "SIGNATURISED"},
                            {"name": "scheduled_task_mod", "cat": "SIGNATURISED"},
                            {"name": "ld_preload", "cat": "SIGNATURISED"},
                            {"name": "cgroup_notify_on_release", "cat": "SIGNATURISED"},
                            {"name": "default_loader_mod", "cat": "SIGNATURISED"},
                            {"name": "sudoers_modification", "cat": "SIGNATURISED"},
                            {"name": "sched_debug_recon", "cat": "SIGNATURISED"},
                            {"name": "system_request_key_mod", "cat": "SIGNATURISED"},
                            {"name": "cgroup_release_agent", "cat": "SIGNATURISED"},
                            {"name": "rcd_modification", "cat": "SIGNATURISED"},
                            {"name": "core_pattern_modification", "cat": "SIGNATURISED"},
                            {"name": "proc_kcore_read", "cat": "SIGNATURISED"},
                            {"name": "proc_mem_access", "cat": "SIGNATURISED"},
                            {"name": "hidden_file_created", "cat": "SIGNATURISED"},
                            {"name": "anti_debugging", "cat": "SIGNATURISED"},
                            {"name": "ptrace_code_injection", "cat": "SIGNATURISED"},
                            {"name": "process_vm_write_inject", "cat": "SIGNATURISED"},
                            {"name": "disk_mount", "cat": "SIGNATURISED"},
                            {"name": "dynamic_code_loading", "cat": "SIGNATURISED"},
                            {"name": "fileless_execution", "cat": "SIGNATURISED"},
                            {"name": "illegitimate_shell", "cat": "SIGNATURISED"},
                            {"name": "kernel_module_loading", "cat": "SIGNATURISED"},
                            {"name": "k8s_cert_theft", "cat": "SIGNATURISED"},
                            {"name": "proc_fops_hooking", "cat": "SIGNATURISED"},
                            {"name": "syscall_hooking", "cat": "SIGNATURISED"},
                            {"name": "dropped_executable", "cat": "SIGNATURISED"},
                            {"name": "sched_debug_recon", "cat": "SIGNATURISED"},
                            {"name": "sched_process_exec", "cat": "SIGNATURISED"},
                            {"name": "security_inode_unlink", "cat": "SIGNATURISED"},
                            {"name": "security_bpf_prog", "cat": "SIGNATURISED"},
                            {"name": "security_socket_connect", "cat": "SIGNATURISED"},
                            {"name": "security_socket_accept", "cat": "SIGNATURISED"},
                            {"name": "security_socket_bind", "cat": "SIGNATURISED"},
                            {"name": "security_sb_mount", "cat": "SIGNATURISED"},
                            {"name": "net_packet_icmp", "cat": "SIGNATURISED"},
                            {"name": "net_packet_icmpv6", "cat": "SIGNATURISED"},
                            {"name": "net_packet_dns_request", "cat": "SIGNATURISED"},
                            {"name": "net_packet_dns_response", "cat": "SIGNATURISED"},
                            {"name": "net_packet_http_request", "cat": "SIGNATURISED"},
                            {"name": "net_packet_http_response", "cat": "SIGNATURISED"},
                            {"name": "process_vm_readv", "cat": "SIGNATURISED"},
                            {"name": "process_vm_writev", "cat": "SIGNATURISED"},
                            {"name": "finit_module", "cat": "SIGNATURISED"},
                            {"name": "memfd_create", "cat": "SIGNATURISED"},
                        ]
                    )
                data["tracee"]["syscalls"] = json.dumps(data["tracee"]["syscalls_decoded"])
                data["tracee"]["cats"] = [
                    "SIGNATURISED",
                    "kernel",
                    "fs",
                    "mm",
                    "net",
                    "ipc",
                    "security",
                    "drivers",
                    "io_uring",
                    "crypto",
                    "block",
                ]
            elif category == "network":
                data = mongo_find_one(
                    "analysis",
                    {"info.id": int(task_id)},
                    {category: 1, "info.tlp": 1, "cif": 1, "suricata": 1, "pcapng": 1, "_id": 0},
                )
            elif category == "eventlogs":
                data = mongo_find_one(
                    "analysis",
                    {"info.id": int(task_id)},
                    {"sigma": 1, "sysmon": 1, "info.tlp": 1, "info.id": 1, "_id": 0},
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
                if category == "strace":
                    data["strace"] = data["behavior"]
            elif category == "network":
                data = elastic_handler.search(
                    index=get_analysis_index(),
                    query=get_query_by_info_id(task_id),
                    _source=[category, "suricata", "cif", "info.tlp"],
                )["hits"]["hits"][0]["_source"]
            elif category == "eventlogs":
                data = elastic_handler.search(
                    index=get_analysis_index(),
                    query=get_query_by_info_id(task_id),
                    _source=["sigma", "sysmon", "info.tlp", "info.id"],
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

        category_data = data.get(category, {})
        if category == "eventlogs":
            evtx_zip = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "evtx", "evtx.zip")
            evtx_channels = []
            if path_exists(evtx_zip):
                evtx_channels = _list_evtx_members(evtx_zip)
            category_data = {
                "sigma": data.get("sigma", {}),
                "sysmon": data.get("sysmon", []),
                "evtx_channels": evtx_channels,
            }
        elif category == "etw":
            category_data = _load_etw_telemetry(task_id)

        ajax_response = {
            category: category_data,
            "tlp": data.get("info", {}).get("tlp", ""),
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
            ajax_response["pcapng"] = data.get("pcapng", {})
            tls_path = os.path.join(ANALYSIS_BASE_PATH, "analyses", str(task_id), "tlsdump", "tlsdump.log")
            if _path_safe(tls_path):
                ajax_response["tlskeys_exists"] = _path_safe(tls_path)
            mitmdump_path = os.path.join(ANALYSIS_BASE_PATH, "analyses", str(task_id), "mitmdump", "dump.har")
            if _path_safe(mitmdump_path):
                ajax_response["mitmdump_exists"] = _path_safe(mitmdump_path)
            decrypted_pcap_path = os.path.join(ANALYSIS_BASE_PATH, "analyses", str(task_id), "dump_decrypted.pcap")
            if _path_safe(decrypted_pcap_path):
                ajax_response["decrypted_pcap_exists"] = True
            mixed_pcap_path = os.path.join(ANALYSIS_BASE_PATH, "analyses", str(task_id), "dump_mixed.pcap")
            if _path_safe(mixed_pcap_path):
                ajax_response["mixed_pcap_exists"] = True
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
                {"info.machine.platform": 1, "behavior.processes.process_id": 1, "behavior.processes.calls": 1, "_id": 0},
            )

        if es_as_db:
            record = es.search(
                index=get_analysis_index(),
                body={
                    "query": {
                        "bool": {"must": [{"match": {"behavior.processes.process_id": pid}}, {"match": {"info.id": task_id}}]}
                    }
                },
                _source=["info.machine.platform", "behavior.processes.process_id", "behavior.processes.calls"],
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

        if record["info"].get("machine", {}).get("platform", "") == "linux":
            return render(request, "analysis/strace/_chunk.html", {"chunk": chunk})
        else:
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
                {"info.machine.platform": 1, "behavior.processes.process_id": 1, "behavior.processes.calls": 1, "_id": 0},
            )
        if es_as_db:
            record = es.search(
                index=get_analysis_index(),
                body={
                    "query": {
                        "bool": {"must": [{"match": {"behavior.processes.process_id": pid}}, {"match": {"info.id": task_id}}]}
                    }
                },
                _source=["info.machine.platform", "behavior.processes.process_id", "behavior.processes.calls"],
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
        for call in process.get("calls", []):
            if enabledconf["mongodb"]:
                chunk = mongo_find_one("calls", {"_id": call})
            if es_as_db:
                chunk = es.search(index=get_calls_index(), body={"query": {"match": {"_id": call}}})["hits"]["hits"][0]["_source"]
            for call in chunk.get("calls", []):
                # filter by call or tid
                if caller != "null" or tid != "0":
                    if caller in ("null", call["caller"]) and tid in ("0", call["thread_id"]):
                        filtered_process["calls"].append(call)
                elif category in ("all", call["category"]):
                    if len(apis) > 0:
                        add_call = -1
                        for api in apis:
                            if api in call["api"].lower():
                                if exclude:
                                    add_call = 0
                                else:
                                    add_call = 1
                                break
                        if (exclude and add_call != 0) or (not exclude and add_call == 1):
                            filtered_process["calls"].append(call)
                    else:
                        filtered_process["calls"].append(call)

        if record.get("info", {}).get("machine", {}).get("platform", "") == "linux":
            return render(request, "analysis/strace/_chunk.html", {"chunk": filtered_process})
        else:
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
            http_method = e.get("http_method") or e.get("method")
            if http_method:
                e["moloch_http_method_url"] = (
                    settings.MOLOCH_BASE + "?date=-1&expression=http.method" + quote("\x3d\x3d\x22%s\x22" % (http_method), safe="")
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
def antivirus(request, task_id):
    if enabledconf["mongodb"]:
        rtmp = mongo_find_one(
            "analysis",
            {"info.id": int(task_id)},
            {"target.file.virustotal": 1, "url.virustotal": 1, "info.category": 1, "_id": 0},
            sort=[("_id", -1)],
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

    if rtmp.get("target", {}).get("file"):
        rtmp["virustotal"] = rtmp.get("target", {}).get("file", {}).get("virustotal")
        del rtmp["target"]["file"]["virustotal"]
    elif rtmp.get("url", {}).get("virustotal"):
        rtmp["virustotal"] = rtmp.get("url", {}).get("virustotal")
        del rtmp["url"]["virustotal"]

    if settings.MOLOCH_ENABLED:
        if settings.MOLOCH_BASE[-1] != "/":
            settings.MOLOCH_BASE += "/"
        if "virustotal" in rtmp:
            rtmp["virustotal"] = gen_moloch_from_antivirus(rtmp["virustotal"])

    rtmp.setdefault("file", {}).setdefault("virustotal", rtmp["virustotal"])
    del rtmp["virustotal"]

    return render(request, "analysis/antivirus.html", rtmp)


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


@csrf_exempt
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def search_behavior(request, task_id):
    if request.method == "POST":
        query = request.POST.get("search")
        results = []
        search_pid = None
        search_tid = None
        search_apicall = None
        search_argname = None
        search_procname = None

        match = re.search(r"pid=(?P<search_pid>\d+)", query)
        if match:
            search_pid = int(match.group("search_pid"))
        match = re.search(r"tid=(?P<search_tid>\d+)", query)
        if match:
            search_tid = match.group("search_tid")
        match = re.search(r"apicall=(?P<search_apicall>[A-Za-z]+)", query)
        if match:
            search_apicall = match.group("search_apicall")
        match = re.search(r"argname=(?P<search_argname>[A-Za-z]+)", query)
        if match:
            search_argname = match.group("search_argname")
        match = re.search(r"procname=(?P<search_procname>[A-Za-z0-9\.\-]+)", query)
        if match:
            search_procname = match.group("search_procname")

        if search_pid:
            query = query.replace("pid=" + str(search_pid), "")
        if search_tid:
            query = query.replace("tid=" + search_tid, "")
        if search_apicall:
            query = query.replace("apicall=" + search_apicall, "")
        if search_argname:
            query = query.replace("argname=" + search_argname, "")
        if search_procname:
            query = query.replace("procname=" + search_procname, "")

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
            if search_procname and process["process_name"].lower() != search_procname.lower():
                continue
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
                    if search_apicall and call["api"] != search_apicall:
                        continue

                    # TODO: ES can speed this up instead of parsing with Python regex.

                    for argument in call["arguments"]:
                        if search_argname and argument["name"] != search_argname:
                            continue
                        if isinstance(argument["value"], (str, bytes)) and query.search(argument["value"]):
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

    reports_exist = {}
    # check if we allow dl reports only to specific users
    reporting_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "reports")
    if path_exists(reporting_path):
        for f in os.listdir(reporting_path):
            if f == "report.json":
                reports_exist["json"] = True
            elif f == "report.html":
                reports_exist["html"] = True
            elif f == "summary-report.html":
                reports_exist["htmlsummary"] = True
            elif f == "report.pdf":
                reports_exist["pdf"] = True
            elif f == "report.maec-4.1.xml":
                reports_exist["maec"] = True
            elif f == "report.maec-5.0.xml":
                reports_exist["maec5"] = True
            elif f == "report.metadata.xml":
                reports_exist["metadata"] = True
            elif f == "misp.json":
                reports_exist["misp"] = True
            elif f == "lite.json":
                reports_exist["litereport"] = True
            elif f == "cents.json":
                reports_exist["cents"] = True

    debugger_log_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "debugger")
    if path_exists(debugger_log_path) and os.listdir(debugger_log_path):
        report["debugger_logs"] = 1

    evtx_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "evtx", "evtx.zip")
    if path_exists(evtx_path):
        report["has_evtx"] = True

    # Mark the report as having ETW telemetry to render the new tab.
    # Cheap pre-check: any non-empty source under aux/. Detailed parsing
    # is deferred to the AJAX `etw` category in load_files so we don't
    # walk multi-MB files on report-page render.
    aux_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "aux")
    for source in ("dns_etw.json", "network_etw.json", "wmi_etw.json",
                   "threatintel_etw.json", "amsi_etw"):
        p = os.path.join(aux_dir, source)
        if not path_exists(p):
            continue
        if os.path.isdir(p):
            try:
                if os.listdir(p):
                    report["has_etw"] = True
                    break
            except OSError:
                continue
        elif os.path.getsize(p) > 0:
            report["has_etw"] = True
            break

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
            "title": "Analysis Report",
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


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def load_evtx_channel(request, task_id):
    if request.headers.get("x-requested-with") != "XMLHttpRequest":
        raise PermissionDenied

    member = request.GET.get("member", "")
    page = request.GET.get("page", "1")
    search_query = request.GET.get("search", "")
    evtx_zip = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "evtx", "evtx.zip")
    if not path_exists(evtx_zip):
        raise PermissionDenied

    evtx_page = _load_evtx_channel_page(evtx_zip, member, page, search_query=search_query)
    if not evtx_page:
        evtx_page = {
            "member": member,
            "channel": _evtx_member_display_name(member),
            "search_query": search_query,
            "error": "Failed to load EVTX channel.",
        }

    return render(request, "analysis/eventlogs/_evtx_channel.html", {"evtx_page": evtx_page})


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def load_evtx_channel_count(request, task_id):
    if request.headers.get("x-requested-with") != "XMLHttpRequest":
        raise PermissionDenied

    member = request.GET.get("member", "")
    evtx_zip = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "evtx", "evtx.zip")
    if not path_exists(evtx_zip):
        raise PermissionDenied

    if not HAVE_EVTX:
        return JsonResponse({"ok": False, "error": "EVTX parser is not installed on the web node."})

    try:
        mtime = os.path.getmtime(evtx_zip)
        count = _count_evtx_channel_events_cached(evtx_zip, member, mtime)
    except Exception:
        return JsonResponse({"ok": False, "error": "Failed to count EVTX events."})

    return JsonResponse({"ok": True, "member": member, "count": count})


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
@csrf_exempt
@api_view(["GET"])
# UI-internal endpoint — the analysis report's <img src="..."> tags hit
# this from a browser session for screenshots / bingraphs / svgs. Re-enable
# session-cookie auth here so the global API-key-only DRF chain (used
# under SSO deployments) doesn't 401 the in-browser fetches.
@authentication_classes([SessionAuthentication])
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
    "logszipall",
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
# UI-internal: same rationale as file_nl — used for in-browser downloads
# of dropped files, payloads, etc. via session cookie auth.
@authentication_classes([SessionAuthentication])
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
    elif category == "pcap":
        file_name += ".pcap"
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "dump.pcap")
        cd = "application/vnd.tcpdump.pcap"
    elif category == "pcapzip":
        analysis_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id)
        pcap_files = [
            ("dump.pcap", os.path.join(analysis_dir, "dump.pcap")),
            ("dump_decrypted.pcap", os.path.join(analysis_dir, "dump_decrypted.pcap")),
            ("dump_mixed.pcap", os.path.join(analysis_dir, "dump_mixed.pcap")),
            ("sslproxy.pcap", os.path.join(analysis_dir, "sslproxy", "sslproxy.pcap")),
            ("sslproxy_clean.pcap", os.path.join(analysis_dir, "sslproxy", "sslproxy_clean.pcap")),
        ]
        path = [p for _, p in pcap_files if path_exists(p) and os.path.getsize(p) > 0]
        if not path:
            path = os.path.join(analysis_dir, "dump.pcap")
        cd = "application/zip"
    elif category == "pcapng":
        analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id)
        pcap_path = os.path.join(analysis_path, "dump.pcap")
        tls_log_path = os.path.join(analysis_path, "tlsdump", "tlsdump.log")
        ssl_key_log_path = os.path.join(analysis_path, "aux", "sslkeylogfile", "sslkeys.log")
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "dump.pcapng")
        pcapng = PcapToNg(pcap_path, tls_log_path, ssl_key_log_path)
        pcapng.generate(path)
        file_name += ".pcapng"
        cd = "application/vnd.tcpdump.pcap"
    elif category == "decrypted_pcap":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "dump_decrypted.pcap")
        file_name += ".pcap"
        cd = "application/vnd.tcpdump.pcap"
    elif category == "mixed_pcap":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "dump_mixed.pcap")
        file_name += ".pcap"
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
    # linux sysmon url to download sysmon.data xml
    elif category == "sysmon":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "sysmon", "sysmon.data")
    elif category == "evtx":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "evtx", "evtx.zip")
        file_name = f"{task_id}_evtx.zip"
        cd = "application/zip"
    elif category == "capeyarazipall":
        # search in mongo and get the path
        if enabledconf["mongodb"] and web_cfg.zipped_download.download_all:
            path = _file_search_all_files(category.replace("zipall", ""), dlfile)
    elif category == "logszipall":
        buf = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "logs")
        path = []
        for dfile in os.listdir(buf):
            path.append(os.path.join(buf, dfile))
    elif category == "mitmdump":
        path = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "mitmdump", "dump.har")
        cd = "text/plain"
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
            if not isinstance(path, list):
                path = [path]
            if USE_SEVENZIP:
                zip_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", f"{task_id}", f"{file_name}.zip")
                sevenZipArgs = [SEVENZIP_PATH, f"-p{settings.ZIP_PWD.decode()}", "a", zip_path]
                sevenZipArgs.extend(path)
                try:
                    subprocess.check_call(sevenZipArgs)
                except subprocess.CalledProcessError:
                    return render(request, "error.html", {"error": "error compressing file"})
                zip_fd = open(zip_path, "rb")
                resp = StreamingHttpResponse(zip_fd, content_type="application/zip")
                resp["Content-Length"] = os.path.getsize(zip_path)
                resp["Content-Disposition"] = f"attachment; filename={file_name}.zip"
                return resp
            else:
                mem_zip = BytesIO()
                with pyzipper.AESZipFile(mem_zip, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
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
                    with pyzipper.AESZipFile(mem_zip, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
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
                {
                    "title": "Search",
                    "analyses": None,
                    "term": searched,
                    "error": "Search term too short, minimum 3 characters required",
                },
            )

        # name:foo or name: foo
        value = value.lstrip()
        term = term.lower()

        if not term:
            value = value.lower()
            split_by = "," if "," in value else " "
            tmp_value = value.split(split_by)[0]
            if len(tmp_value) == 64 and re.match(r"^([a-fA-F\d]{64})$", tmp_value):
                term = "sha256"
            elif len(tmp_value) == 32 and re.match(r"^([a-fA-F\d]{32})$", tmp_value):
                term = "md5"
            elif len(tmp_value) == 40 and re.match(r"^([a-fA-F\d]{40})$", tmp_value):
                term = "sha1"
            elif len(tmp_value) == 96 and re.match(r"^([a-fA-F\d]{96})$", tmp_value):
                term = "sha3"
            elif len(tmp_value) == 128 and re.match(r"^([a-fA-F\d]{128})$", tmp_value):
                term = "sha512"

        if term == "ids":
            if all([v.strip().isdigit() for v in value.split(",")]):
                value = [int(v.strip()) for v in filter(None, value.split(","))]
            else:
                return render(
                    request,
                    "analysis/search.html",
                    {"title": "Search", "analyses": None, "term": searched, "error": "Not all values are integers"},
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
                    {"title": "Search", "analyses": None, "term": searched, "error": "Invalid search term: %s" % term},
                )
            else:
                return render(
                    request,
                    "analysis/search.html",
                    {"title": "Search", "analyses": None, "term": None, "error": "Unable to recognize the search syntax"},
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
                "title": "Search Results",
                "analyses": analyses,
                "config": enabledconf,
                "term": searched,
                "error": None,
                "term_only": term_only,
                "value_only": value_only,
            },
        )
    return render(request, "analysis/search.html", {"title": "Search", "analyses": None, "term": None, "error": None})


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
    if enabledconf["vtupload"] and integrations_cfg.virustotal.apikey:
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

            headers = {"x-apikey": integrations_cfg.virustotal.apikey}
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
                request,
                "error.html",
                {"title": "Statistics", "error": "Please restart your database. Probably it had an update or it just down"},
            )
        return render(request, "statistics.html", {"title": "Statistics", "statistics": details, "days": days})
    return render(request, "error.html", {"title": "Statistics", "error": "Provide days as number"})


on_demand_config_mapper = {
    "bingraph": reporting_cfg,
    "flare_capa": integrations_cfg,
    "vba2graph": processing_cfg,
    "xlsdeobf": processing_cfg,
    "strings": processing_cfg,
    "floss": integrations_cfg,
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
    ) and not getattr(
        on_demand_config_mapper.get(service, {}), service
    ).get("on_demand"):
        return render(request, "error.html", {"error": "Not supported/enabled service on demand"})

    # Restrict category to known report sections writable by this endpoint.
    allowed_categories = {"static", "CAPE", "procdump", "procmemory", "dropped"}
    if category not in allowed_categories:
        return render(request, "error.html", {"error": f"Unsupported category: {category}"}, status=400)

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
        # selfextracted storage is shared by multiple categories; keep non-static category intact
        if category == "static":
            category = "target.file"
        extractedfile = True

    if path and (not _path_safe(path) or not path_exists(path)):
        return render(request, "error.html", {"error": "File not found: {}".format(path)})

    details = False
    if service == "flare_capa" and HAVE_FLARE_CAPA:
        # ToDo check if PE
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

    def _set_service_by_sha256(node, target_sha256, service_name, service_details):
        if isinstance(node, dict):
            if node.get("sha256") == target_sha256:
                node[service_name] = service_details
                return True
            for value in node.values():
                if isinstance(value, (dict, list)) and _set_service_by_sha256(value, target_sha256, service_name, service_details):
                    return True
            return False
        if isinstance(node, list):
            for item in node:
                if _set_service_by_sha256(item, target_sha256, service_name, service_details):
                    return True
        return False

    if details:
        buf = mongo_find_one("analysis", {"info.id": int(task_id)}, {"_id": 1, category: 1})

        servicedata = {}
        if category == "CAPE":
            _set_service_by_sha256(buf[category].get("payloads", []) or [], sha256, service, details)
            servicedata = buf[category]
        elif category in ("procdump", "procmemory", "dropped"):
            _set_service_by_sha256(buf[category] or [], sha256, service, details)
            servicedata = buf[category]
        elif category == "target.file":
            servicedata = buf.get("target", {}).get("file", {})
            if servicedata:
                if service == "xlsdeobf":
                    servicedata.setdefault("office", {}).setdefault("XLMMacroDeobfuscator", details)
                elif extractedfile:
                    _set_service_by_sha256(servicedata, sha256, service, details)
                else:
                    servicedata.setdefault(service, details)

        if servicedata:
            try:
                mongo_update_one("analysis", {"_id": ObjectId(buf["_id"])}, {"$set": {category: servicedata}})
            except MONGO_DOCUMENT_TOO_LARGE_ERRORS:
                return render(
                    request,
                    "error.html",
                    {
                        "error": (
                            f"Generated {service} data is too large to store for this file. "
                            "Please narrow extraction scope or use offline extraction."
                        )
                    },
                    status=413,
                )
            except Exception as e:
                print(f"on_demand update failed for task_id={task_id} service={service} category={category} sha256={sha256}: {e}")
                return render(
                    request,
                    "error.html",
                    {"error": f"Failed to store generated {service} data."},
                    status=500,
                )
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
def reprocess_tasks(request, task_id: int):
    if not settings.REPROCESS_TASKS:
        return HttpResponseRedirect(request.META.get("HTTP_REFERER", "/"))

    error, msg, _ = db.tasks_reprocess(task_id)
    if error:
        return render(request, "error.html", {"error": msg})
    else:
        return redirect("submission_status", task_id=task_id)


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def failed_processing(request, task_id):
    task = db.view_task(task_id)
    if not task:
        return render(request, "error.html", {"error": "Task not found"})

    process_log_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "process.log")

    log_content = "Process log file not found."
    if path_exists(process_log_path):
        log_content = path_read_file(process_log_path, mode="text")

    return render(request, "analysis/failed_processing.html", {
        "task": task,
        "process_log": log_content,
        "settings": settings,
    })
