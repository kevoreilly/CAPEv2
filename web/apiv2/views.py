# encoding: utf-8
import hashlib
import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
import zipfile
from contextlib import suppress
from datetime import datetime, timedelta
from io import BytesIO
from urllib.parse import quote, urljoin
from wsgiref.util import FileWrapper

import pyzipper
import requests
import yara
from bson.objectid import ObjectId
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import StreamingHttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_safe
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.authentication import SessionAuthentication
from rest_framework.response import Response
try:
    from apikey.authentication import ApiKeyAuthentication
except ImportError:
    ApiKeyAuthentication = None

# Auth chain for UI-internal DRF endpoints (e.g. the report-page visibility
# toggle): SessionAuthentication is dropped from the DRF default in SSO/OIDC
# mode (see settings.py), so a browser session + CSRF can't hit /apiv2/. Opt
# these endpoints back into session auth WHILE keeping API-token auth, so both
# the in-browser control and scripted API clients work.
_UI_INTERNAL_AUTH = [SessionAuthentication] + ([ApiKeyAuthentication] if ApiKeyAuthentication else [])

from web.tenancy_optional import submission_scope, can_view_task, can_toggle_task, can_manage_task, can_view_sample, viewer_for
from web.tenancy_optional import VISIBILITIES, TENANT, multitenancy_config

# Shared central-mode cross-store info.id collision seam (report-family reads route through it) --
# see analysis.central_views. The apiv2 report-family passes no `extra` (extra defaults to None).
from analysis.central_views import scoped_analysis_query as _analysis_filter

# Central-aware task delete: scopes the analysis+calls delete to the caller in central mode so a colliding
# tenant's docs aren't destroyed; single-node delegates to mongo_delete_data unchanged.
from analysis.central_views import central_delete_analysis


def _deny_if_hidden(request, task):
    """Return a Response (to be returned by the caller) if request.user may not
    see `task`, else None. Every per-task READ endpoint must route through this
    (enforced by the endpoint-coverage test) to prevent cross-tenant leaks.

    A non-existent task and a hidden task return the SAME generic 404 response so
    an attacker cannot enumerate which task IDs / states exist in other tenants.
    Callers must invoke this BEFORE validate_task()/status/TLP checks so those
    don't leak existence either."""
    if task is None:
        # Missing task: under MT this returns the SAME generic 404 as a hidden
        # task so other tenants' task ids can't be enumerated. With MT DISABLED
        # there is no isolation to enforce, so defer to the caller's own
        # missing-task handling (upstream behavior; default-off changes nothing).
        return Response({"error": True, "error_value": "Task not found"}, status=404) if multitenancy_config().enabled else None
    if not can_view_task(request.user, task):
        return Response({"error": True, "error_value": "Task not found"}, status=404)
    return None


def _deny_task(request, task_id):
    """Convenience: load the task and apply _deny_if_hidden. Used by endpoints
    that don't otherwise hold the Task object."""
    return _deny_if_hidden(request, db.view_task(task_id))


def _deny_manage(request, task_id):
    """Like _deny_task but for MUTATIONS — requires can_manage (owner/tenant-admin/
    break-glass). Returns a generic 404 Response if not allowed, else None."""
    task = db.view_task(task_id)
    if task is None:
        # Missing task: generic 404 under MT (no cross-tenant id enumeration);
        # with MT disabled, defer to the caller's own missing-task handling so a
        # default (non-MT) install keeps its existing responses.
        return Response({"error": True, "error_value": "Task not found"}, status=404) if multitenancy_config().enabled else None
    if not can_manage_task(request.user, task):
        return Response({"error": True, "error_value": "Task not found"}, status=404)
    return None


def _strip_mt_task_fields(d):
    """Task.to_dict() now emits the multitenancy columns ("tenant_id",
    "visibility"). On a DEFAULT (multitenancy-disabled) install these keys did
    not exist upstream, so drop them from any api response payload to keep the
    output byte-identical to upstream base. When MT is enabled the keys are part
    of the tenant model and are preserved untouched."""
    if not multitenancy_config().enabled and isinstance(d, dict):
        d.pop("tenant_id", None)
        d.pop("visibility", None)
    return d


def _strip_mt_sample_fields(d):
    """The `samples` row is GLOBALLY hash-deduplicated (one row per sha256, no
    owner/tenant column), but `source_url` is per-submission provenance written by
    whoever FIRST registered the hash. Under multitenancy, returning it from a
    hash-addressed / cross-referenced sample serialization leaks the first
    registrant's source (e.g. another tenant's internal URL or a C2 they track) to
    any tenant that later submits the same file. Strip it when MT is enabled. The
    remaining fields are intrinsic file properties (hashes/size/type), derivable
    from the file the caller already holds. MT-off keeps upstream output verbatim."""
    if multitenancy_config().enabled and isinstance(d, dict):
        d.pop("source_url", None)
    return d


def _deny_by_hash(request, *, sha256=None, sha1=None, md5=None, sample_id=None):
    """Indistinguishable 404 unless the caller has >=1 VISIBLE task referencing the
    sample identified by the hash/id. A sample can be shared across tenants, so access
    follows the union of the caller's visible tasks.

    When multitenancy is DISABLED (or for a break-glass admin), viewer_for returns
    is_local_admin=True and this function is a no-op — it must NOT gate the public
    install, and must NOT 404 dropped/procdump payloads that have no Sample row."""
    # Delegate the entitlement decision to the shared tenancy.can_view_sample so
    # this gate, web file()'s sample/static branch, and the submission resubmit /
    # download-services paths all enforce the SAME by-hash boundary and can't
    # drift (no-op for break-glass / MT-disabled — handled inside the helper).
    if can_view_sample(request.user, sha256=sha256, sha1=sha1, md5=md5, sample_id=sample_id):
        return None
    return Response({"error": True, "error_value": "Sample not found"}, status=404)


@api_view(["PATCH"])
@authentication_classes(_UI_INTERNAL_AUTH)
def tasks_set_visibility(request, task_id):
    """Owner (or tenant-admin for public/tenant jobs, or a break-glass admin)
    re-toggles a task's visibility. Mirrors the can_toggle predicate (break-glass =
    viewer.is_local_admin, i.e. a superuser gated by cuckoo.conf, not any superuser)."""
    # Visibility is a multitenancy feature. With MT OFF, viewer_for marks every
    # principal is_local_admin, so can_toggle would authorize ANY caller to write a
    # value that is ignored now but can hide/expose LEGACY analyses if MT is later
    # enabled (the mongo backfill skips already-stamped docs). Reject when disabled.
    if not multitenancy_config().enabled:
        return Response({"error": True, "error_value": "multitenancy is not enabled"}, status=400)
    # Parse once so view_task() and set_task_visibility() get a consistent int and
    # a non-numeric id fails as the same generic 404 (no implicit-coercion no-op).
    try:
        task_id = int(task_id)
    except (ValueError, TypeError):
        return Response({"error": True, "error_value": "Task not found"}, status=404)
    task = db.view_task(task_id)
    # Indistinguishable response (H3): a caller who can't even SEE the task gets
    # the SAME generic 404 as a missing one, so this endpoint can't be used to
    # enumerate other tenants' task IDs. A 403 below is only reachable once the
    # caller can read the task (so it leaks nothing they don't already see).
    if task is None or not can_view_task(request.user, task):
        return Response({"error": True, "error_value": "Task not found"}, status=404)
    vis = request.data.get("visibility")
    if vis not in VISIBILITIES:
        return Response({"error": True, "error_value": "invalid visibility"}, status=400)
    if not can_toggle_task(request.user, task):
        return Response({"error": True, "error_value": "Access denied"}, status=403)
    # A task with no tenant can't be 'tenant'-visible: can_read's tenant branch
    # requires a non-null job tenant, so this would make the task readable by nobody
    # but its owner / break-glass (a broken, invisible state). Reject the transition.
    if vis == TENANT and getattr(task, "tenant_id", None) is None:
        return Response(
            {"error": True, "error_value": "tenant visibility requires the task to belong to a tenant"},
            status=400,
        )
    try:
        db.set_task_visibility(task_id, vis)
    except CuckooOperationalError:
        # The report store (mongo) was unreachable, so set_task_visibility rolled
        # the SQL change back to keep the two stores consistent — NOTHING changed.
        # Report 503 so the caller retries; the task is still at its prior visibility.
        return Response(
            {"error": True, "error_value": "visibility change aborted (report store unreachable); no change made, retry"},
            status=503,
        )
    return Response({"error": False, "data": {"task_id": int(task_id), "visibility": vis}})

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import ANALYSIS_BASE_PATH, CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooDemuxError, CuckooOperationalError
from lib.cuckoo.common.path_utils import path_delete, path_exists
from lib.cuckoo.common.saztopcap import saz_to_pcap
from lib.cuckoo.common.utils import (
    convert_to_printable,
    create_zip,
    delete_folder,
    get_options,
    get_user_filename,
    sanitize_filename,
    store_temp_file,
)
from lib.cuckoo.common.web_utils import (
    apiconf,
    download_file,
    download_from_3rdparty,
    force_int,
    parse_request_arguments,
    perform_search,
    process_new_dlnexec_task,
    process_new_task_files,
    search_term_map,
    statistics,
    validate_task,
)

from lib.cuckoo.core.database import Database, _Database
from lib.cuckoo.core.data.task import (
    TASK_RECOVERED,
    TASK_RUNNING,
    Task,
)
from lib.cuckoo.core.rooter import _load_socks5_operational, vpns

# from mcp.filters import lean_search_filters
lean_search_filters = {}
try:
    import psutil

    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False
    print("Missed psutil dependency: poetry run pip install -U psutil")

log = logging.getLogger(__name__)

try:
    zippwd = settings.ZIP_PWD
except AttributeError:
    zippwd = b"infected"

try:
    import re2 as re
except ImportError:
    import re

HAVE_PLYARA = False
with suppress(ImportError):
    import plyara
    import plyara.utils
    HAVE_PLYARA = True

# FORMAT = '%(asctime)-15s %(clientip)s %(user)-8s %(message)s'

# Config variables
repconf = Config("reporting")
web_conf = Config("web")
routing_conf = Config("routing")
reporting_conf = Config("reporting")
dist_conf = Config("distributed")

zlib_compresion = False
if repconf.compression.enabled:
    from zlib import decompress

    zlib_compresion = True

USE_SEVENZIP = False
if reporting_conf.compression.compressiontool.strip() == "7zip":
    USE_SEVENZIP = True
    SEVENZIP_PATH = reporting_conf.compression.sevenzippath.strip() or "/usr/bin/7z"


if repconf.mongodb.enabled:
    from dev_utils.mongodb import (
        mongo_find,
        mongo_find_one,
        mongo_find_one_and_update,
    )

es_as_db = False
if repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
    from dev_utils.elasticsearchdb import (
        elastic_handler,
        get_analysis_index,
        get_query_by_info_id,
    )

    es_as_db = True
    es = elastic_handler


DIST_ENABLED = False
if dist_conf.distributed.enabled:
    from sqlalchemy import select

    from lib.cuckoo.common.dist_db import Node, create_session
    from lib.cuckoo.common.dist_db import Task as DTask

    dist_session = create_session(
        dist_conf.distributed.db,
        echo=False,
    )
    DIST_ENABLED = True

db: _Database = Database()

ALLOWED_YARA_CATEGORIES = ("binaries", "urls", "memory", "CAPE", "macro", "monitor")

# Conditional decorator for web authentication
class conditional_login_required:
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)


def createProcessTreeNode(process):
    """Creates a single ProcessTreeNode corresponding to a single node in the tree observed cuckoo.
    @param process: process from cuckoo dict.
    """
    process_node_dict = {
        "pid": process["pid"],
        "name": process["name"],
        "spawned_processes": [createProcessTreeNode(child_process) for child_process in process["children"]],
    }
    return process_node_dict


@require_safe
@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request):
    conf = apiconf.get_config()
    parsed = {}
    # Parse out the config for the API
    for section in conf:
        if section not in parsed:
            parsed[section] = {}
        for option in conf[section]:
            if option == "__name__":
                pass
            else:
                cfgvalue = conf[section][option]
                if cfgvalue == "yes":
                    newvalue = True
                elif cfgvalue == "no":
                    newvalue = False
                else:
                    newvalue = cfgvalue
                if option not in parsed[section]:
                    parsed[section][option] = newvalue

    # Fill in any blanks to normalize the API config Dict
    for key in parsed:
        if key == "api":
            pass
        else:
            if "rps" not in list(parsed[key].keys()):
                parsed[key]["rps"] = "None"
            if "rpm" not in list(parsed[key].keys()):
                parsed[key]["rpm"] = "None"
            # Set rates to None if the API is disabled
            if not parsed[key]["enabled"]:
                parsed[key]["rps"] = "None"
                parsed[key]["rpm"] = "None"

    return render(request, "apiv2/index.html", {"title": "API", "config": parsed})


@csrf_exempt
@api_view(["POST"])
def tasks_create_static(request):
    resp = {}
    # Check if this API function is enabled
    if not apiconf.staticextraction.get("enabled"):
        return Response({"error": True, "error_value": "File Create API is Disabled"})
    # Check if files are actually provided
    if request.FILES.getlist("file") == []:
        return Response({"error": True, "error_value": "No file was submitted"})

    options = request.data.get("options", "")
    priority = force_int(request.data.get("priority"))

    resp["error"] = []
    try:
        _tenant_id, _visibility = submission_scope(request)
    except ValueError:
        return Response({"error": True, "error_value": "invalid visibility"})
    files = request.FILES.getlist("file")
    extra_details = {}
    task_ids = []
    for sample in files:
        with sample:
            tmp_path = store_temp_file(sample.read(), sanitize_filename(sample.name))
            try:
                task_id, extra_details = db.demux_sample_and_add_to_db(
                    tmp_path,
                    options=options,
                    priority=priority,
                    static=1,
                    only_extraction=True,
                    user_id=request.user.id or 0,
                    tenant_id=_tenant_id,
                    visibility=_visibility,
                )
                task_ids.extend(task_id)
                if extra_details.get("erros"):
                    resp["errors"].extend(extra_details["errors"])
            except CuckooDemuxError as e:
                resp = {"error": True, "error_value": e}
                return Response(resp)

    resp["data"] = {}
    resp["data"]["task_ids"] = task_ids
    if extra_details and "config" in extra_details:
        resp["data"]["config"] = extra_details["config"]
    if extra_details.get("errors"):
        resp["errors"].extend(extra_details["errors"])

    callback = apiconf.filecreate.get("status")
    if task_ids:
        if len(task_ids) == 1:
            resp["data"]["message"] = "Task ID(s) {0} has been submitted".format(task_ids[0])
            if callback:
                resp["url"] = ["{0}/submit/status/{1}/".format(apiconf.api.get("url"), task_ids[0])]
        else:
            resp["data"] = {}
            resp["data"]["message"] = "Task IDs {0} have been submitted".format(", ".join(str(x) for x in task_ids))
            if callback:
                resp["url"] = []
                for tid in task_ids:
                    resp["url"].append("{0}/submit/status/{1}".format(apiconf.api.get("url"), tid))
            else:
                resp = {"error": True, "error_value": "Error adding task to database"}

    return Response(resp)


@csrf_exempt
@api_view(["POST"])
def tasks_create_file(request):
    resp = {}
    if request.method == "POST":
        # Check if this API function is enabled
        if not apiconf.filecreate.get("enabled"):
            resp = {"error": True, "error_value": "File Create API is Disabled"}
            return Response(resp)
        # Check if files are actually provided
        if request.FILES.getlist("file") == []:
            resp = {"error": True, "error_value": "No file was submitted"}
            return Response(resp)
        resp["error"] = []
        try:
            _tenant_id, _visibility = submission_scope(request)
        except ValueError:
            return Response({"error": True, "error_value": "invalid visibility"})
        # Parse potential POST options (see submission/views.py)
        pcap = request.data.get("pcap", "")

        (
            static,
            package,
            timeout,
            priority,
            options,
            machine,
            platform,
            tags,
            custom,
            memory,
            clock,
            enforce_timeout,
            unique,
            referrer,
            tlp,
            tags_tasks,
            route,
            cape,
        ) = parse_request_arguments(request, keyword="data")

        details = {
            "errors": [],
            "request": request,
            "task_ids": [],
            "url": False,
            "params": {},
            "headers": {},
            "service": "tasks_create_file_API",
            "fhash": False,
            "options": options,
            "only_extraction": False,
            "user_id": request.user.id or 0,
            "tenant_id": _tenant_id,
            "visibility": _visibility,
        }

        task_machines = []
        vm_list = [vm.label for vm in db.list_machines()]

        if machine.lower() == "all":
            if not apiconf.filecreate.get("allmachines"):
                resp = {"error": True, "error_value": "Machine=all is disabled using the API"}
                return Response(resp)
            for entry in vm_list:
                task_machines.append(entry)
        else:
            # Check if VM is in our machines table
            if machine == "" or machine in vm_list:
                task_machines.append(machine)
            else:
                resp = {
                    "error": True,
                    "error_value": f"Machine '{machine}' does not exist. Available: {', '.join(vm_list)}",
                }
                return Response(resp)

        files = []
        # Check if we are allowing multiple file submissions
        multifile = apiconf.filecreate.get("multifile")
        if multifile:
            files = request.FILES.getlist("file")
        else:
            files = [request.FILES.getlist("file")[0]]

        opt_filename = get_user_filename(options, custom)
        list_of_tasks, details = process_new_task_files(request, files, details, opt_filename, unique)

        for content, tmp_path, _ in list_of_tasks:
            if pcap:
                if tmp_path.lower().endswith(b".saz"):
                    saz = saz_to_pcap(tmp_path)
                    if saz:
                        try:
                            path_delete(tmp_path)
                        except Exception as e:
                            print(e, "removing pcap")
                        tmp_path = saz
                    else:
                        details["error"].append({os.path.basename(tmp_path): "Failed to convert SAZ to PCAP"})
                        continue
                # Carry the submitter's tenancy (same scope the other create
                # branches use via details) — otherwise add_pcap's defaults
                # (user_id=0, tenant_id=None, visibility=private) make a tenant
                # user's own PCAP task invisible to them in locked mode.
                task_id = db.add_pcap(
                    file_path=tmp_path,
                    user_id=details["user_id"],
                    tenant_id=details["tenant_id"],
                    visibility=details["visibility"],
                )
                details["task_ids"].append(task_id)
                continue
            if static:
                task_id = db.add_static(file_path=tmp_path, priority=priority, user_id=request.user.id or 0, tenant_id=_tenant_id, visibility=_visibility)
                details["task_ids"].append(task_id)
                continue
            if tmp_path:
                details["path"] = tmp_path
                details["content"] = content

                status, tasks_details = download_file(**details)
                if status == "error":
                    details["errors"].append({os.path.basename(tmp_path).decode(): tasks_details})
                else:
                    details["task_ids"] = tasks_details.get("task_ids")
                    if tasks_details.get("errors"):
                        details["errors"].extend(tasks_details["errors"])

        if details["task_ids"]:
            tasks_count = len(details["task_ids"])
        else:
            tasks_count = 0
        if tasks_count > 0:
            resp["data"] = {}
            resp["errors"] = details["errors"]
            resp["data"]["task_ids"] = details.get("task_ids", [])
            callback = apiconf.filecreate.get("status")
            if len(details["task_ids"]) == 1:
                resp["data"]["message"] = "Task ID {0} has been submitted".format(str(details.get("task_ids", [])[0]))
                if callback:
                    resp["url"] = ["{0}/submit/status/{1}/".format(apiconf.api.get("url"), details.get("task_ids", [])[0])]
            else:
                resp["data"]["message"] = "Task IDs {0} have been submitted".format(
                    ", ".join(str(x) for x in details.get("task_ids", []))
                )
                if callback:
                    resp["url"] = []
                    for tid in details.get("task_ids", []):
                        resp["url"].append("{0}/submit/status/{1}".format(apiconf.api.get("url"), tid))
        else:
            resp = {"error": True, "error_value": "Error adding task to database", "errors": details["errors"]}

    return Response(resp)


@csrf_exempt
@api_view(["POST"])
def tasks_create_url(request):
    if not apiconf.urlcreate.get("enabled"):
        resp = {"error": True, "error_value": "URL Create API is Disabled"}
        return Response(resp)

    resp = {}
    if request.method == "POST":
        resp["error"] = []
        try:
            _tenant_id, _visibility = submission_scope(request)
        except ValueError:
            return Response({"error": True, "error_value": "invalid visibility"})

        url = request.data.get("url")
        (
            static,
            package,
            timeout,
            priority,
            options,
            machine,
            platform,
            tags,
            custom,
            memory,
            clock,
            enforce_timeout,
            unique,
            referrer,
            tlp,
            tags_tasks,
            route,
            cape,
        ) = parse_request_arguments(request, keyword="data")

        task_ids = []
        task_machines = []
        vm_list = [vm.label for vm in db.list_machines()]

        if not url:
            resp = {"error": True, "error_value": "URL value is empty"}
            return Response(resp)

        if machine.lower() == "all":
            if not apiconf.filecreate.get("allmachines"):
                resp = {"error": True, "error_value": "Machine=all is disabled using the API"}
                return Response(resp)
            for entry in vm_list:
                task_machines.append(entry)
        else:
            # Check if VM is in our machines table
            if machine == "" or machine in vm_list:
                task_machines.append(machine)
            # Error if its not
            else:
                resp = {
                    "error": True,
                    "error_value": "Machine '{0}' does not exist. Available: {1}".format(machine, ", ".join(vm_list)),
                }
                return Response(resp)

        if referrer:
            if options:
                options += ","
            options += "referrer=%s" % (referrer)

        for entry in task_machines:
            task_id = db.add_url(
                url=url,
                package=package,
                timeout=timeout,
                priority=priority,
                options=options,
                machine=entry,
                platform=platform,
                tags=tags,
                custom=custom,
                memory=memory,
                enforce_timeout=enforce_timeout,
                clock=clock,
                route=route,
                cape=cape,
                tlp=tlp,
                tags_tasks=tags_tasks,
                user_id=request.user.id or 0,
                tenant_id=_tenant_id,
                visibility=_visibility,
            )
            if task_id:
                task_ids.append(task_id)

        if len(task_ids):
            resp["data"] = {}
            resp["data"]["task_ids"] = task_ids
            resp["data"]["message"] = "Task ID {0} has been submitted".format(str(task_ids[0]))
            if apiconf.urlcreate.get("status"):
                resp["url"] = ["{0}/submit/status/{1}".format(apiconf.api.get("url"), task_ids[0])]
        else:
            resp = {"error": True, "error_value": "Error adding task to database"}
    else:
        resp = {"error": True, "error_value": "Method not allowed"}

    return Response(resp)


@csrf_exempt
@api_view(["POST"])
def tasks_create_dlnexec(request):
    resp = {}
    if request.method == "POST":
        if not apiconf.dlnexeccreate.get("enabled"):
            resp = {"error": True, "error_value": "DL&Exec Create API is Disabled"}
            return Response(resp)

        resp["error"] = []
        try:
            _tenant_id, _visibility = submission_scope(request)
        except ValueError:
            return Response({"error": True, "error_value": "invalid visibility"})
        url = request.data.get("dlnexec")
        if not url:
            resp = {"error": True, "error_value": "URL value is empty"}
            return Response(resp)

        (
            static,
            package,
            timeout,
            priority,
            options,
            machine,
            platform,
            tags,
            custom,
            memory,
            clock,
            enforce_timeout,
            unique,
            referrer,
            tlp,
            tags_tasks,
            route,
            cape,
        ) = parse_request_arguments(request, keyword="data")

        details = {}
        task_machines = []
        vm_list = [vm.label for vm in db.list_machines()]

        if machine.lower() == "all":
            if not apiconf.dlnexeccreate.get("allmachines"):
                resp = {"error": True, "error_value": "Machine=all is disabled using the API"}
                return Response(resp)
            for entry in vm_list:
                task_machines.append(entry)
        else:
            # Check if VM is in our machines table
            if machine == "" or machine in vm_list:
                task_machines.append(machine)
            # Error if its not
            else:
                resp = {
                    "error": True,
                    "error_value": "Machine '{0}' does not exist. Available: {1}".format(machine, ", ".join(vm_list)),
                }
                return Response(resp)

        path, content, _ = process_new_dlnexec_task(url, route, options, custom)
        if not path:
            return Response({"error": "Was impossible to retrieve url"})

        details = {
            "errors": [],
            "content": content,
            "request": request,
            "task_ids": [],
            "url": False,
            "params": {},
            "headers": {},
            "service": "tasks_create_dlnexec_API",
            "path": path,
            "fhash": False,
            "options": options,
            "only_extraction": False,
            "user_id": request.user.id or 0,
            "tenant_id": _tenant_id,
            "visibility": _visibility,
        }

        status, tasks_details = download_file(**details)
        if status == "error":
            details["errors"].append({os.path.basename(path).decode(): tasks_details})
        else:
            details["task_ids"] = tasks_details.get("task_ids")
            if tasks_details.get("errors"):
                details["errors"].extend(tasks_details["errors"])

        if details["task_ids"]:
            tasks_count = len(details["task_ids"])
        else:
            tasks_count = 0
        if tasks_count > 0:
            resp["data"] = {}
            resp["errors"] = details["errors"]
            resp["data"]["task_ids"] = details.get("task_ids")
            if len(details.get("task_ids")) == 1:
                resp["data"]["message"] = "Task ID {0} has been submitted".format(str(details.get("task_ids", [])[0]))
            else:
                resp["data"]["message"] = "Task IDs {0} have been submitted".format(
                    ", ".join(str(x) for x in details.get("task_ids", []))
                )
        else:
            resp = {"error": True, "error_value": "Error adding task to database", "errors": details["errors"]}
    else:
        resp = {"error": True, "error_value": "Method not allowed"}

    return Response(resp)


# Return Sample information.
@csrf_exempt
@api_view(["GET"])
def files_view(request, md5=None, sha1=None, sha256=None, sample_id=None):
    if not apiconf.fileview.get("enabled"):
        resp = {"error": True, "error_value": "File View API is Disabled"}
        return Response(resp)

    _denied = _deny_by_hash(request, md5=md5, sha1=sha1, sha256=sha256, sample_id=sample_id)
    if _denied is not None:
        return _denied

    resp = {}
    if md5 or sha1 or sha256 or sample_id:
        resp["error"] = []
        """
        for key, value in (("md5", md5), ("sha1", sha1), ("sha256", sha256), ("id", sample_id)):
            if value:
                if not apiconf.fileview.get(key):
                    resp = {"error": True, "error_value": f"File View by {key.upper()} is Disabled"}
                    return Response(resp)
        """
        if md5:
            if not apiconf.fileview.get("md5"):
                resp = {"error": True, "error_value": "File View by MD5 is Disabled"}
                return Response(resp)

            sample = db.find_sample(md5=md5)
        elif sha1:
            if not apiconf.fileview.get("sha1"):
                resp = {"error": True, "error_value": "File View by SHA1 is Disabled"}
                return Response(resp)

            sample = db.find_sample(sha1=sha1)
        elif sha256:
            if not apiconf.fileview.get("sha256"):
                resp = {"error": True, "error_value": "File View by SHA256 is Disabled"}
                return Response(resp)

            sample = db.find_sample(sha256=sha256)
        elif sample_id:
            if not apiconf.fileview.get("id"):
                resp = {"error": True, "error_value": "File View by ID is Disabled"}
                return Response(resp)

            sample = db.view_sample(sample_id)
        if sample:
            resp["data"] = _strip_mt_sample_fields(sample.to_dict())
        else:
            resp = {"error": True, "error_value": "Sample not found in database"}

    return Response(resp)


# Return Task ID's and data that match a hash.
@csrf_exempt
@api_view(["GET"])
def tasks_search(request, md5=None, sha1=None, sha256=None):
    resp = {}

    if not apiconf.tasksearch.get("enabled"):
        resp = {"error": True, "error_value": "Task Search API is Disabled"}
        return Response(resp)

    if md5 or sha1 or sha256:
        resp["error"] = []
        if md5:
            if not apiconf.tasksearch.get("md5"):
                resp = {"error": True, "error_value": "Task Search by MD5 is Disabled"}
                return Response(resp)

            sample = db.find_sample(md5=md5)
        elif sha1:
            if not apiconf.tasksearch.get("sha1"):
                resp = {"error": True, "error_value": "Task Search by SHA1 is Disabled"}
                return Response(resp)

            sample = db.find_sample(sha1=sha1)
        elif sha256:
            if not apiconf.tasksearch.get("sha256"):
                resp = {"error": True, "error_value": "Task Search by SHA256 is Disabled"}
                return Response(resp)

            sample = db.find_sample(sha256=sha256)
        if sample:
            samples = db.find_sample(parent=sample.id)
            if samples:
                sids = [tmp_sample.to_dict()["id"] for tmp_sample in samples]
            else:
                sids = [sample.to_dict()["id"]]
            resp["data"] = []
            for sid in sids:
                tasks = db.list_tasks(sample_id=sid, include_hashes=True, visible_to=viewer_for(request.user))
                for task in tasks:
                    buf = _strip_mt_task_fields(task.to_dict())
                    # Remove path information, just grab the file name
                    buf["target"] = buf["target"].rsplit("/", 1)[-1]
                    if task.sample:
                        buf["sample"] = _strip_mt_sample_fields(task.sample.to_dict())
                    resp["data"].append(buf)
            # No visible task for this sample => respond byte-identically to
            # "sample absent" so the error-field doesn't become a cross-tenant
            # existence oracle (mirror _deny_by_hash). Break-glass / MT-disabled
            # keeps the {"error": []} shape (back-compat, no-op).
            if not resp["data"] and not viewer_for(request.user).is_local_admin:
                resp = {"data": [], "error": False}
        else:
            resp = {"data": [], "error": False}

    return Response(resp)


# ToDo requires proper review and rewrite
# Return Task ID's and data that match a hash.
@csrf_exempt
@api_view(["POST"])
def ext_tasks_search(request):
    resp = {}

    if not apiconf.extendedtasksearch.get("enabled"):
        resp = {"error": True, "error_value": "Extended Task Search API is Disabled"}
        return Response(resp)

    return_data = []
    term = request.data.get("option", "")
    value = request.data.get("argument", "")
    search_limit = request.data.get("search_limit", 50)

    if term and value:
        records = False
        if term not in search_term_map and term not in ("malscore", "ttp"):
            resp = {"error": True, "error_value": "Invalid Option. '%s' is not a valid option." % term}
            return Response(resp)

        if term == "tags_tasks":
            value = [int(v.id) for v in db.list_tasks(tags_tasks_like=value, limit=int(search_limit), visible_to=viewer_for(request.user))]
            term = "ids"
        elif term == "options":
            value = [int(v.id) for v in db.list_tasks(options_like=value, limit=search_limit, visible_to=viewer_for(request.user))]
            term = "ids"
        elif term == "ids":
            if all([v.strip().isdigit() for v in value.split(",")]):
                value = [int(v.strip()) for v in filter(None, value.split(","))]
            else:
                return Response({"error": True, "error_value": "Not all values are integers"})
            tmp_value = []
            for task in db.list_tasks(task_ids=value, visible_to=viewer_for(request.user)) or []:
                if task.status == "reported":
                    tmp_value.append(task.id)
                else:
                    return_data.append({"analysis": {"status": task.status, "id": task.id}})
            value = tmp_value
            del tmp_value
        try:
            projection = lean_search_filters if request.data.get("lean") else None
            records = perform_search(term, value, user_id=request.user.id, privs=request.user.is_staff, web=False, projection=projection, viewer=viewer_for(request.user))
        except ValueError:
            if not term:
                resp = {"error": True, "error_value": "No option provided."}
            if not value:
                resp = {"error": True, "error_value": "No argument provided."}
            if not term and not value:
                resp = {"error": True, "error_value": "No option or argument provided."}

        if records:
            _viewer = viewer_for(request.user)
            if _viewer.is_local_admin:
                # Break-glass / multitenancy-disabled: no isolation to enforce, so
                # append every record exactly as upstream did (no _visible build,
                # no per-record drop). Keeps default-install output byte-identical.
                for results in records:
                    if repconf.mongodb.enabled:
                        return_data.append(results)
                    if es_as_db:
                        return_data.append(results["_source"])
            else:
                # Visibility filter: the mongo/ES report rows don't carry tenant info,
                # so resolve the visible set in ONE query (list_tasks(visible_to=))
                # instead of a view_task() per row, then drop rows the viewer can't see.
                _tids = set()
                for results in records:
                    _doc = results.get("_source", results) if es_as_db else results
                    _tid = (_doc.get("info") or {}).get("id") if isinstance(_doc, dict) else None
                    if _tid is not None:
                        try:
                            _tids.add(int(_tid))
                        except (ValueError, TypeError):
                            pass
                _visible = {t.id for t in db.list_tasks(task_ids=list(_tids), visible_to=_viewer)} if _tids else set()
                for results in records:
                    _doc = results.get("_source", results) if es_as_db else results
                    _tid = (_doc.get("info") or {}).get("id") if isinstance(_doc, dict) else None
                    try:
                        if _tid is None or int(_tid) not in _visible:
                            continue
                    except (ValueError, TypeError):
                        continue
                    if repconf.mongodb.enabled:
                        return_data.append(results)
                    if es_as_db:
                        return_data.append(results["_source"])

            resp = {"error": False, "data": return_data}
        else:
            if not return_data:
                resp = {"error": True, "error_value": "Unable to retrieve records"}
            else:
                resp = {"error": False, "data": return_data}
    else:
        if not term:
            resp = {"error": True, "error_value": "No option provided."}
        if not value:
            resp = {"error": True, "error_value": "No argument provided."}
        if not term and not value:
            resp = {"error": True, "error_value": "No option or argument provided."}

    return Response(resp)


# Return Task ID's and data within a range of Task ID's
@csrf_exempt
@api_view(["GET"])
def tasks_list(request, offset=None, limit=None, window=None):
    if not apiconf.tasklist.get("enabled"):
        resp = {"error": True, "error_value": "Task List API is Disabled"}
        return Response(resp)

    resp = {}
    # Limit checks
    if not limit:
        limit = int(apiconf.tasklist.get("defaultlimit"))
    if int(limit) > int(apiconf.tasklist.get("maxlimit")):
        resp = {"warning": "Task limit exceeds API configured limit."}
        limit = int(apiconf.tasklist.get("maxlimit"))

    completed_after = request.query_params.get("completed_after")
    ids_only = request.query_params.get("ids")
    if completed_after:
        completed_after = datetime.fromtimestamp(int(completed_after))

    if not completed_after and window:
        maxwindow = apiconf.tasklist.get("maxwindow")
        if maxwindow > 0:
            if int(window) > maxwindow:
                resp = {"error": True, "error_value": "The Window You Specified is greater than the configured maximum"}
                return Response(resp)
        completed_after = datetime.now() - timedelta(minutes=int(window))

    status = request.query_params.get("status")
    option = request.query_params.get("option")
    category = request.query_params.get("category")

    if offset:
        offset = int(offset)
    resp["data"] = []
    resp["config"] = "Limit: {0}, Offset: {1}".format(limit, offset)
    resp["buf"] = 0

    tasks = db.list_tasks(
        limit=limit,
        details=True,
        category=category,
        offset=offset,
        completed_after=completed_after,
        status=status,
        options_like=option,
        order_by=Task.completed_on.desc(),
        include_hashes=True,
        visible_to=viewer_for(request.user),
    )

    if not tasks:
        return Response(resp)

    # Dist.py fetches only ids
    if ids_only:
        resp["data"] = [{"id": task.id} for task in tasks]
    else:
        for row in tasks:
            resp["buf"] += 1
            task = _strip_mt_task_fields(row.to_dict())
            task["guest"] = {}
            if row.guest:
                task["guest"] = row.guest.to_dict()

            task["errors"] = []
            for error in row.errors:
                task["errors"].append(error.message)

            task["sample"] = {}
            if row.sample:
                task["sample"] = _strip_mt_sample_fields(row.sample.to_dict())

            if task.get("target"):
                task["target"] = convert_to_printable(task["target"])

            resp["data"].append(task)

    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_view(request, task_id):
    if not apiconf.taskview.get("enabled"):
        resp = {"error": True, "error_value": "Task View API is Disabled"}
        return Response(resp)

    task = db.view_task(task_id, details=True)
    _denied = _deny_if_hidden(request, task)
    if _denied is not None:
        return _denied
    # Missing task: with MT off _deny_if_hidden defers (returns None), so restore
    # upstream's explicit missing-task response here. No-op under MT, where the
    # helper already returned the generic 404 for a missing/hidden task.
    if not task:
        resp = {"error": True, "error_value": "Task not found in database"}
        return Response(resp)

    resp = {"error": False}
    entry = _strip_mt_task_fields(task.to_dict())
    if entry["category"] != "url":
        entry["target"] = entry["target"].rsplit("/", 1)[-1]
    entry["guest"] = {}
    if task.guest:
        entry["guest"] = task.guest.to_dict()

    entry["errors"] = []
    for error in task.errors:
        entry["errors"].append(error.message)

    entry["sample"] = {}
    if task.sample_id:
        sample = db.view_sample(task.sample_id)
        entry["sample"] = _strip_mt_sample_fields(sample.to_dict())

    if task.status == TASK_RECOVERED and task.custom:
        m = re.match(r"^Recovery_(?P<taskid>\d+)$", task.custom)
        if m:
            task_id = int(m.group("taskid"))
            task = db.view_task(task_id, details=True)
            # Recovery_<N> can point at another tenant's task; re-gate the RESOLVED
            # task before rebuilding/serving its data, sample, and mongo doc — the
            # gate at the top only authorized the originally-requested id.
            _denied = _deny_if_hidden(request, task)
            if _denied is not None:
                return _denied
            resp["error"] = []
            if task:
                entry = _strip_mt_task_fields(task.to_dict())
                if entry["category"] != "url":
                    entry["target"] = entry["target"].rsplit("/", 1)[-1]
                    entry["guest"] = {}
                if task.guest:
                    entry["guest"] = task.guest.to_dict()
                entry["errors"] = []
                for error in task.errors:
                    entry["errors"].append(error.message)
                entry["sample"] = {}
                if task.sample_id:
                    sample = db.view_sample(task.sample_id)
                    entry["sample"] = _strip_mt_sample_fields(sample.to_dict())

    if repconf.mongodb.enabled:
        rtmp = mongo_find_one(
            "analysis",
            _analysis_filter(request, task.id),
            {
                "info": 1,
                "virustotal_summary": 1,
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

    rtmp = None
    if es_as_db:
        rtmp = es.search(
            index=get_analysis_index(),
            query=get_query_by_info_id(str(task.id)),
            _source=[
                "info",
                "virustotal_summary",
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
                entry[keyword] = rtmp[keyword]

        if "info" in rtmp:
            for keyword in ("custom", "package"):
                if rtmp["info"].get(keyword, False):
                    entry[keyword] = rtmp["info"][keyword]

        if "network" in rtmp and "pcap_sha256" in rtmp["network"]:
            entry["pcap_sha256"] = rtmp["network"]["pcap_sha256"]

        if rtmp.get("target", {}).get("file", False):
            for keyword in ("clamav", "trid"):
                if rtmp["info"].get(keyword, False):
                    entry[keyword] = rtmp["info"]["target"][keyword]

        if settings.MOLOCH_ENABLED:
            if settings.MOLOCH_BASE[-1] != "/":
                settings.MOLOCH_BASE += "/"
            entry["moloch_url"] = (
                settings.MOLOCH_BASE
                + "?date=-1&expression=tags"
                + quote("\x3d\x3d\x22%s\x3a%s\x22" % (settings.MOLOCH_NODE, task.id), safe="")
            )

    resp["data"] = entry
    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_reschedule(request, task_id):
    if not apiconf.taskresched.get("enabled"):
        resp = {"error": True, "error_value": "Task Reschedule API is Disabled"}
        return Response(resp)

    _denied = _deny_manage(request, task_id)
    if _denied is not None:
        return _denied

    resp = {}
    new_task_id = db.reschedule(task_id)
    if new_task_id:
        resp["error"] = []
        resp["data"] = {}
        resp["data"]["new_task_id"] = new_task_id
        resp["data"]["message"] = "Task ID {0} has been rescheduled".format(task_id)
    else:
        resp = {
            "error": True,
            "error_value": "An error occurred while trying to reschedule Task ID {0}".format(task_id),
        }

    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_reprocess(request, task_id):
    resp = {}
    if not apiconf.taskreprocess.get("enabled"):
        resp["error"] = True
        resp["error_value"] = "Task Reprocess API is Disabled"
        return Response(resp)

    _denied = _deny_manage(request, task_id)
    if _denied is not None:
        return _denied

    error, msg, task_status = db.tasks_reprocess(task_id)
    if error:
        return Response({"error": True, "error_value": msg})

    return Response({"error": error, "data": f"Task ID {task_id} with status {task_status} marked for reprocessing"})


@csrf_exempt
@api_view(["GET"])
def tasks_delete(request, task_id, status=False):
    """
    task_id: int or string if many
    example: 1 or 1,2,3,4 or 1-4

    """
    if not (apiconf.taskdelete.get("enabled") or request.user.is_staff):
        resp = {"error": True, "error_value": "Task Deletion API is Disabled"}
        return Response(resp)

    if isinstance(task_id, int):
        task_id = [task_id]
    elif "-" in task_id:
        start, end = map(force_int, task_id.split("-"))
        if start > end:
            resp = {"error": True, "error_value": "Start Task ID is bigger than End Task ID"}
            return Response(resp)
        else:
            task_id = list(range(start, end + 1))
    else:
        task_id = [force_int(task.strip()) for task in task_id.split(",")]

    resp = {}
    s_deleted = []
    f_deleted = []
    orphaned = []  # SQL row deleted, but its Mongo report couldn't be erased -> NOT retryable as a task delete
    for task in task_id:
        check = validate_task(task, status)
        if check["error"]:
            f_deleted.append(str(task))
            continue
        # tenant isolation: only delete tasks the caller may manage
        _t = db.view_task(task)
        if not can_manage_task(request.user, _t):
            f_deleted.append(str(task))
            continue

        # Resolve the task's OWN tenant WHILE the SQL row exists (central_delete_analysis uses it to scope the
        # Mongo delete). Commit the SQL delete BEFORE the irreversible folder/Mongo deletes: db.delete_task only
        # STAGES (the middleware commits after the view), and the Mongo delete is immediate + non-transactional,
        # so committing first prevents a later-iteration rollback from resurrecting the row over an already-gone
        # report. THREE outcomes, distinguished in the response so a client knows what to retry:
        #   - f_deleted  -> NOT deleted; cause VARIES (invalid/absent id, not permitted, row already gone, OR a
        #     genuine pre-commit exception which IS rolled back + retryable). Only the last is transient -- a
        #     client must not blind-retry the whole bucket.
        #   - orphaned   -> task IS gone but its report couldn't be erased; NOT retryable (a task-delete retry
        #     answers "not exists"; the Mongo doc + S3 need a reaper), so surfaced distinctly, not as success
        #     NOR as a retryable "failed".
        #   - s_deleted  -> deleted; the report is erased ONLY when web.conf [web_reporting] enabled is on
        #     (the _central gate below + :central_delete_analysis) -- that flag ships `no` and is the GUI-serving
        #     switch, NOT the Mongo-backend switch, so with it off the report is RETAINED and still reported here
        #     as deleted, while tasks_delete_many (ungated on this flag) WOULD erase it. That cross-endpoint
        #     divergence is pre-existing upstream gating; unifying it (gate both on the Mongo-backend flag) is a
        #     surfaced design call, not changed here. A folder-delete failure alone is a logged disk orphan.
        _central = web_conf.web_reporting.get("enabled", True)
        _tenant = getattr(_t, "tenant_id", None) if _central else None
        try:
            if not db.delete_task(task):
                f_deleted.append(str(task))
                continue
            db.session.commit()
        except Exception as _de:
            try:
                db.session.rollback()  # staged delete must not survive; also clears a pending-rollback session
            except Exception:
                pass
            log.error("tasks_delete: task %s SQL delete failed (rolled back, retryable): %s", task, _de)
            f_deleted.append(str(task))
            continue
        # SEPARATE guards: a folder-delete failure must NOT skip the Mongo/central delete (a shared try would
        # orphan the analysis doc + S3 artifacts -- the more serious leak -- on a mere disk error). A folder
        # failure degrades to a disk orphan-by-path (logged, still counts as deleted); a report-delete failure
        # is surfaced SEPARATELY as `orphaned` -> resp["orphaned"], NOT as f_deleted: the SQL row is already
        # committed away, so it's an unreapable doc rather than a retryable delete.
        # CAVEAT: this only fires if central_delete_analysis RAISES -- true for a central-mode OperationFailure
        # (auth expiry / primary stepdown), but NOT for a mongo_delete_data-swallowed failure (the non-central
        # arm, or an exhausted-AutoReconnect None return), which is logged-and-swallowed below it. Fully closing
        # that needs a status-returning Mongo delete (tracked follow-up; same limitation noted in delete_data).
        try:
            delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task))
        except Exception as _fe:
            log.error("tasks_delete: task %s folder delete failed (disk orphan-by-path): %s", task, _fe)
        try:
            if _central:
                central_delete_analysis(request, task, tenant_id=_tenant)
        except Exception as _ce:
            log.error("tasks_delete: task %s report delete FAILED (Mongo doc + S3 orphaned, unreapable): %s", task, _ce)
            orphaned.append(str(task))
            continue
        s_deleted.append(str(task))

    if s_deleted:
        resp["data"] = "Task(s) ID(s) {0} has been deleted".format(",".join(s_deleted))

    if f_deleted:
        resp["error"] = True
        resp["failed"] = "Task(s) ID(s) {0} failed to remove".format(",".join(f_deleted))

    if orphaned:
        # Task rows are gone but their reports could not be erased -- distinct from "failed" (retryable): these
        # need out-of-band reaping, not a task-delete retry (which would answer "not exists").
        resp["error"] = True
        resp["orphaned"] = "Task(s) ID(s) {0} deleted but report NOT erased (orphaned, needs reaping)".format(
            ",".join(orphaned))

    return Response(resp)


# Re-enable session-cookie auth so the in-browser "End Session" button works
# under SSO deployments where the global DRF chain is API-key-only.
@csrf_exempt
@api_view(["GET", "POST"])
def tasks_status(request, task_id):
    if not apiconf.taskstatus.get("enabled"):
        resp = {"error": True, "error_value": "Task status API is disabled"}
        return Response(resp)

    resp = {}
    task = db.view_task(task_id)
    _denied = _deny_if_hidden(request, task)
    if _denied is not None:
        return _denied
    # MT off: _deny_if_hidden defers on a missing task -> restore upstream's
    # explicit response (no-op under MT, which already 404'd missing/hidden).
    if not task:
        resp = {"error": True, "error_value": "Task does not exist"}
        return Response(resp)
    if request.method == "GET":
        status = task.to_dict()["status"]
        resp = {"error": False, "data": status}
    elif request.method == "POST" and apiconf.user_stop.enabled and request.data.get("status", "") == "finish":
        # Stopping/finishing a running analysis is a MUTATION — require manage
        # rights (owner / tenant-admin / break-glass), not just read visibility,
        # so a same-tenant read-only user can't end another user's analysis.
        if not can_manage_task(request.user, task):
            return Response({"error": True, "error_value": "Access denied"}, status=403)
        machine = db.view_machine(task.guest.name)
        # Todo probably add task status if pending
        if machine.status == "running":
            try:
                guest_env = requests.get(f"http://{machine.ip}:8000/environ").json()
                complete_folder = hashlib.md5(f"cape-{task_id}".encode()).hexdigest()
                if machine.platform == "windows":
                    dest_folder = f"{guest_env['environ']['TMP']}\\{complete_folder}"
                elif machine.platform == "linux":
                    dest_folder = f"{guest_env['environ'].get('TMP', '/tmp')}/{complete_folder}"
                r = requests.post(f"http://{machine.ip}:8000/mkdir", data={"dirpath": dest_folder})
                resp = {"error": r.status_code == 200, "data": r.text}
            except requests.exceptions.ConnectionError as e:
                log.error(e)
    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_report(request, task_id, report_format="json", make_zip=False):
    if not apiconf.taskreport.get("enabled"):
        resp = {"error": True, "error_value": "Task Report API is Disabled"}
        return Response(resp)

    allow_dl = False
    if hasattr(request.user, "userprofile") and request.user.userprofile.reports:
        allow_dl = True
    # check if allowed to download to all + if no if user has permissions
    if not settings.ALLOW_DL_REPORTS_TO_ALL and allow_dl is False:
        return render(
            request,
            "error.html",
            {"error": "You don't have permissions to download reports. Ask admin to enable it for you in user profile."},
        )

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    formats = {
        "protobuf": "report.protobuf",
        "json": "report.json",
        "html": "report.html",
        "htmlsummary": "summary-report.html",
        "pdf": "report.pdf",
        "maec": "report.maec-4.1.xml",
        "maec5": "report.maec-5.0.json",
        "metadata": "report.metadata.xml",
        "litereport": "lite.json",
        "parti": "report.parti",
    }

    report_formats = {
        # Use the 'all' option if you want all generated files except for memory.dmp and derived pcaps
        "all": {
            "type": "-",
            "files": [
                "memory.dmp",
                "dump.pcapng",
                "dump_decrypted.pcap",
                "dump_mixed.pcap",
                "dump_mixed_sorted.pcap",
                "dump_sorted.pcap",
            ],
        },
        # Use the 'dropped' option if you want all dropped files found in the /files directory
        "dropped": {"type": "+", "files": ["files"]},
        # Use the 'dist' option if you want all generated files except for binary, dump_sorted.pcap, memory.dmp, and
        # those found in the /logs directory
        "dist": {"type": "-", "files": ["binary", "dump_sorted.pcap", "memory.dmp", "logs"]},
        #  Use the 'lite' option if you want the generated files files.json, dump.pcap, and those found
        # in the /CAPE, /files, /procdump, /macros and /shots directories
        "lite": {
            "type": "+",
            "files": [
                "files.json",
                "CAPE",
                "files",
                "procdump",
                "macros",
                "shots",
                "dump.pcap",
                "selfextracted",
                "evtx",
                "tlsdump",
            ],
        },
    }

    # Validate the requested format BEFORE staging: a typo'd/unknown format is a 4xx client error, and staging
    # first would materialize the whole analysis tree onto the web node (central mode) only to reject. Then
    # gate the 'all' bulk archive before staging too, so a refused request never stages / writes the marker.
    # NORMALIZE report_format to lowercase here so the content-type chain below (which compares the raw value
    # and has no trailing else) can't be reached with a mixed-case format that passed the .lower() gate and
    # then falls through unbound -> NameError/500 (the \w+ route otherwise allows e.g. /report/<id>/JSON/).
    report_format = report_format.lower()
    if report_format not in formats and report_format not in report_formats:
        return Response({"error": True, "error_value": f"Report format not found: {report_format}"}, status=400)
    if report_format == "all" and not apiconf.taskreport.get("all"):
        return Response({"error": True, "error_value": "Downloading all reports in one call is disabled"})

    _central_stage(request, task_id)

    resp = {}

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports")
    if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found {os.path.basename(srcdir)}"})

    # Report validity check
    if path_exists(srcdir) and len(os.listdir(srcdir)) == 0:
        resp = {"error": True, "error_value": "No reports created for task %s" % task_id}

    if report_format.lower() in formats:
        report_path = os.path.join(srcdir, formats[report_format.lower()])
        if not os.path.normpath(report_path).startswith(ANALYSIS_BASE_PATH):
            return render(request, "error.html", {"error": f"File not found {os.path.basename(report_path)}"})
        if path_exists(report_path):
            if report_format in ("litereport", "json", "maec5"):
                content = "application/json; charset=UTF-8"
                ext = "json"
            elif report_format.startswith("html"):
                content = "text/html"
                ext = "html"
            elif report_format in ("maec", "metadata"):
                content = "text/xml"
                ext = "xml"
            elif report_format == "pdf":
                content = "application/pdf"
                ext = "pdf"
            elif report_format == "protobuf":
                content = "application/octet-stream"
                ext = "protobuf"
            elif report_format == "parti":
                ext = "parti"
                content = "application/zip"
            fname = "%s_report.%s" % (task_id, ext)

            if make_zip:
                if os.path.exists(report_path + ".zip"):
                    report_path += ".zip"
                    resp = StreamingHttpResponse(
                        FileWrapper(open(report_path, "rb"), 8096), content_type="application/zip"
                    )
                    resp["Content-Length"] = os.path.getsize(report_path)
                    resp["Content-Disposition"] = "attachment; filename=" + fname
                else:
                    mem_zip = create_zip(files=report_path)
                    if mem_zip is False:
                        resp = {"error": True, "error_value": "Can't create zip archive for report file"}
                        return Response(resp)

                    resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
                    resp["Content-Length"] = len(mem_zip.getvalue())
                    resp["Content-Disposition"] = f"attachment; filename={report_format}.zip"
            else:
                resp = StreamingHttpResponse(
                    FileWrapper(open(report_path, "rb"), 8096), content_type=content or "application/octet-stream;"
                )
                resp["Content-Length"] = os.path.getsize(report_path)
                resp["Content-Disposition"] = "attachment; filename=" + fname

            return resp

        else:
            resp = {"error": True, "error_value": "Reports directory does not exist"}
            return Response(resp)

    elif report_format.lower() in report_formats:
        # ('all' gate + format validity are enforced before staging above.)
        report_files = report_formats[report_format.lower()]
        srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
        # Traversal guard is UNCONDITIONAL (an out-of-tree path is always an error, present or not) -- mirrors
        # the sibling endpoints (tasks_screenshot). The prior `and path_exists(srcdir)` conjunction only
        # errored when the path was BOTH out-of-tree AND existed, which was a copy-paste hazard.
        if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH):
            return render(request, "error.html", {"error": f"File not found {os.path.basename(srcdir)}"})
        # Separately guard a missing dir: in central mode _central_stage is best-effort (it swallows all
        # exceptions), so a stage that failed silently leaves no local analysis dir and the bare os.listdir
        # below would raise FileNotFoundError -> HTTP 500 instead of a clean JSON error.
        if not path_exists(srcdir):
            return Response({"error": True, "error_value": "No analysis directory for task %s" % task_id})

        mem_zip = BytesIO()
        with zipfile.ZipFile(mem_zip, "a", zipfile.ZIP_DEFLATED, False) as zf:
            for filedir in os.listdir(srcdir):
                try:
                    filepath = os.path.join(srcdir, filedir)
                    if report_files["type"] == "-" and filedir not in report_files["files"]:
                        if os.path.isdir(filepath):
                            for subfile in os.listdir(filepath):
                                zf.write(os.path.join(filepath, subfile), os.path.join(filedir, subfile))
                        else:
                            zf.write(filepath, filedir)
                    if report_files["type"] == "+" and filedir in report_files["files"]:
                        if os.path.isdir(filepath):
                            for subfile in os.listdir(filepath):
                                zf.write(os.path.join(filepath, subfile), os.path.join(filedir, subfile))
                        else:
                            zf.write(filepath, filedir)
                except Exception as e:
                    log.exception(e)

            # exception for lite report that is under reports/lite.json
            if report_format.lower() == "lite":
                lite_report_path = os.path.join(srcdir, "reports", "lite.json")
                if path_exists(lite_report_path):
                    zf.write(lite_report_path, "reports/lite.json")
                else:
                    log.warning("Lite report does not exist. Did you enable 'litereport' in reporting.conf?")

        mem_zip.seek(0)
        resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
        resp["Content-Length"] = len(mem_zip.getvalue())
        resp["Content-Disposition"] = f"attachment; filename={report_format.lower()}.zip"
        return resp

    else:
        resp = {"error": True, "error_value": "Invalid report format specified"}
        return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_iocs(request, task_id, detail=None):
    if not apiconf.taskiocs.get("enabled"):
        resp = {"error": True, "error_value": "IOC download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id)

    buf = {}
    if repconf.mongodb.get("enabled") and not buf:
        buf = mongo_find_one("analysis", _analysis_filter(request, task_id), {"behavior.calls": 0})
    if es_as_db and not buf:
        tmp = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"]
        if tmp:
            buf = tmp[-1]["_source"]
        else:
            buf = None
    if buf is None:
        resp = {"error": True, "error_value": "Sample not found in database"}
        return Response(resp)
    if repconf.jsondump.get("enabled") and not buf:
        jfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports", "report.json")
        # path_exists as well as the traversal guard: in central mode _central_stage is best-effort (it
        # swallows all exceptions), so a stage that failed silently leaves no local report.json and a bare
        # open() would raise FileNotFoundError -> HTTP 500 instead of the clean JSON error below (mirrors
        # tasks_selfextracted).
        if os.path.normpath(jfile).startswith(ANALYSIS_BASE_PATH) and path_exists(jfile):
            with open(jfile, "r") as jdata:
                buf = json.load(jdata)
    if not buf:
        resp = {"error": True, "error_value": "Unable to retrieve report to parse for IOCs"}
        return Response(resp)

    data = {}
    if "tr_extractor" in buf:
        data["tr_extractor"] = buf["tr_extractor"]
    if "certs" in buf:
        data["certs"] = buf["certs"]
    data["detections"] = buf.get("detections")
    data["malscore"] = buf["malscore"]
    data["info"] = buf["info"]
    del data["info"]["custom"]
    # The machines key won't exist in cases where an x64 binary is submitted
    # when there are no x64 machines.
    if data.get("info", {}).get("machine", {}) and isinstance(data["info"]["machine"], dict):
        del data["info"]["machine"]["manager"]
        del data["info"]["machine"]["label"]
        del data["info"]["machine"]["id"]
    data["signatures"] = []
    """
    # Grab sigs
    for sig in buf["signatures"]:
        del sig["alert"]
        data["signatures"].append(sig)
    """
    # Grab target file info
    if "target" in list(buf.keys()):
        data["target"] = buf["target"]
        if data["target"]["category"] == "file":
            del data["target"]["file"]["path"]
            del data["target"]["file"]["guest_paths"]

    data["network"] = {}
    if "network" in list(buf.keys()) and buf["network"]:
        data["network"]["traffic"] = {}
        for netitem in ("tcp", "udp", "irc", "http", "dns", "smtp", "hosts", "domains"):
            if netitem in buf["network"]:
                data["network"]["traffic"][netitem + "_count"] = len(buf["network"][netitem])
            else:
                data["network"]["traffic"][netitem + "_count"] = 0
        data["network"]["traffic"]["http"] = buf["network"]["http"]
        data["network"]["hosts"] = buf["network"]["hosts"]
        data["network"]["domains"] = buf["network"]["domains"]
    data["network"]["ids"] = {}
    if "suricata" in list(buf.keys()) and isinstance(buf["suricata"], dict):
        data["network"]["ids"]["totalalerts"] = len(buf["suricata"]["alerts"])
        data["network"]["ids"]["alerts"] = buf["suricata"]["alerts"]
        data["network"]["ids"]["http"] = buf["suricata"]["http"]
        data["network"]["ids"]["totalfiles"] = len(buf["suricata"]["files"])
        data["network"]["ids"]["files"] = []
        for surifile in buf["suricata"]["files"]:
            if "file_info" in list(surifile.keys()):
                tmpfile = surifile
                tmpfile["sha1"] = surifile["file_info"]["sha1"]
                tmpfile["md5"] = surifile["file_info"]["md5"]
                tmpfile["sha256"] = surifile["file_info"]["sha256"]
                tmpfile["sha512"] = surifile["file_info"]["sha512"]
                del tmpfile["file_info"]
                data["network"]["ids"]["files"].append(tmpfile)

    data["static"] = {}
    if "static" in list(buf.keys()):
        pe = {}
        pdf = {}
        office = {}
        if buf["static"].get("peid_signatures"):
            pe["peid_signatures"] = buf["static"]["peid_signatures"]
        if buf["static"].get("pe_timestamp"):
            pe["pe_timestamp"] = buf["static"]["pe_timestamp"]
        if buf["static"].get("pe_imphash"):
            pe["pe_imphash"] = buf["static"]["pe_imphash"]
        if buf["static"].get("pe_icon_hash"):
            pe["pe_icon_hash"] = buf["static"]["pe_icon_hash"]
        if buf["static"].get("pe_icon_fuzzy"):
            pe["pe_icon_fuzzy"] = buf["static"]["pe_icon_fuzzy"]
        if buf["static"].get("Objects"):
            pdf["objects"] = len(buf["static"]["Objects"])
        if buf["static"].get("Info"):
            if "PDF Header" in list(buf["static"]["Info"].keys()):
                pdf["header"] = buf["static"]["Info"]["PDF Header"]
        if "Streams" in buf["static"]:
            if "/Page" in list(buf["static"]["Streams"].keys()):
                pdf["pages"] = buf["static"]["Streams"]["/Page"]
        if buf["static"].get("Macro"):
            if "Analysis" in buf["static"]["Macro"]:
                office["signatures"] = {}
                for item in buf["static"]["Macro"]["Analysis"]:
                    office["signatures"][item] = []
                    for indicator, desc in buf["static"]["Macro"]["Analysis"][item]:
                        office["signatures"][item].append((indicator, desc))
            if "Code" in buf["static"]["Macro"]:
                office["macros"] = len(buf["static"]["Macro"]["Code"])
        data["static"]["pe"] = pe
        data["static"]["pdf"] = pdf
        data["static"]["office"] = office

    data["files"] = {}
    data["files"]["modified"] = []
    data["files"]["deleted"] = []
    data["registry"] = {}
    data["registry"]["modified"] = []
    data["registry"]["deleted"] = []
    data["mutexes"] = []
    data["executed_commands"] = []
    data["dropped"] = []

    if "behavior" in buf and "summary" in buf["behavior"]:
        if "write_files" in buf["behavior"]["summary"]:
            data["files"]["modified"] = buf["behavior"]["summary"]["write_files"]
        if "delete_files" in buf["behavior"]["summary"]:
            data["files"]["deleted"] = buf["behavior"]["summary"]["delete_files"]
        if "write_keys" in buf["behavior"]["summary"]:
            data["registry"]["modified"] = buf["behavior"]["summary"]["write_keys"]
        if "delete_keys" in buf["behavior"]["summary"]:
            data["registry"]["deleted"] = buf["behavior"]["summary"]["delete_keys"]
        if "mutexes" in buf["behavior"]["summary"]:
            data["mutexes"] = buf["behavior"]["summary"]["mutexes"]
        if "executed_commands" in buf["behavior"]["summary"]:
            data["executed_commands"] = buf["behavior"]["summary"]["executed_commands"]

    data["process_tree"] = {}
    if "behavior" in buf and "processtree" in buf["behavior"] and len(buf["behavior"]["processtree"]) > 0:
        data["process_tree"] = {
            "pid": buf["behavior"]["processtree"][0]["pid"],
            "name": buf["behavior"]["processtree"][0]["name"],
            "spawned_processes": [
                createProcessTreeNode(child_process) for child_process in buf["behavior"]["processtree"][0]["children"]
            ],
        }
    if "dropped" in buf:
        for entry in buf["dropped"]:
            tmpdict = {}
            if entry.get("clamav", False):
                tmpdict["clamav"] = entry["clamav"]
            if entry.get("sha256"):
                tmpdict["sha256"] = entry["sha256"]
            if entry.get("md5"):
                tmpdict["md5"] = entry["md5"]
            if entry.get("yara"):
                tmpdict["yara"] = entry["yara"]
            if entry.get("trid"):
                tmpdict["trid"] = entry["trid"]
            if entry.get("type"):
                tmpdict["type"] = entry["type"]
            if entry.get("guest_paths"):
                tmpdict["guest_paths"] = entry["guest_paths"]
            data["dropped"].append(tmpdict)

    if not detail:
        resp = {"error": False, "data": data}
        return Response(resp)

    if "static" in buf:
        if buf["static"].get("pe_versioninfo"):
            data["static"]["pe"]["pe_versioninfo"] = buf["static"]["pe_versioninfo"]

    if "behavior" in buf and "summary" in buf["behavior"]:
        if "read_files" in buf["behavior"]["summary"]:
            data["files"]["read"] = buf["behavior"]["summary"]["read_files"]
        if "read_keys" in buf["behavior"]["summary"]:
            data["registry"]["read"] = buf["behavior"]["summary"]["read_keys"]
        if "resolved_apis" in buf["behavior"]["summary"]:
            data["resolved_apis"] = buf["behavior"]["summary"]["resolved_apis"]

    if buf["network"] and "http" in buf["network"]:
        data["network"]["http"] = {}
        for req in buf["network"]["http"]:
            if "host" in req:
                data["network"]["http"]["host"] = req["host"]
            else:
                data["network"]["http"]["host"] = ""
            if "data" in req and "\r\n" in req["data"]:
                data["network"]["http"]["data"] = req["data"].split("\r\n", 1)[0]
            else:
                data["network"]["http"]["data"] = ""
            if "method" in req:
                data["network"]["http"]["method"] = req["method"]
            else:
                data["network"]["http"]["method"] = ""
                if "user-agent" in req:
                    data["network"]["http"]["ua"] = req["user-agent"]
                else:
                    data["network"]["http"]["ua"] = ""

    if "strings" in list(buf.keys()):
        data["strings"] = buf["strings"]
    else:
        data["strings"] = ["No Strings"]

    if "trid" in list(buf.keys()):
        data["trid"] = buf["trid"]
    else:
        data["trid"] = ["None matched"]
    resp = {"error": False, "data": data}
    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_screenshot(request, task_id, screenshot="all"):
    if not apiconf.taskscreenshot.get("enabled"):
        resp = {"error": True, "error_value": "Screenshot download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id)

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "shots")
    if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found: {os.path.basename(srcdir)}"})

    # Guard the listing like the sibling endpoints (tasks_dropped / tasks_selfextracted): in central mode a
    # task that produced no screenshots has no shots/* S3 keys, so ensure_local_analysis never creates the
    # local shots/ dir -- a bare os.listdir would then raise FileNotFoundError -> HTTP 500 instead of this
    # clean JSON error.
    if not path_exists(srcdir) or len(os.listdir(srcdir)) == 0:
        resp = {"error": True, "error_value": "No screenshots created for task %s" % task_id}
        return Response(resp)

    if screenshot == "all":
        mem_zip = create_zip(folder=srcdir)
        if mem_zip is False:
            resp = {"error": True, "error_value": "Can't create zip archive for report file"}
            return Response(resp)

        resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
        resp["Content-Length"] = len(mem_zip.getvalue())
        resp["Content-Disposition"] = f"attachment; filename={task_id}_screenshots.zip"
        return resp

    else:
        for ext, ct in ((".jpg", "image/jpeg"), (".png", "image/png")):
            shot = srcdir + "/" + screenshot.zfill(4) + ext
            if path_exists(shot):
                fname = f"{task_id}_{os.path.basename(shot)}"
                resp = StreamingHttpResponse(FileWrapper(open(shot, "rb"), 8096), content_type=ct)
                resp["Content-Length"] = os.path.getsize(shot)
                resp["Content-Disposition"] = f"attachment; filename={fname}"
                return resp

        else:
            resp = {"error": True, "error_value": "Screenshot does not exist"}
            return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_pcap(request, task_id):
    if not apiconf.taskpcap.get("enabled"):
        resp = {"error": True, "error_value": "PCAP download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id)

    srcfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "dump.pcap")
    if not os.path.normpath(srcfile).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found: {os.path.basename(srcfile)}"})
    if path_exists(srcfile):
        fname = "%s_dump.pcap" % task_id
        resp = StreamingHttpResponse(FileWrapper(open(srcfile, "rb"), 8096), content_type="application/vnd.tcpdump.pcap")
        resp["Content-Length"] = os.path.getsize(srcfile)
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    else:
        resp = {"error": True, "error_value": "PCAP does not exist"}
        return Response(resp)


def _resolve_task_id(request, task_id, enabled_key, check_tlp=True):
    """Shared preamble for artifact-download endpoints.

    Returns ((task_id, None)) on success or ((None, Response(error))) on failure.
    `enabled_key` names the apiconf section that gates the endpoint; callers
    that want to share a gate (e.g. all pcap variants under [taskpcap]) reuse
    the same key. TLP:RED checks are skipped only for endpoints that need
    to serve regardless (none at present). Enforces job visibility via
    _deny_if_hidden so all artifact endpoints honor tenant boundaries."""
    section = getattr(apiconf, enabled_key, None)
    if section is not None and not section.get("enabled"):
        return None, Response({"error": True, "error_value": "%s download API is disabled" % enabled_key})
    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return None, _denied
    check = validate_task(task_id)
    if check["error"]:
        return None, Response(check)
    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return None, _rtid_denied
    if check_tlp and (check.get("tlp") or "").lower() == "red":
        return None, Response({"error": True, "error_value": "Task has a TLP of RED"})
    return task_id, None


def _central_stage(request, task_id, include_memory=False, include_full_ram=True):
    """Central mode: stage the S3 results/<job_id>/ tree to the local
    storage/analyses/<task_id>/ dir so the local-FS artifact reads in the apiv2
    download endpoints below work (same generic seam the web report view uses —
    avoids rewriting each endpoint's FS reads). MUST be called AFTER the endpoint's
    per-task authorization so an unauthorized task_id is never staged. The large
    memory dumps are excluded from the bulk stage; the fullmemory/procmemory
    endpoints pass include_memory=True to stage them on explicit demand.
    include_full_ram=False (the procmemory endpoints) stages only the per-process
    memory/ subtree, not the multi-GB root full-RAM image. No-op single-node;
    best-effort (never raises)."""
    try:
        from lib.cuckoo.common.central_mode import central_mode_config

        if not central_mode_config().enabled:
            return
        from lib.cuckoo.common.artifact_storage import ensure_local_analysis, ensure_local_memory
        from analysis.central_scope import viewer_scope

        scope = viewer_scope(request.user)
        ensure_local_analysis(task_id, scope=scope)
        if include_memory:
            ensure_local_memory(task_id, scope=scope, include_full_ram=include_full_ram)
    except Exception:
        pass


def _serve_analysis_file(task_id, rel_path, download_name, content_type="application/octet-stream"):
    """Stream `<analysis>/<rel_path>` back as an attachment. Returns a Response
    object (either a StreamingHttpResponse for success, or a JSON error)."""
    srcfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, rel_path)
    if not os.path.normpath(srcfile).startswith(ANALYSIS_BASE_PATH):
        return Response({"error": True, "error_value": "Invalid path"})
    if not path_exists(srcfile) or os.path.getsize(srcfile) == 0:
        return Response({"error": True, "error_value": f"{os.path.basename(rel_path)} does not exist"})
    resp = StreamingHttpResponse(FileWrapper(open(srcfile, "rb"), 8192), content_type=content_type)
    resp["Content-Length"] = os.path.getsize(srcfile)
    resp["Content-Disposition"] = f"attachment; filename={task_id}_{download_name}"
    return resp


def _zip_paths(task_id, pairs, download_name):
    """Zip (archive_name, absolute_path) pairs into a disk-backed temporary archive and
    return it as a StreamingHttpResponse. Missing / empty sources are skipped."""
    buf = tempfile.NamedTemporaryFile(delete=True)
    written = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, p in pairs:
            if path_exists(p) and os.path.getsize(p) > 0:
                zf.write(p, arcname)
                written += 1
    if not written:
        buf.close()
        return Response({"error": True, "error_value": "No artifacts available for this task"})
    buf.seek(0, os.SEEK_END)
    size = buf.tell()
    buf.seek(0)
    resp = StreamingHttpResponse(FileWrapper(buf, 8192), content_type="application/zip")
    resp["Content-Length"] = size
    resp["Content-Disposition"] = f"attachment; filename={task_id}_{download_name}"
    return resp


def _serve_folder_zip(task_id, rel_folder, download_name, empty_msg=None):
    """Encrypt-zip an entire directory under the analysis dir and stream it.
    Uses `create_zip` (password = ZIP_PWD) for parity with tasks_dropped /
    tasks_payloadfiles. Returns a Response with a JSON error if the folder
    doesn't exist or is empty."""
    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, rel_folder)
    if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH):
        return Response({"error": True, "error_value": "Invalid path"})
    if not path_exists(srcdir) or not os.listdir(srcdir):
        return Response({"error": True, "error_value": empty_msg or f"No {rel_folder} artifacts for task {task_id}"})
    mem_zip = create_zip(folder=srcdir, encrypted=True, temp_file=True)
    if mem_zip is False:
        return Response({"error": True, "error_value": "Can't create zip archive"})
    mem_zip.seek(0, os.SEEK_END)
    size = mem_zip.tell()
    mem_zip.seek(0)
    resp = StreamingHttpResponse(FileWrapper(mem_zip, 8192), content_type="application/zip")
    resp["Content-Length"] = size
    resp["Content-Disposition"] = f"attachment; filename={task_id}_{download_name}"
    return resp


@csrf_exempt
@api_view(["GET"])
def tasks_tlspcap(request, task_id):
    """Back-compat endpoint: originally served PolarProxy's tls.pcap. We've
    since moved to SSLproxy + GoGoRoboCap which produces dump_decrypted.pcap;
    prefer that, but fall back to the legacy path for old analyses."""
    task_id, err = _resolve_task_id(request, task_id, "tasktlspcap", check_tlp=False)
    if err:
        return err
    _central_stage(request, task_id)  # central mode: materialize the S3 tree before the local-FS reads

    decrypted = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "dump_decrypted.pcap")
    legacy = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "polarproxy", "tls.pcap")
    for srcfile, fname in ((decrypted, "dump_decrypted.pcap"), (legacy, "tls.pcap")):
        if not os.path.normpath(srcfile).startswith(ANALYSIS_BASE_PATH):
            continue
        if path_exists(srcfile) and os.path.getsize(srcfile) > 0:
            resp = StreamingHttpResponse(
                FileWrapper(open(srcfile, "rb"), 8096), content_type="application/vnd.tcpdump.pcap"
            )
            resp["Content-Length"] = os.path.getsize(srcfile)
            resp["Content-Disposition"] = f"attachment; filename={task_id}_{fname}"
            return resp
    return Response({"error": True, "error_value": "TLS PCAP does not exist"})


# Variant tables used by the consolidated dispatcher endpoints. Each handler
# validates <variant> against a whitelist before touching the filesystem so
# the URL parameter can't be used to probe paths outside the analysis dir.

_PCAP_VARIANTS = {
    "decrypted": ("dump_decrypted.pcap", "dump_decrypted.pcap"),
    "mixed": ("dump_mixed.pcap", "dump_mixed.pcap"),
    "sslproxy": (os.path.join("sslproxy", "sslproxy.pcap"), "sslproxy.pcap"),
}

_KEY_SOURCES = {
    "tls": (os.path.join("tlsdump", "tlsdump.log"), "tlsdump.log"),
    "ssl": (os.path.join("aux", "sslkeylogfile", "sslkeys.log"), "sslkeys.log"),
    "master": (os.path.join("sslproxy", "master_keys.log"), "master_keys.log"),
}

_ETW_JSON_SOURCES = {
    "dns": (os.path.join("aux", "dns_etw.json"), "dns_etw.json"),
    "network": (os.path.join("aux", "network_etw.json"), "network_etw.json"),
    "wmi": (os.path.join("aux", "wmi_etw.json"), "wmi_etw.json"),
}

# "memory" is intentionally NOT a bulkzip folder: process/full-memory dumps have their own policy-gated
# endpoints (tasks_procmemory / tasks_fullmemory enforce [taskprocmemory]/[fullmemory] enabled+all + TLP-red),
# whereas bulkzip has only the weaker [taskbulkzip] gate -- so allowing "memory" here would bypass them
# (staging it in central mode made the dormant bypass live). NOTE: this does not by itself make memory dumps
# gated everywhere -- tasks_report 'all'/'dist' still recurse into the memory/ directory under the
# [taskreport] gate alone (a pre-existing upstream behaviour, flagged to the maintainers as a separate
# hardening; not changed here to avoid altering upstream report/all output).
_BULKZIP_FOLDERS = {"logs", "network", "selfextracted"}


def _pcapng_response(task_id):
    """On-the-fly PCAPNG with TLS keylog records embedded. Output goes to
    a per-request tempfile — concurrent callers must not race on a shared
    path inside the analysis dir."""
    try:
        from lib.cuckoo.common.pcap_utils import PcapToNg
    except ImportError:
        return Response({"error": True, "error_value": "PCAPNG conversion helper unavailable"})
    adir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id)
    pcap_path = os.path.join(adir, "dump.pcap")
    if not path_exists(pcap_path):
        return Response({"error": True, "error_value": "dump.pcap does not exist"})
    tls_log_path = os.path.join(adir, "tlsdump", "tlsdump.log")
    ssl_key_log_path = os.path.join(adir, "aux", "sslkeylogfile", "sslkeys.log")
    tmp = tempfile.NamedTemporaryFile(prefix=f"{task_id}_pcapng_", suffix=".pcapng", delete=False)
    tmp.close()
    try:
        PcapToNg(pcap_path, tls_log_path, ssl_key_log_path).generate(tmp.name)
        if not path_exists(tmp.name) or os.path.getsize(tmp.name) == 0:
            return Response({"error": True, "error_value": "PCAPNG generation failed"})
        size = os.path.getsize(tmp.name)
        # Hand the open fd to the streaming response; unlinking the path now
        # keeps the fd alive through streaming and lets the kernel reclaim
        # the inode as soon as the response finishes.
        fd = open(tmp.name, "rb")
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        resp = StreamingHttpResponse(FileWrapper(fd, 8192), content_type="application/x-pcapng")
        resp["Content-Length"] = size
        resp["Content-Disposition"] = f"attachment; filename={task_id}_dump.pcapng"
        return resp
    except Exception:
        try:
            os.unlink(tmp.name)
        except OSError:
            pass
        raise


def _pcapzip_response(task_id):
    """Zip every available pcap variant (original, decrypted, mixed, sslproxy
    raw, sslproxy cleaned). Variants that are missing or empty are silently
    dropped so consumers only receive what actually ran."""
    adir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id)
    pairs = [
        ("dump.pcap", os.path.join(adir, "dump.pcap")),
        ("dump_decrypted.pcap", os.path.join(adir, "dump_decrypted.pcap")),
        ("dump_mixed.pcap", os.path.join(adir, "dump_mixed.pcap")),
        ("sslproxy.pcap", os.path.join(adir, "sslproxy", "sslproxy.pcap")),
        ("sslproxy_clean.pcap", os.path.join(adir, "sslproxy", "sslproxy_clean.pcap")),
    ]
    return _zip_paths(task_id, pairs, "pcaps.zip")


@csrf_exempt
@api_view(["GET"])
def tasks_pcap_variant(request, task_id, variant):
    """Alternate PCAP artifacts for <task_id>. variant ∈
    {decrypted, mixed, sslproxy, zip, pcapng}. The bare tasks/get/pcap/<id>/
    remains for back-compat with existing callers (serves dump.pcap)."""
    task_id, err = _resolve_task_id(request, task_id, "taskpcap")
    if err:
        return err
    v = (variant or "").lower()
    # Validate BEFORE staging: an unknown variant is a 4xx client error, and staging first would pay a full
    # S3 list + tree download only to reject.
    if v not in _PCAP_VARIANTS and v not in ("zip", "pcapng"):
        return Response({"error": True, "error_value": f"Unknown pcap variant: {variant}"}, status=400)
    _central_stage(request, task_id)
    if v in _PCAP_VARIANTS:
        rel_path, fname = _PCAP_VARIANTS[v]
        return _serve_analysis_file(task_id, rel_path, fname, content_type="application/vnd.tcpdump.pcap")
    if v == "zip":
        return _pcapzip_response(task_id)
    return _pcapng_response(task_id)  # v == "pcapng" (only remaining valid variant)


@csrf_exempt
@api_view(["GET"])
def tasks_keys(request, task_id, kind):
    """TLS keylog material. kind ∈ {tls, ssl, master} — each refers to a
    different hook source (tls: MockSSL → tlsdump.log; ssl: bcrypt/NCrypt →
    aux/sslkeylogfile/sslkeys.log; master: SSLproxy → master_keys.log).
    All three are NSS-format keylogs."""
    task_id, err = _resolve_task_id(request, task_id, "tasktlskeys")
    if err:
        return err
    k = (kind or "").lower()
    if k not in _KEY_SOURCES:  # validate before staging (4xx client error, no wasted S3 download)
        return Response({"error": True, "error_value": f"Unknown keys kind: {kind}"}, status=400)
    _central_stage(request, task_id)  # central mode: materialize the S3 tree before the local-FS reads
    rel_path, fname = _KEY_SOURCES[k]
    return _serve_analysis_file(task_id, rel_path, fname, content_type="text/plain")


@csrf_exempt
@api_view(["GET"])
def tasks_etw(request, task_id, kind):
    """ETW telemetry downloads. kind ∈ {dns, network, wmi} each map to an
    NDJSON stream; kind == amsi zips the per-buffer AMSI script captures."""
    task_id, err = _resolve_task_id(request, task_id, "tasketw")
    if err:
        return err
    k = (kind or "").lower()
    if k not in _ETW_JSON_SOURCES and k != "amsi":  # validate before staging (4xx, no wasted S3 download)
        return Response({"error": True, "error_value": f"Unknown etw kind: {kind}"}, status=400)
    _central_stage(request, task_id)  # central mode: materialize the S3 tree before the local-FS reads
    if k in _ETW_JSON_SOURCES:
        rel_path, fname = _ETW_JSON_SOURCES[k]
        return _serve_analysis_file(task_id, rel_path, fname, content_type="application/x-ndjson")
    return _serve_folder_zip(task_id, os.path.join("aux", "amsi_etw"), "amsi_etw.zip")  # k == "amsi"


@csrf_exempt
@api_view(["GET"])
def tasks_bulkzip(request, task_id, folder):
    """Encrypt-zip an entire analysis subdirectory. folder is whitelisted
    to {logs, network, selfextracted}. Archive is AES-encrypted
    with ZIP_PWD for parity with tasks_dropped / tasks_payloadfiles /
    tasks_procdumpfiles. "memory" is intentionally excluded: process/full-memory
    dumps are served only via tasks_procmemory / tasks_fullmemory, which enforce
    the dedicated policy gates -- see _BULKZIP_FOLDERS."""
    task_id, err = _resolve_task_id(request, task_id, "taskbulkzip")
    if err:
        return err
    f = (folder or "").lower()
    # Validate the folder BEFORE staging: an unknown folder is a 4xx client error, and staging first would
    # pay a full S3 list + tree download only to reject. (memory/ was removed from the whitelist -- process/
    # full-memory dumps are served only via the policy-gated tasks_procmemory/tasks_fullmemory -- so a
    # folder=memory request now 400s here rather than silently returning a 200 with an empty archive.)
    if f not in _BULKZIP_FOLDERS:
        return Response({"error": True, "error_value": f"Unknown bulkzip folder: {folder}"}, status=400)
    # central mode: materialize the S3 tree for the (now-validated) folder. memory/ is never staged here.
    _central_stage(request, task_id)
    return _serve_folder_zip(task_id, f, f"{f}.zip")


@csrf_exempt
@api_view(["GET"])
def tasks_evtx(request, task_id):
    if not apiconf.taskevtx.get("enabled"):
        resp = {"error": True, "error_value": "EVTX download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id)

    evtxfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "evtx", "evtx.zip")
    if not os.path.normpath(evtxfile).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found: {os.path.basename(evtxfile)}"})
    if path_exists(evtxfile):
        fname = "%s_evtx.zip" % task_id
        resp = StreamingHttpResponse(FileWrapper(open(evtxfile, "rb")), content_type="application/zip")
        resp["Content-Length"] = os.path.getsize(evtxfile)
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    else:
        resp = {"error": True, "error_value": "EVTX does not exist"}
        return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_mitmdump(request, task_id):
    if not apiconf.mitmdump.get("enabled"):
        resp = {"error": True, "error_value": "Mitmdump HAR download API is disabled"}
        return Response(resp)
    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)
    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # before serving its artifacts (wrong-object authorization otherwise).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied
    _central_stage(request, task_id)
    harfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "mitmdump", "dump.har")
    if not os.path.normpath(harfile).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found: {os.path.basename(harfile)}"})
    if path_exists(harfile):
        fname = "%s_dump.har" % task_id
        resp = StreamingHttpResponse(FileWrapper(open(harfile, "rb")), content_type="text/plain")
        resp["Content-Length"] = os.path.getsize(harfile)
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp
    else:
        resp = {"error": True, "error_value": "HAR file does not exist"}
        return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_dropped(request, task_id):
    if not apiconf.taskdropped.get("enabled"):
        resp = {"error": True, "error_value": "Dropped File download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id)

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "files")
    if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found: {os.path.basename(srcdir)}"})

    if not path_exists(srcdir) or not len(os.listdir(srcdir)):
        resp = {"error": True, "error_value": "No files dropped for task %s" % task_id}
        return Response(resp)

    else:
        mem_zip = create_zip(folder=srcdir, encrypted=True)
        if mem_zip is False:
            resp = {"error": True, "error_value": "Can't create zip archive for report file"}
            return Response(resp)

        # in Mb
        dropped_max_size_limit = request.GET.get("max_size", False)
        # convert to MB
        size = len(mem_zip.getvalue())
        size_in_mb = int(size / 1024 / 1024)
        if dropped_max_size_limit and size_in_mb > int(dropped_max_size_limit):
            resp = {
                "error": True,
                "error_value": "Archive is bigger than max size. Current size is {}".format(size_in_mb),
            }
            return Response(resp)

        resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
        resp["Content-Length"] = len(mem_zip.getvalue())
        resp["Content-Disposition"] = f"attachment; filename={task_id}_dropped.zip"
        return resp


@csrf_exempt
@api_view(["GET"])
def tasks_selfextracted(request, task_id, tool="all"):
    if not apiconf.taskselfextracted.get("enabled"):
        resp = {"error": True, "error_value": "Self Extracted File download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id)

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "selfextracted")
    if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found: {os.path.basename(srcdir)}"})

    if not path_exists(srcdir) or not len(os.listdir(srcdir)):
        resp = {"error": True, "error_value": "No self extracted files for task %s" % task_id}
        return Response(resp)

    selfextract_data = {}

    if repconf.mongodb.enabled:
        tmp = mongo_find_one("analysis", _analysis_filter(request, task_id), {"selfextract": 1})
        if tmp and "selfextract" in tmp:
            selfextract_data = tmp["selfextract"]
    elif es_as_db:
        tmp = es.search(
            index=get_analysis_index(), query=get_query_by_info_id(str(task_id)), _source=["selfextract"]
        )["hits"]["hits"]
        if tmp:
            selfextract_data = tmp[-1]["_source"].get("selfextract", {})

    if not selfextract_data:
        jfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports", "report.json")
        if path_exists(jfile):
            try:
                with open(jfile, "r") as f:
                    rep = json.load(f)
                    selfextract_data = rep.get("selfextract", {})
            except Exception as e:
                log.error(e)

    if tool != "all" and tool not in selfextract_data:
        resp = {"error": True, "error_value": f"Tool {tool} not found in analysis data"}
        return Response(resp)

    mem_zip = BytesIO()
    with zipfile.ZipFile(mem_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        if tool == "all":
            if selfextract_data:
                processed_sha256s = set()
                for tname, tdata in selfextract_data.items():
                    for fmeta in tdata.get("extracted_files", []):
                        sha256 = fmeta.get("sha256")
                        if not sha256 or not re.match(r"^[a-fA-F0-9]{64}$", sha256):
                            continue

                        fpath = os.path.join(srcdir, sha256)
                        if not os.path.exists(fpath):
                            continue

                        arcname = os.path.join(tname, sha256)
                        zf.write(fpath, arcname)
                        processed_sha256s.add(sha256)

                for f in os.listdir(srcdir):
                    if f not in processed_sha256s:
                        zf.write(os.path.join(srcdir, f), f)
            else:
                for f in os.listdir(srcdir):
                    zf.write(os.path.join(srcdir, f), f)
        else:
            tdata = selfextract_data[tool]
            for fmeta in tdata.get("extracted_files", []):
                sha256 = fmeta.get("sha256")
                if not sha256 or not re.match(r"^[a-fA-F0-9]{64}$", sha256):
                    continue

                fpath = os.path.join(srcdir, sha256)
                if not os.path.exists(fpath):
                    continue

                zf.write(fpath, sha256)

    mem_zip.seek(0)
    resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
    resp["Content-Length"] = len(mem_zip.getvalue())
    resp["Content-Disposition"] = f"attachment; filename={task_id}_selfextracted_{tool}.zip"
    return resp


@csrf_exempt
@api_view(["GET"])
def tasks_surifile(request, task_id):
    if not apiconf.taskdropped.get("enabled"):
        resp = {"error": True, "error_value": "Suricata File download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id)

    srcfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "logs", "files.zip")
    if not os.path.normpath(srcfile).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found: {os.path.basename(srcfile)}"})
    if path_exists(srcfile):
        resp = StreamingHttpResponse(FileWrapper(open(srcfile, "rb"), 8192), content_type="application/octet-stream;")
        resp["Content-Length"] = os.path.getsize(srcfile)
        resp["Content-Disposition"] = f"attachment; filename={task_id}_surifiles.zip"
        return resp

    else:
        resp = {"error": True, "error_value": "No suricata files captured for task %s" % task_id}
        return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_rollingsuri(request, window=60):
    window = int(window)

    if not apiconf.rollingsuri.get("enabled"):
        resp = {"error": True, "error_value": "Suricata Rolling Alerts API is disabled"}
        return Response(resp)
    maxwindow = apiconf.rollingsuri.get("maxwindow")
    if maxwindow > 0:
        if window > maxwindow:
            resp = {"error": True, "error_value": "The Window You Specified is greater than the configured maximum"}
            return Response(resp)

    gen_time = datetime.now() - timedelta(minutes=window)
    dummy_id = ObjectId.from_datetime(gen_time)
    # Central mode: this aggregate feed keeps rows by NUMERIC SQL-task-id membership below, which does
    # NOT prove a returned Mongo doc belongs to that SQL task -- a colliding worker-local doc for another
    # tenant (same info.id) would ride the caller's visible-id set and leak its alerts (audit MEDIUM).
    # Constrain the Mongo query to the viewer's tenant stamp so foreign-tenant (and not-yet-reconciled,
    # tenant_id-null) docs are dropped at the DB. No-op for single-node / break-glass (viewer_scope None).
    _feed_q = {"suricata.alerts": {"$exists": True}, "_id": {"$gte": dummy_id}}
    from lib.cuckoo.common.central_mode import central_mode_config

    if central_mode_config().enabled:
        from analysis.central_scope import viewer_scope

        _scope = viewer_scope(request.user)
        if _scope:
            _feed_q = {"$and": [_feed_q, _scope]}
    result = list(
        mongo_find(
            "analysis",
            _feed_q,
            {"suricata.alerts": 1, "info.id": 1},
        )
    )

    # Tenant isolation: this is an aggregate feed across ALL recent analyses, so
    # it must drop alerts (and task ids) for tasks the caller may not see — the
    # task_id coverage gate can't catch this endpoint (no task_id in its route).
    # When multitenancy is disabled, viewer.is_local_admin short-circuits to
    # see-all, so this is a no-op and behavior is unchanged.
    # Break-glass (is_local_admin, incl. MT-disabled) sees all -> no filter.
    # Otherwise batch-resolve the visible set in ONE query instead of a
    # view_task() per row.
    viewer = viewer_for(request.user)
    if viewer.is_local_admin:
        _visible = None
    else:
        _tids = {e["info"]["id"] for e in result if "info" in e and "id" in e.get("info", {})}
        _visible = {t.id for t in db.list_tasks(task_ids=list(_tids), visible_to=viewer)} if _tids else set()

    resp = []
    for e in result:
        tid = e["info"]["id"]
        if _visible is not None and tid not in _visible:
            continue
        for alert in e["suricata"]["alerts"]:
            alert["id"] = tid
            resp.append(alert)

    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_procmemory(request, task_id, pid="all"):
    if not apiconf.taskprocmemory.get("enabled"):
        resp = {"error": True, "error_value": "Process memory download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    # Gate the "all" bulk download BEFORE staging so a REFUSED request never materializes the S3 memory/
    # tree onto the web node's disk (central mode). The per-pid path has no "all" gate; it stages below.
    if pid == "all" and not apiconf.taskprocmemory.get("all"):
        return Response({"error": True, "error_value": "Downloading of all process memory dumps is disabled"})
    # procmemory serves PER-PROCESS dumps (memory/<pid>.dmp); stage only that subtree, NOT the multi-GB root
    # full-RAM image (memory.dmp) -- that is gated by [taskfullmemory] and served only by tasks_fullmemory.
    _central_stage(request, task_id, include_memory=True, include_full_ram=False)
    # Check if any process memory dumps exist
    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", f"{task_id}", "memory")
    if not path_exists(srcdir):
        resp = {"error": True, "error_value": "No memory dumps saved"}
        return Response(resp)

    parent_folder = os.path.dirname(srcdir)
    analysis_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", f"{task_id}")
    if pid == "all":
        if USE_SEVENZIP:
            zip_path = os.path.join(analysis_dir, "procdumps.zip")
            try:
                subprocess.check_call(["/usr/bin/7z", f"-p{settings.ZIP_PWD.decode()}", "a", zip_path, srcdir])
            except subprocess.CalledProcessError:
                resp = {"error": True, "error_value": "error compressing file"}
                return Response(resp)
            # using `with` prematurely closes the file
            zip_fd = open(zip_path, "rb")
            resp = StreamingHttpResponse(zip_fd, content_type="application/zip")
            resp["Content-Length"] = os.path.getsize(zip_path)
        else:
            mem_zip = create_zip(folder=srcdir, encrypted=True)
            if mem_zip is False:
                resp = {"error": True, "error_value": "Can't create zip archive for report file"}
                return Response(resp)
            resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
            resp["Content-Length"] = len(mem_zip.getvalue())
        resp["Content-Disposition"] = f"attachment; filename={task_id}_procdumps.zip"
        return resp
    else:
        filepath = os.path.join(parent_folder, pid + ".dmp")
        if path_exists(filepath):
            if USE_SEVENZIP:
                zip_path = os.path.join(analysis_dir, f"{task_id}-{pid}_dmp.zip")
                try:
                    subprocess.check_call([SEVENZIP_PATH, f"-p{settings.ZIP_PWD.decode()}", "a", zip_path, filepath])
                except subprocess.CalledProcessError:
                    resp = {"error": True, "error_value": "error compressing file"}
                    return Response(resp)
                zip_fd = open(zip_path, "rb")
                resp = StreamingHttpResponse(zip_fd, content_type="application/zip")
                resp["Content-Length"] = os.path.getsize(zip_path)
            else:
                mem_zip = create_zip(files=filepath, encrypted=True)
                if mem_zip is False:
                    resp = {"error": True, "error_value": "Can't create zip archive for report file"}
                    return Response(resp)
                resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
                resp["Content-Length"] = len(mem_zip.getvalue())
            resp["Content-Disposition"] = f"attachment; filename={task_id}-{pid}_dmp.zip"
            return resp
        else:
            resp = {"error": True, "error_value": "Process memory dump does not exist for pid %s" % pid}
            return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_fullmemory(request, task_id):
    if not apiconf.taskfullmemory.get("enabled"):
        resp = {"error": True, "error_value": "Full memory download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id, include_memory=True)
    filename = ""
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "memory.dmp")
    if path_exists(file_path):
        filename = os.path.basename(file_path)
    elif path_exists(file_path + ".zip"):
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "memory.dmp.zip")
        if path_exists(file_path):
            filename = os.path.basename(file_path)

    if filename:
        content_type = "application/octet-stream"
        chunk_size = 8192
        fname = f"{task_id}_{filename}"
        response = StreamingHttpResponse(FileWrapper(open(file_path, "rb"), chunk_size), content_type=content_type)
        response["Content-Length"] = os.path.getsize(file_path)
        response["Content-Disposition"] = f"attachment; filename={fname}"
        return response
    else:
        resp = {"error": True, "error_value": "Memory dump not found for task " + task_id}
        return Response(resp)


@csrf_exempt
@api_view(["GET"])
def file(request, stype, value):
    if not apiconf.sampledl.get("enabled", False):
        resp = {"error": True, "error_value": "Sample download API is disabled"}
        return Response(resp)

    if stype in ("md5", "sha1", "sha256"):
        _denied = _deny_by_hash(request, **{stype: value})
    else:  # stype == "task" — value is a string from the URL; coerce so the
        # int task_id column comparison doesn't error on PostgreSQL.
        try:
            value = int(value)
        except (ValueError, TypeError):
            return Response({"error": True, "error_value": "Invalid task ID"}, status=400)
        _denied = _deny_task(request, value)
    if _denied is not None:
        return _denied

    # This Func is not Synced with views.py "def file()"

    file_hash = False
    if stype in ("md5", "sha1", "sha256"):
        file_hash = value
    elif stype == "task":
        check = validate_task(value)
        if check["error"]:
            return Response(check)

        sid = db.view_task(value).to_dict()["sample_id"]
        file_hash = db.view_sample(sid).to_dict()["sha256"]

    if not file_hash:
        resp = {"error": True, "error_value": "Sample %s was not found" % file_hash}
        return Response(resp)

    paths = db.sample_path_by_hash(sample_hash=file_hash)

    if not paths:
        resp = {"error": True, "error_value": "Sample %s was not found" % file_hash}
        return Response(resp)

    for sample in paths:
        if request.GET.get("encrypted"):
            # Check if file exists in temp folder
            zip_path = f"/tmp/{file_hash}.zip"
            file_exists = os.path.isfile(zip_path)
            if file_exists:
                resp = StreamingHttpResponse(FileWrapper(open(zip_path, "rb"), 8096), content_type="application/zip")
                resp["Content-Disposition"] = f"attachment; filename={file_hash}.zip"
                return resp

            if USE_SEVENZIP:
                try:
                    subprocess.check_call([SEVENZIP_PATH, f"-p{settings.ZIP_PWD.decode()}", "a", zip_path, sample])
                except subprocess.CalledProcessError:
                    resp = {"error": True, "error_value": "error compressing file"}
                    return Response(resp)
                zip_fd = open(zip_path, "rb")
                resp = StreamingHttpResponse(zip_fd, content_type="application/zip")
                resp["Content-Length"] = os.path.getsize(zip_path)
                resp["Content-Disposition"] = f"attachment; filename={file_hash}.zip"
                return resp
            else:
                # If files does not exist encrypt and move to tmp folder
                with pyzipper.AESZipFile(zip_path, "w", encryption=pyzipper.WZ_AES) as zf:
                    zf.setpassword(b"infected")
                    zf.write(sample, os.path.basename(sample), zipfile.ZIP_DEFLATED)
                resp = StreamingHttpResponse(FileWrapper(open(zip_path, "rb"), 8096), content_type="application/zip")
                resp["Content-Disposition"] = f"attachment; filename={file_hash}.zip"
            return resp
        else:
            resp = StreamingHttpResponse(FileWrapper(open(sample, "rb"), 8096), content_type="application/octet-stream")
            resp["Content-Length"] = os.path.getsize(sample)
            resp["Content-Disposition"] = f"attachment; filename={file_hash}.bin"
        return resp


@csrf_exempt
@api_view(["GET"])
def machines_list(request):
    if not apiconf.machinelist.get("enabled"):
        resp = {"error": True, "error_value": "Machine list API is disabled"}
        return Response(resp)

    resp = {}
    resp["data"] = []
    resp["error"] = []
    machines = db.list_machines()
    for row in machines:
        resp["data"].append(row.to_dict())
    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def exit_nodes_list(request):
    if not apiconf.list_exitnodes.get("enabled"):
        resp = {"error": True, "error_value": "Exit nodes list API is disabled"}
        return Response(resp)

    resp = {}
    resp["data"] = []
    resp["error"] = []
    resp["data"] += ["socks:" + sock5 for sock5 in _load_socks5_operational() or []]
    resp["data"] += ["vpn:" + vpn for vpn in vpns.keys() or []]
    if routing_conf.tor.enabled:
        resp["data"].append("tor")
    if routing_conf.inetsim.enabled:
        resp["data"].append("inetsim")

    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def machines_view(request, name=None):
    if not apiconf.machineview.get("enabled"):
        resp = {"error": True, "error_value": "Machine view API is disabled"}
        return Response(resp)

    resp = {}
    machine = db.view_machine(name=name)
    if machine:
        resp["data"] = machine.to_dict()
        resp["error"] = []
    else:
        resp["error"] = True
        resp["error_value"] = "Machine not found"
    return Response(resp)


def _bytes2gb(size):
    return int(size / 1024 / 1024 / 1024)


@api_view(["GET"])
def cuckoo_status(request):
    # get
    # print(request.query_params)
    # post
    # request.data
    resp = {}
    if not apiconf.cuckoostatus.get("enabled"):
        resp["error"] = True
        resp["error_value"] = "Cuckoo Status API is disabled"
    else:
        resp["error"] = []
        tasks_dict_with_counts = db.get_tasks_status_count(visible_to=viewer_for(request.user))
        total_sum = 0
        if isinstance(tasks_dict_with_counts, dict):
            total_sum = sum(tasks_dict_with_counts.values())
        resp["data"] = dict(
            version=CUCKOO_VERSION,
            hostname=socket.gethostname(),
            machines=dict(total=len(db.list_machines()), available=db.count_machines_available()),
            tasks=dict(
                total=total_sum,
                pending=tasks_dict_with_counts.get("pending", 0),
                running=tasks_dict_with_counts.get("running", 0),
                completed=tasks_dict_with_counts.get("completed", 0),
                reported=tasks_dict_with_counts.get("reported", 0),
            ),
        )

        if HAVE_PSUTIL:
            du = psutil.disk_usage("/")
            hdd_free = _bytes2gb(du.free)
            hdd_total = _bytes2gb(du.total)
            hdd_used = _bytes2gb(du.used)
            hdd_percent_used = du.percent

            vu = psutil.virtual_memory()
            ram_free = _bytes2gb(vu.free)
            ram_total = _bytes2gb(vu.total)
            ram_used = _bytes2gb(vu.used)

            # add more from https://pypi.org/project/psutil/
            resp["data"]["server"] = {
                "storage": {
                    "free": hdd_free,
                    "total": hdd_total,
                    "used": hdd_used,
                    "used_by": "{}%".format(hdd_percent_used),
                },
                "ram": {"free": ram_free, "total": ram_total, "used": ram_used},
            }
    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def task_x_hours(request):
    session = db.Session()
    if not multitenancy_config().enabled:
        # Multitenancy disabled: reproduce upstream verbatim, including the
        # pre-existing reversed between() args (now, now-1day) that make this
        # window always empty. Fixing the bounds here would change the default
        # install's output (from {} to real data), which must stay identical to
        # upstream base. The corrected bounds + visibility filter apply only when
        # multitenancy is enabled (below).
        res = (
            session.query(Task)
            .filter(Task.added_on.between(datetime.now(), datetime.now() - timedelta(days=1)))
            .all()
        )
        results = {}
        if res:
            for date, samples in res:
                results.setdefault(date.strftime("%Y-%m-%eT%H:%M:00"), samples)
        session.close()
        resp = {"error": False, "stats": results}
        return Response(resp)
    try:
        # Query the bounded last-24h window FIRST (a small set), then filter by
        # visibility in Python — avoids loading the whole visible set into memory
        # (OOM). Tenant isolation via can_view_task is a no-op when multitenancy
        # is disabled / break-glass. (Also fixes the pre-existing reversed
        # between() args, which made this always return empty.)
        tasks = (
            session.query(Task)
            .filter(Task.added_on.between(datetime.now() - timedelta(days=1), datetime.now()))
            .all()
        )
        results = {}
        for t in tasks:
            if not can_view_task(request.user, t):
                continue
            bucket = t.added_on.strftime("%Y-%m-%eT%H:%M:00")
            results[bucket] = results.get(bucket, 0) + 1
    finally:
        session.close()
    return Response({"error": False, "stats": results})


@csrf_exempt
@api_view(["GET"])
def tasks_latest(request, hours):
    resp = {}
    resp["error"] = []
    timestamp = datetime.now() - timedelta(hours=int(hours))
    ids = db.list_tasks(completed_after=timestamp, visible_to=viewer_for(request.user))
    resp["ids"] = [_strip_mt_task_fields(id.to_dict()) for id in ids]
    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_payloadfiles(request, task_id):
    if not apiconf.payloadfiles.get("enabled"):
        resp = {"error": True, "error_value": "CAPE payload file download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id)

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "CAPE")

    if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found: {os.path.basename(srcdir)}"})

    if path_exists(srcdir):
        mem_zip = create_zip(folder=srcdir, encrypted=True)
        if mem_zip is False:
            resp = {"error": True, "error_value": "Can't create zip archive for report file"}
            return Response(resp)

        resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
        resp["Content-Length"] = len(mem_zip.getvalue())
        resp["Content-Disposition"] = f"attachment; filename=cape_payloads_{task_id}.zip"
        return resp
    return Response({"error": True, "error_value": f"No CAPE file(s) for task {task_id}."})


@csrf_exempt
@api_view(["GET"])
def tasks_procdumpfiles(request, task_id):
    if not apiconf.procdumpfiles.get("enabled"):
        resp = {"error": True, "error_value": "Procdump file download API is disabled"}
        return Response(resp)

    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id)

    # ToDo add all/one

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "procdump")
    if path_exists(srcdir):
        mem_zip = create_zip(folder=srcdir, encrypted=True)
        if mem_zip is False:
            resp = {"error": True, "error_value": "Can't create zip archive for report file"}
            return Response(resp)

        resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
        resp["Content-Length"] = len(mem_zip.getvalue())
        resp["Content-Disposition"] = f"attachment; filename=cape_payloads_{task_id}.zip"
        return resp
    else:
        resp = {"error": True, "error_value": f"No procdump file(s) for task {task_id}."}
        return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_config(request, task_id, cape_name=False):
    if not apiconf.capeconfig.get("enabled"):
        resp = {"error": True, "error_value": "Config download API is disabled"}
        return Response(resp)
    _denied = _deny_if_hidden(request, db.view_task(task_id))
    if _denied is not None:
        return _denied
    check = validate_task(task_id)

    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid
        # Recovery_<N> pivots to a DIFFERENT task; the earlier _deny_if_hidden
        # authorized the ORIGINAL id, so re-gate visibility on the RESOLVED id
        # BEFORE the TLP/serving checks (wrong-object authz + no TLP existence oracle).
        _rtid_denied = _deny_if_hidden(request, db.view_task(task_id))
        if _rtid_denied is not None:
            return _rtid_denied

    if check.get("tlp", "") in ("red", "Red"):
        return Response({"error": True, "error_value": "Task has a TLP of RED"})

    _central_stage(request, task_id)

    buf = {}
    if repconf.mongodb.get("enabled"):
        buf = mongo_find_one("analysis", _analysis_filter(request, task_id), {"CAPE.configs": 1}, sort=[("_id", -1)])
    if es_as_db and not buf:
        tmp = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"]
        if len(tmp) > 1:
            buf = tmp[-1]["_source"]
        elif len(tmp) == 1:
            buf = tmp[0]["_source"]
        else:
            buf = None
    if repconf.jsondump.get("enabled") and not buf:
        jfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports", "report.json")
        # path_exists as well as the traversal guard: in central mode _central_stage is best-effort (it
        # swallows all exceptions), so a stage that failed silently leaves no local report.json and a bare
        # open() would raise FileNotFoundError -> HTTP 500 instead of the clean JSON error below (mirrors
        # tasks_selfextracted).
        if os.path.normpath(jfile).startswith(ANALYSIS_BASE_PATH) and path_exists(jfile):
            with open(jfile, "r") as jdata:
                buf = json.load(jdata)

    if buf and not buf.get("CAPE"):
        resp = {"error": True, "error_value": "Unable to retrieve results for task {}.".format(task_id)}
        return Response(resp)

    if isinstance(buf, dict) and buf.get("CAPE", False):
        if zlib_compresion:
            buf["CAPE"] = json.loads(decompress(buf["CAPE"]))
        data = []
        if not isinstance(buf["CAPE"], list) and buf["CAPE"].get("configs"):
            if cape_name and buf["CAPE"]["configs"].get(cape_name, "") == cape_name:
                return Response({cape_name.lower(): buf["CAPE"]["configs"][cape_name]})
            data = buf["CAPE"]["configs"]
        if data:
            resp = {"error": False, "configs": data}
        else:
            resp = {"error": True, "error_value": "CAPE config for task {} does not exist.".format(task_id)}
        return Response(resp)
    else:
        resp = {"error": True, "error_value": "CAPE config for task {} does not exist.".format(task_id)}
        return Response(resp)


@csrf_exempt
@api_view(["POST"])
# should be securized by checking category, this is just an example how easy to extend webgui with external tools
def post_processing(request, category, task_id):
    content = request.data.get("content", "")
    if content and category:
        content = json.loads(content)
        if not content:
            return Response({"error": True, "msg": "Missed content data or category"})
        # NOTE: this route is a commented-out example (urls.py) and is NOT auth/tenant-gated -- it MUST be
        # secured (auth + can_manage_task + tenant scope) before being enabled. Minimal defence-in-depth: in
        # central mode route the $set through the SHARED, bridge-aware own-doc filter (mirrors comments() /
        # central_delete_analysis / set_task_visibility) rather than a hand-built one, so it stays correct in
        # both modes: ui-only under central+MT (central_bridge_required), or the three-arm {ui- OR info.id}
        # form single-node/MT-off. A bare {info.id} could $set onto a colliding worker-local doc. Single-node
        # keeps bare info.id.
        from lib.cuckoo.common.central_mode import central_mode_config, central_own_analysis_filter

        if central_mode_config().enabled:
            _pp_filter = central_own_analysis_filter(int(task_id), getattr(db.view_task(int(task_id)), "tenant_id", None))
        else:
            _pp_filter = {"info.id": int(task_id)}
        # Fail loud: a 0-match must NOT report success (else a dropped $set on a non-bridged/absent doc looks
        # like it landed). mongo_find_one_and_update returns None when nothing matched.
        if mongo_find_one_and_update("analysis", _pp_filter, {"$set": {category: content}}) is None:
            resp = {"error": True, "msg": "No analysis doc for task {}".format(task_id)}
        else:
            resp = {"error": False, "msg": "Added under the key {}".format(category)}
    else:
        resp = {"error": True, "msg": "Missed content data or category"}

    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def statistics_data(requests, days):
    resp = {}
    if days.isdigit():
        from dashboard.views import entitled_scopes

        v = viewer_for(requests.user)
        scopes = entitled_scopes(requests.user)
        # Back-compat: when only the global panel applies (MT disabled or
        # break-glass local-admin) return the legacy FLAT stats dict so existing
        # API clients reading resp["data"]["signatures"] keep working. Shared and
        # locked modes both yield scoped panels, so they take the per-scope dict.
        if scopes == ["global"]:
            data = statistics(int(days))
        else:
            data = {scope: statistics(int(days), scope=scope, viewer=v) for scope in scopes}
        resp = {"Error": False, "data": data}
    else:
        resp = {"Error": True, "error_value": "Provide days as number"}
    return Response(resp)


@api_view(["POST"])
def tasks_delete_many(request):
    response = {}
    # NB: NOT gated by the [taskdelete] kill-switch. Unlike the human-facing tasks_delete, this is the
    # automated worker-cleanup path (utils/dist.py _delete_many + utils/go-fetcher), and on a stock install
    # ([taskdelete] enabled=no + token_auth_enabled=no -> AllowAny/AnonymousUser) a kill-switch here would
    # 403 EVERY caller and silently break disk reclamation (dist.py's `if res` treats a 403 as falsy).
    # delete_mongo: form-encoding sends booleans as strings, and bool("False") is True, so parse the string
    # forms explicitly -- upstream's bool(...) turned an opt-OUT "False" (utils/dist.py, to keep the worker's
    # Mongo report) into a delete. ABSENT -> delete (upstream default True); a present-but-EMPTY value is
    # RETAIN, preserving upstream's bool("")=False back-compat ("" is in the retain set below).
    _dm = request.POST.get("delete_mongo", True)
    delete_mongo = _dm if isinstance(_dm, bool) else str(_dm).strip().lower() not in ("", "false", "0", "no")
    # Validate the WHOLE id list up front: the per-task db.session.commit() below makes each delete durable
    # immediately, so a malformed id mid-list (int() raising) would 500 AFTER destroying the earlier ids.
    # Empty tokens (absent/blank ids) -> no-op, not the old int("") 500; a non-integer -> 400 before any delete.
    _raw_ids = [x.strip() for x in request.POST.get("ids", "").split(",") if x.strip()]
    try:
        _ids = [int(x) for x in _raw_ids]
    except ValueError:
        return Response({"error": True, "error_value": "ids must be a comma-separated list of integers"}, status=400)
    for task_id in _ids:
        task = db.view_task(task_id)
        if task:
            if not can_manage_task(request.user, task):
                # hidden == missing: no cross-tenant enumeration, no unauthorized delete
                response.setdefault(task_id, "not exists")
                continue
            if task.status == TASK_RUNNING:
                response.setdefault(task_id, "running")
                continue
            # Resolve the task's tenant WHILE the SQL row exists (from the row we already fetched). db.delete_task
            # only STAGES the SQL delete (DBTransactionMiddleware commits after the view), and the Mongo
            # delete_many is immediate/non-transactional, so COMMIT the SQL delete explicitly BEFORE the Mongo
            # delete -- else a later-iteration rollback would resurrect this task while its report is gone.
            _tenant = getattr(task, "tenant_id", None)
            # Commit the SQL delete BEFORE the irreversible folder/Mongo deletes (see tasks_delete). Per-task
            # outcomes (a client must act differently on each): "error" = PRE-commit failure, task still
            # exists, RETRYABLE; "deleted_orphan_report" = task gone but its report couldn't be erased, NOT
            # retryable (needs a reaper); "deleted" = clean (includes the delete_mongo=False opt-out, where the
            # report is DELIBERATELY retained -- an intended distributed-mode behavior, not an orphan).
            # CAVEAT (same as tasks_delete + delete_data): "deleted_orphan_report" only fires if
            # central_delete_analysis RAISES -- a mongo_delete_data-swallowed failure (non-central arm, or an
            # exhausted-AutoReconnect None) is NOT detected; closing that needs a status-returning Mongo delete.
            try:
                if not db.delete_task(task_id):
                    response.setdefault(task_id, "not exists")
                    continue
                db.session.commit()
            except Exception as _de:
                try:
                    db.session.rollback()
                except Exception:
                    pass
                log.error("tasks_delete_many: task %s SQL delete failed (rolled back, retryable): %s", task_id, _de)
                response.setdefault(task_id, "error")
                continue
            # SEPARATE guards (see tasks_delete): a folder failure must not skip the Mongo delete.
            try:
                delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%d" % task_id))
            except Exception as _fe:
                log.error("tasks_delete_many: task %s folder delete failed (disk orphan-by-path): %s", task_id, _fe)
            try:
                if delete_mongo:
                    central_delete_analysis(request, task_id, tenant_id=_tenant)
            except Exception as _ce:
                log.error("tasks_delete_many: task %s report delete FAILED (Mongo doc + S3 orphaned, unreapable): %s",
                          task_id, _ce)
                response.setdefault(task_id, "deleted_orphan_report")
                continue
            response.setdefault(task_id, "deleted")
        else:
            response.setdefault(task_id, "not exists")
    # status must let a retention client tell three outcomes apart: a RETRYABLE failure ("error", task still
    # exists), an ORPHANED report ("deleted_orphan_report", task gone but its Mongo doc needs reaping), and a
    # clean batch. Don't answer plain OK when either problem occurred.
    _errored = any(v == "error" for v in response.values())
    _orphaned = any(v == "deleted_orphan_report" for v in response.values())
    response["status"] = "partial_error" if (_errored or _orphaned) else "OK"
    if _errored or _orphaned:
        response["error"] = True
    return Response(response)


def limit_exceeded(request, exception):
    resp = {"error": True, "error_value": "Rate limit exceeded for this API"}
    return Response(resp)


dl_service_map = {
    "VirusTotal": "vtdl",
}


@csrf_exempt
@api_view(["POST"])
def tasks_download_services(request):
    # Check if this API function is enabled
    if not apiconf.downloading_services.get("enabled"):
        return Response({"error": True, "error_value": "Download sample API is Disabled"})
    resp = {}
    hashes = request.POST.get("hashes").strip()
    if not hashes:
        return Response({"error": True, "error_value": "hashes value is empty"})
    resp["error"] = []
    try:
        _tenant_id, _visibility = submission_scope(request)
    except ValueError:
        return Response({"error": True, "error_value": "invalid visibility"})
    # Parse potential POST options (see submission/views.py)
    options = request.POST.get("options", "")
    custom = request.POST.get("custom", "")
    machine = request.POST.get("machine", "")
    opt_filename = get_user_filename(options, custom)

    details = {}
    task_machines = []
    vm_list = []
    opt_apikey = False
    opts = get_options(options)
    if opts:
        opt_apikey = opts.get("apikey", False)

    for vm in db.list_machines():
        vm_list.append(vm.label)
    if machine.lower() == "all":
        if not apiconf.filecreate.get("allmachines"):
            resp = {"error": True, "error_value": "Machine=all is disabled using the API"}
            return Response(resp)
        for entry in vm_list:
            task_machines.append(entry)
    else:
        # Check if VM is in our machines table
        if machine == "" or machine in vm_list:
            task_machines.append(machine)
        # Error if its not
        else:
            resp = {
                "error": True,
                "error_value": "Machine '{0}' does not exist. Available: {1}".format(machine, ", ".join(vm_list)),
            }
            return Response(resp)

    details = {
        "errors": [],
        "content": False,
        "request": request,
        "task_id": [],
        "url": False,
        "params": {},
        "headers": {},
        "path": "",
        "fhash": False,
        "options": options,
        "only_extraction": False,
        "service": "",
        "tenant_id": _tenant_id,
        "visibility": _visibility,
        "user_id": request.user.id or 0,
    }

    if opt_apikey:
        details["apikey"] = opt_apikey

    # viewer gates the local-cache reuse inside download_from_3rdparty (no
    # cross-tenant sample-bytes via a "Local" cache hit). No-op when MT disabled.
    details["viewer"] = viewer_for(request.user)
    details = download_from_3rdparty(hashes, opt_filename, details)
    if isinstance(details.get("task_ids"), list):
        tasks_count = len(details["task_ids"])
    else:
        tasks_count = 0
    if tasks_count > 0:
        resp["data"] = {}
        resp["errors"] = details["errors"]
        resp["data"]["task_ids"] = details.get("task_ids", [])
        if len(details.get("task_ids", [])) == 1:
            resp["data"]["message"] = "Task ID {0} has been submitted".format(str(details.get("task_ids", [])[0]))
        else:
            resp["data"]["message"] = "Task IDs {0} have been submitted".format(
                ", ".join(str(x) for x in details.get("task_ids", []))
            )
    else:
        resp = {"error": True, "error_value": "Error adding task to database", "errors": details["errors"]}

    return Response(resp)


@csrf_exempt
@api_view(["POST"])
def tasks_file_stream(request, task_id):
    """Streams a file from the running machine with matching task_id."""

    def _stream_iterator(fp, guest_name, chunk_size=1024):
        pos = 0
        while True:
            machine = db.view_machine(guest_name)
            if machine.status != "running":
                break
            with open(fp, "rb") as fd:
                if pos:
                    fd.seek(pos)
                while True:
                    content = fd.read(chunk_size)
                    if not content:
                        break
                    yield content
                    pos = fd.tell()

    if not apiconf.taskstatus.get("enabled"):
        resp = {"error": True, "error_value": "Task status API is disabled"}
        return Response(resp)
    resp = {}
    # Pulling a file off the RUNNING guest (or its live analysis dir) is a task
    # ACTION, not passive report viewing — a read-only viewer of a public/tenant
    # task must not fetch arbitrary live-VM files. Require manage rights (owner /
    # tenant-admin / break-glass); hidden == generic 404 (no enumeration).
    _denied = _deny_manage(request, task_id)
    if _denied is not None:
        return _denied
    task = db.view_task(task_id)
    # MT off: _deny_manage defers on a missing task -> restore upstream's explicit
    # response (no-op under MT, which already 404'd missing/hidden).
    if not task:
        resp = {"error": True, "error_value": "Task does not exist"}
        return Response(resp)
    machine = db.view_machine(task.guest.name)
    if machine.status != "running":
        resp = {"error": True, "error_value": "Machine is not running", "errors": machine.status}
        return Response(resp)
    filepath = request.data.get("filepath")
    if not filepath:
        resp = {"error": True, "error_value": "filepath not set"}
        return Response(resp)
    if request.data.get("is_local", ""):
        if filepath.startswith(("/", r"\/")):
            resp = {"error": True, "error_value": "Filepath mustn't start with /"}
            return Response(resp)
        filepath = os.path.join(CUCKOO_ROOT, "storage", "analyses", f"{task_id}", filepath)
        if not os.path.normpath(filepath).startswith(ANALYSIS_BASE_PATH):
            resp = {"error": True, "error_value": "Path traversal detected"}
            return Response(resp)
        if not os.path.isfile(filepath):
            resp = {"error": True, "error_value": "file does not exist"}
            return Response(resp)
        return StreamingHttpResponse(
            streaming_content=_stream_iterator(filepath, task.guest.name), content_type="application/octet-stream"
        )
    try:
        r = requests.post(f"http://{machine.ip}:8000/retrieve", stream=True, data={"filepath": filepath, "streaming": "1"})
        if r.status_code >= 400:
            resp = {"error": True, "error_value": f"{filepath} does not exist"}
            return Response(resp)
        return StreamingHttpResponse(streaming_content=r.iter_content(chunk_size=1024), content_type="application/octet-stream")
    except requests.exceptions.RequestException as ex:
        log.exception(ex)
        resp = {"error": True, "error_value": f"Requests exception: {ex}"}
    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def dist_tasks_reported(request):
    # List finished tasks here
    if not DIST_ENABLED:
        return Response(
            {
                "Error": True,
                "error_value": "Distributed CAPE is not enabled",
            }
        )
    """

        Add new API endpoint in CAPE to query the tasks that are reported and ready to be retrieved
        Add new API endpoint in CAPE to set "task.notificated = True" for a specific task

        yeah we could script that go and fetch reported tasks.
        can you currently list tasks that are finished but waiting to be retrieved in the api?
        e.g. in the notification_loop() in dist.py, where it queries tasks that need to be sent to the callback url it does this:

        if there was an pi endpoint that exposed that, and another that allowed us to set notificated on the task when we'd finished processing it, then we wouldnt need the callback anymore
    """
    # change to with session as
    dist_db = dist_session()
    ready = []
    tasks = dist_db.query(DTask).filter_by(finished=True, retrieved=True, notificated=False).order_by(DTask.id.desc()).all()
    for task in tasks or []:
        ready.append(task.main_task_id)
    dist_db.close()
    return Response({"Tasks": ready})


@csrf_exempt
@api_view(["GET"])
def dist_tasks_notification(request, task_id: int):
    dist_db = dist_session()
    tasks = dist_db.query(DTask).filter_by(main_task_id=task_id).order_by(DTask.id.desc()).all()
    if not tasks:
        return Response({"error": True, "error_value": f"No tasks found with main_task_id: {task_id}"})
    for task in tasks:
        # main_db.set_status(task.main_task_id, TASK_REPORTED)
        # log.debug("reporting main_task_id: {}".format(task.main_task_id))
        task.notificated = True


@csrf_exempt
@api_view(["POST"])
def yara_uploader(request):
    try:
        if not apiconf.yara_uploader.get("enabled"):
            return Response({"error": True, "error_value": "Yara Uploader API is Disabled"})

        if not HAVE_PLYARA:
            return Response({"error": True, "error_value": "Missing dependency. Contact your administrator."})

        category = request.data.get("category")
        if not category or category not in ALLOWED_YARA_CATEGORIES:
            return Response(
                {"status": "error", "message": f"Invalid or missing category. Allowed categories: {ALLOWED_YARA_CATEGORIES}"},
                status=400,
            )
        """
        if request.user.is_authenticated and request.user.username not in ALLOWED_UPLOADERS:
            return Response(
                {"status": "error", "message": f"User '{request.user.username}' is not authorized to upload YARA rules."}, status=403
            )
        """
        if "file" not in request.FILES:
            return Response({"status": "error", "message": "No file provided"}, status=400)

        uploaded_file = request.FILES["file"]

        # Read content for processing
        try:
            content = uploaded_file.read().decode("utf-8")
        except UnicodeDecodeError:
            return Response({"status": "error", "message": "File must be a text file (UTF-8)"}, status=400)

        # Validate YARA
        try:
            yara.compile(source=content)
        except yara.SyntaxError as e:
            return Response({"status": "error", "message": f"YARA Syntax Error: {str(e)}"}, status=400)
        except yara.Error as e:
            return Response({"status": "error", "message": f"YARA Error: {str(e)}"}, status=400)

        try:
            parser = plyara.Plyara()
            rules = parser.parse_string(content)

            if not rules:
                return Response({"status": "error", "message": "No YARA rules found in file"}, status=400)

            main_rule = rules[0]

            # Check for family
            family = None
            metadata = main_rule.get("metadata", [])

            for meta in metadata:
                if "family" in meta:
                    family = meta["family"]
                    break

            if not family:
                # Fallback: check cape_type
                for meta in metadata:
                    if "cape_type" in meta:
                        cape_type_val = meta["cape_type"]
                        if cape_type_val and isinstance(cape_type_val, str):
                            family = cape_type_val.split(" ")[0]
                        break

            if not family:
                return Response({"status": "error", "message": "Missing 'family' in metadata"}, status=400)

            # Now iterate all rules to inject cape_type / author if needed
            for rule in rules:
                rule_metadata = rule.get("metadata", [])

                has_cape_type = any("cape_type" in m for m in rule_metadata)
                has_author = any("yara_created_by" in m for m in rule_metadata)  # Using yara_created_by as key

                if not has_cape_type:
                    rule_metadata.append({"cape_type": f"{family} Payload"})

                if request.user.is_authenticated and not has_author:
                    rule_metadata.append({"yara_created_by": request.user.username})

                rule["metadata"] = rule_metadata

            # Define destination path
            original_filename = os.path.basename(uploaded_file.name)  # Basic safety
            if category == "monitor":
                dest_dir = os.path.join(CUCKOO_ROOT, "analyzer", "windows", "data", "yara")
            else:
                dest_dir = os.path.join(CUCKOO_ROOT, "data", "yara", category)

            # Ensure directory exists
            if not os.path.exists(dest_dir):
                os.makedirs(dest_dir, exist_ok=True)

            original_dest_path = os.path.join(dest_dir, original_filename)

            if os.path.exists(original_dest_path):
                filename = original_filename
                dest_path = original_dest_path
            else:
                # Fallback to standard naming
                filename = f"{family}.yar"
                dest_path = os.path.join(dest_dir, filename)

            # Check if file exists to append
            if os.path.exists(dest_path):
                with open(dest_path, "r", encoding="utf-8") as f:
                    existing_content = f.read()

                try:
                    existing_rules = parser.parse_string(existing_content)
                    existing_names = {r["rule_name"] for r in existing_rules}

                    # Filter new rules
                    unique_rules = []
                    for rule in rules:
                        if rule["rule_name"] not in existing_names:
                            unique_rules.append(rule)

                    if not unique_rules:
                        # No new rules to add
                        msg = "All rules already exist. Nothing to add."
                        return Response({"status": "success", "message": msg})

                    append_content = ""
                    for rule in unique_rules:
                        append_content += "\n\n" + plyara.utils.rebuild_yara_rule(rule)

                    content = existing_content + append_content

                except Exception as e:
                    return Response({"status": "error", "message": f"Failed to parse existing file for append: {str(e)}"}, status=500)
            else:
                # Rebuild content for new file
                new_content = ""
                for rule in rules:
                    new_content += plyara.utils.rebuild_yara_rule(rule) + "\n\n"

                content = new_content

        except Exception as e:
            return Response({"status": "error", "message": f"Plyara parsing error: {str(e)}"}, status=400)

        # Save file
        with open(dest_path, "w", encoding="utf-8") as f:
            f.write(content)

        msg = "Rule saved! Thank you"

        # Distributed propagation
        try:
            if DIST_ENABLED:
                # Prepare for propagation
                files = {"file": (filename, content)}
                with dist_session() as db_session:
                    nodes = db_session.execute(select(Node).where(Node.enabled.is_(True))).scalars().all()

                    propagated_count = 0
                    total_count = 0

                    for node in nodes:
                        total_count += 1
                        prop_url = urljoin(node.url, "apiv2/yara_uploader/")
                        headers = {"Authorization": f"Token {node.apikey}"}

                        try:
                            data = {"username": request.user.username, "category": category}
                            r = requests.post(prop_url, files=files, data=data, headers=headers, verify=False, timeout=10)
                            if r.status_code == 200:
                                propagated_count += 1
                        except Exception:
                            pass

                    msg += f" (Propagated to {propagated_count}/{total_count} workers)"

        except Exception as e:
            msg += f" (Propagation failed: {str(e)})"

        return Response(
            {
                "status": "success",
                "message": msg,
            }
        )

    except Exception as e:
        return Response({"status": "error", "message": str(e)}, status=500)
