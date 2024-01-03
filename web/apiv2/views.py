# encoding: utf-8
import json
import logging
import os
import shutil
import socket
import sys
import zipfile
from datetime import datetime, timedelta
from io import BytesIO
from urllib.parse import quote
from wsgiref.util import FileWrapper

import pyzipper
from bson.objectid import ObjectId
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import StreamingHttpResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_safe
from rest_framework.decorators import api_view
from rest_framework.response import Response

sys.path.append(settings.CUCKOO_PATH)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import ANALYSIS_BASE_PATH, CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.exceptions import CuckooDemuxError
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
    download_from_vt,
    force_int,
    parse_request_arguments,
    perform_search,
    process_new_dlnexec_task,
    process_new_task_files,
    search_term_map,
    statistics,
    validate_task,
)
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_RECOVERED, TASK_RUNNING, Database, Task
from lib.cuckoo.core.rooter import _load_socks5_operational, vpns

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

# FORMAT = '%(asctime)-15s %(clientip)s %(user)-8s %(message)s'

# Config variables
repconf = Config("reporting")
web_conf = Config("web")
routing_conf = Config("routing")

zlib_compresion = False
if repconf.compression.enabled:
    from zlib import decompress

    zlib_compresion = True

if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_delete_data, mongo_find, mongo_find_one, mongo_find_one_and_update

es_as_db = False
if repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
    from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index, get_query_by_info_id

    es_as_db = True
    es = elastic_handler

db = Database()


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

    return render(request, "apiv2/index.html", {"config": parsed})


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

    resp["error"] = False
    files = request.FILES.getlist("file")
    extra_details = {}
    task_ids = []
    for sample in files:
        tmp_path = store_temp_file(sample.read(), sanitize_filename(sample.name))
        try:
            task_id, extra_details = db.demux_sample_and_add_to_db(
                tmp_path,
                options=options,
                priority=priority,
                static=1,
                only_extraction=True,
                user_id=request.user.id or 0,
            )
            task_ids.extend(task_id)
        except CuckooDemuxError as e:
            resp = {"error": True, "error_value": e}
            return Response(resp)

    resp["data"] = {}
    resp["data"]["task_ids"] = task_ids
    if extra_details and "config" in extra_details:
        resp["data"]["config"] = extra_details["config"]
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
        resp["error"] = False
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
            shrike_url,
            shrike_msg,
            shrike_sid,
            shrike_refer,
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
        }

        task_ids_tmp = []
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
                if tmp_path.lower().endswith(".saz"):
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
                task_id = db.add_pcap(file_path=tmp_path)
                details["task_ids"].append(task_id)
                continue
            if static:
                task_id = db.add_static(file_path=tmp_path, priority=priority, user_id=request.user.id or 0)
                details["task_ids"].append(task_id)
                continue
            if tmp_path:
                details["path"] = tmp_path
                details["content"] = content
                status, task_ids_tmp = download_file(**details)
                if status == "error":
                    details["errors"].append({os.path.basename(tmp_path).decode(): task_ids_tmp})
                else:
                    details["task_ids"] = task_ids_tmp

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
        resp["error"] = False

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
            shrike_url,
            shrike_msg,
            shrike_sid,
            shrike_refer,
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
                shrike_url=shrike_url,
                shrike_msg=shrike_msg,
                shrike_sid=shrike_sid,
                shrike_refer=shrike_refer,
                route=route,
                cape=cape,
                tlp=tlp,
                tags_tasks=tags_tasks,
                user_id=request.user.id or 0,
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

        resp["error"] = False
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
            shrike_url,
            shrike_msg,
            shrike_sid,
            shrike_refer,
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
        }

        status, task_ids_tmp = download_file(**details)
        if status == "error":
            details["errors"].append({os.path.basename(path).decode(): task_ids_tmp})
        else:
            details["task_ids"] = task_ids_tmp

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

    resp = {}
    if md5 or sha1 or sha256 or sample_id:
        resp["error"] = False
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
            resp["data"] = sample.to_dict()
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
        resp["error"] = False
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
                tasks = db.list_tasks(sample_id=sid)
                for task in tasks:
                    buf = task.to_dict()
                    # Remove path information, just grab the file name
                    buf["target"] = buf["target"].rsplit("/", 1)[-1]
                    resp["data"].append(buf)
        else:
            resp = {"data": [], "error": False}

    return Response(resp)


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

    if term and value:
        records = False
        if term not in search_term_map and term not in ("malscore", "ttp"):
            resp = {"error": True, "error_value": "Invalid Option. '%s' is not a valid option." % term}
            return Response(resp)

        if term in ("ids", "options", "tags_tasks"):
            if all([v.strip().isdigit() for v in value.split(",")]):
                value = [int(v.strip()) for v in filter(None, value.split(","))]
            else:
                return Response({"error": True, "error_value": "Not all values are integers"})
        if term == "ids":
            tmp_value = []
            for task in db.list_tasks(task_ids=value) or []:
                if task.status == "reported":
                    tmp_value.append(task.id)
                else:
                    return_data.append({"analysis": {"status": task.status, "id": task.id}})
            value = tmp_value
            del tmp_value

        try:
            records = perform_search(term, value, user_id=request.user.id, privs=request.user.is_staff, web=False)
        except ValueError:
            if not term:
                resp = {"error": True, "error_value": "No option provided."}
            if not value:
                resp = {"error": True, "error_value": "No argument provided."}
            if not term and not value:
                resp = {"error": True, "error_value": "No option or argument provided."}

        if records:
            for results in records:
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

    if offset:
        offset = int(offset)
    resp["data"] = []
    resp["config"] = "Limit: {0}, Offset: {1}".format(limit, offset)
    resp["buf"] = 0

    tasks = db.list_tasks(
        limit=limit,
        details=True,
        offset=offset,
        completed_after=completed_after,
        status=status,
        options_like=option,
        order_by=Task.completed_on.desc(),
    )

    if not tasks:
        return Response(resp)

    # Dist.py fetches only ids
    if ids_only:
        resp["data"] = [{"id": task.id} for task in tasks]
    else:
        for row in tasks:
            resp["buf"] += 1
            task = row.to_dict()
            task["guest"] = {}
            if row.guest:
                task["guest"] = row.guest.to_dict()

            task["errors"] = []
            for error in row.errors:
                task["errors"].append(error.message)

            task["sample"] = {}
            if row.sample_id:
                sample = db.view_sample(row.sample_id)
                if sample:
                    task["sample"] = sample.to_dict()

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
    if not task:
        resp = {"error": True, "error_value": "Task not found in database"}
        return Response(resp)

    resp = {"error": False}
    entry = task.to_dict()
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
        entry["sample"] = sample.to_dict()

    if task.status == TASK_RECOVERED and task.custom:
        m = re.match(r"^Recovery_(?P<taskid>\d+)$", task.custom)
        if m:
            task_id = int(m.group("taskid"))
            task = db.view_task(task_id, details=True)
            resp["error"] = False
            if task:
                entry = task.to_dict()
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
                    entry["sample"] = sample.to_dict()

    if repconf.mongodb.enabled:
        rtmp = mongo_find_one(
            "analysis",
            {"info.id": int(task.id)},
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

    if not db.view_task(task_id):
        resp = {"error": True, "error_value": "Task ID does not exist in the database"}
        return Response(resp)

    resp = {}
    new_task_id = db.reschedule(task_id)
    if new_task_id:
        resp["error"] = False
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

    error, msg, task_status = db.tasks_reprocess(task_id)
    if error:
        return Response({"error": True, "error_value": msg})

    db.set_status(task_id, TASK_COMPLETED)
    return Response({"error": error, "data": f"Task ID {task_id} with status {task_status} marked for reprocessing"})


@csrf_exempt
@api_view(["GET"])
def tasks_delete(request, task_id, status=False):
    """
    task_id: int or string if many
    example: 1 or 1,2,3,4

    """
    if not (apiconf.taskdelete.get("enabled") or request.user.is_staff):
        resp = {"error": True, "error_value": "Task Deletion API is Disabled"}
        return Response(resp)

    if isinstance(task_id, int):
        task_id = [task_id]
    else:
        task_id = [force_int(task.strip()) for task in task_id.split(",")]

    resp = {}
    s_deleted = []
    f_deleted = []
    for task in task_id:
        check = validate_task(task, status)
        if check["error"]:
            f_deleted.append(str(task))
            continue

        if db.delete_task(task):
            delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task))
            if web_conf.web_reporting.get("enabled", True):
                mongo_delete_data(task)

            s_deleted.append(str(task))
        else:
            f_deleted.append(str(task))

    if s_deleted:
        resp["data"] = "Task(s) ID(s) {0} has been deleted".format(",".join(s_deleted))

    if f_deleted:
        resp["error"] = True
        resp["failed"] = "Task(s) ID(s) {0} failed to remove".format(",".join(f_deleted))

    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_status(request, task_id):
    if not apiconf.taskstatus.get("enabled"):
        resp = {"error": True, "error_value": "Task status API is disabled"}
        return Response(resp)

    task = db.view_task(task_id)
    if not task:
        resp = {"error": True, "error_value": "Task does not exist"}
        return Response(resp)

    status = task.to_dict()["status"]
    resp = {"error": False, "data": status}
    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_report(request, task_id, report_format="json", make_zip=False):
    if not apiconf.taskreport.get("enabled"):
        resp = {"error": True, "error_value": "Task Report API is Disabled"}
        return Response(resp)

    # check if allowed to download to all + if no if user has permissions
    if not settings.ALLOW_DL_REPORTS_TO_ALL and not request.user.userprofile.reports:
        return render(
            request,
            "error.html",
            {"error": "You don't have permissions to download reports. Ask admin to enable it for you in user profile."},
        )

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

    resp = {}

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports")
    if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found {os.path.basename(srcdir)}"})

    # Report validity check
    if path_exists(srcdir) and len(os.listdir(srcdir)) == 0:
        resp = {"error": True, "error_value": "No reports created for task %s" % task_id}

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
    }

    report_formats = {
        # Use the 'all' option if you want all generated files except for memory.dmp
        "all": {"type": "-", "files": ["memory.dmp"]},
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
            fname = "%s_report.%s" % (task_id, ext)

            if make_zip:
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
        if report_format.lower() == "all":
            if not apiconf.taskreport.get("all"):
                resp = {"error": True, "error_value": "Downloading all reports in one call is disabled"}
                return Response(resp)

        report_files = report_formats[report_format.lower()]
        srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
        if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH) and path_exists(srcdir):
            return render(request, "error.html", {"error": f"File not found {os.path.basename(srcdir)}"})

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
                    log.error(e, exc_info=True)

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

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

    buf = {}
    if repconf.mongodb.get("enabled") and not buf:
        buf = mongo_find_one("analysis", {"info.id": int(task_id)}, {"behavior.calls": 0})
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
        if os.path.normpath(jfile).startswith(ANALYSIS_BASE_PATH):
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

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "shots")
    if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH):
        return render(request, "error.html", {"error": f"File not found: {os.path.basename(srcdir)}"})

    if len(os.listdir(srcdir)) == 0:
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

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

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


@csrf_exempt
@api_view(["GET"])
def tasks_dropped(request, task_id):
    if not apiconf.taskdropped.get("enabled"):
        resp = {"error": True, "error_value": "Dropped File download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

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
def tasks_surifile(request, task_id):
    if not apiconf.taskdropped.get("enabled"):
        resp = {"error": True, "error_value": "Suricata File download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

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
    result = list(
        mongo_find(
            "analysis",
            {"suricata.alerts": {"$exists": True}, "_id": {"$gte": dummy_id}},
            {"suricata.alerts": 1, "info.id": 1},
        )
    )
    resp = []
    for e in result:
        for alert in e["suricata"]["alerts"]:
            alert["id"] = e["info"]["id"]
            resp.append(alert)

    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_rollingshrike(request, window=60, msgfilter=None):
    window = int(window)

    if not apiconf.rollingshrike.get("enabled"):
        resp = {"error": True, "error_value": "Rolling Shrike API is disabled"}
        return Response(resp)
    maxwindow = apiconf.rollingshrike.get("maxwindow")
    if maxwindow > 0:
        if window > maxwindow:
            resp = {"error": True, "error_value": "The Window You Specified is greater than the configured maximum"}
            return Response(resp)

    gen_time = datetime.now() - timedelta(minutes=window)
    dummy_id = ObjectId.from_datetime(gen_time)
    if msgfilter:
        result = mongo_find(
            "analysis",
            {
                "info.shrike_url": {"$exists": True, "$ne": None},
                "_id": {"$gte": dummy_id},
                "info.shrike_msg": {"$regex": msgfilter, "$options": "-1"},
            },
            {"info.id": 1, "info.shrike_msg": 1, "info.shrike_sid": 1, "info.shrike_url": 1, "info.shrike_refer": 1},
            sort=[("_id", -1)],
        )
    else:
        result = mongo_find(
            "analysis",
            {"info.shrike_url": {"$exists": True, "$ne": None}, "_id": {"$gte": dummy_id}},
            {"info.id": 1, "info.shrike_msg": 1, "info.shrike_sid": 1, "info.shrike_url": 1, "info.shrike_refer": 1},
            sort=[("_id", -1)],
        )

    resp = []
    for e in result:
        tmp = {}
        tmp["id"] = e["info"]["id"]
        tmp["shrike_msg"] = e["info"]["shrike_msg"]
        tmp["shrike_sid"] = e["info"]["shrike_sid"]
        tmp["shrike_url"] = e["info"]["shrike_url"]
        if e["info"].get("shrike_refer"):
            tmp["shrike_refer"] = e["info"]["shrike_refer"]
        resp.append(tmp)

    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_procmemory(request, task_id, pid="all"):
    if not apiconf.taskprocmemory.get("enabled"):
        resp = {"error": True, "error_value": "Process memory download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

    # Check if any process memory dumps exist
    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "memory")
    if not path_exists(srcdir):
        resp = {"error": True, "error_value": "No memory dumps saved"}
        return Response(resp)

    parent_folder = os.path.dirname(srcdir)
    if pid == "all":
        if not apiconf.taskprocmemory.get("all"):
            resp = {"error": True, "error_value": "Downloading of all process memory dumps is disabled"}
            return Response(resp)

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

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

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
            file_exists = os.path.isfile(f"/tmp/{file_hash}.zip")
            if not file_exists:
                # If files does not exist encrypt and move to tmp folder
                with pyzipper.AESZipFile(f"{file_hash}.zip", "w", encryption=pyzipper.WZ_AES) as zf:
                    zf.setpassword(b"infected")
                    zf.write(sample, os.path.basename(sample), zipfile.ZIP_DEFLATED)
                shutil.move(f"{file_hash}.zip", "/tmp")
            resp = StreamingHttpResponse(FileWrapper(open(f"/tmp/{file_hash}.zip", "rb"), 8096), content_type="application/zip")
            resp["Content-Disposition"] = f"attachment; filename={file_hash}.zip"
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
    resp["error"] = False
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
    resp["error"] = False
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
        resp["error"] = False
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
        resp["error"] = False
        tasks_dict_with_counts = db.get_tasks_status_count()
        resp["data"] = dict(
            version=CUCKOO_VERSION,
            hostname=socket.gethostname(),
            machines=dict(total=len(db.list_machines()), available=db.count_machines_available()),
            tasks=dict(
                total=sum(tasks_dict_with_counts.values()),
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
    res = (
        session.query(Task)
        .filter(Task.added_on.between(datetime.datetime.now(), datetime.datetime.now() - datetime.timedelta(days=1)))
        .all()
    )
    results = {}
    if res:
        for date, samples in res:
            results.setdefault(date.strftime("%Y-%m-%eT%H:%M:00"), samples)
    session.close()
    resp = {"error": False, "stats": results}
    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_latest(request, hours):
    resp = {}
    resp["error"] = False
    timestamp = datetime.now() - timedelta(hours=int(hours))
    ids = db.list_tasks(completed_after=timestamp)
    resp["ids"] = [id.to_dict() for id in ids]
    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def tasks_payloadfiles(request, task_id):
    if not apiconf.payloadfiles.get("enabled"):
        resp = {"error": True, "error_value": "CAPE payload file download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

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

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

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
    check = validate_task(task_id)

    if check["error"]:
        return Response(check)

    rtid = check.get("rtid", 0)
    if rtid:
        task_id = rtid

    buf = {}
    if repconf.mongodb.get("enabled"):
        buf = mongo_find_one("analysis", {"info.id": int(task_id)}, {"CAPE.configs": 1}, sort=[("_id", -1)])
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
        if os.path.normpath(jfile).startswith(ANALYSIS_BASE_PATH):
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
        _ = mongo_find_one_and_update("analysis", {"info.id": int(task_id)}, {"$set": {category: content}})
        resp = {"error": False, "msg": "Added under the key {}".format(category)}
    else:
        resp = {"error": True, "msg": "Missed content data or category"}

    return Response(resp)


@csrf_exempt
@api_view(["GET"])
def statistics_data(requests, days):
    resp = {}
    if days.isdigit():
        details = statistics(int(days))
        resp = {"Error": False, "data": details}
    else:
        resp = {"Error": True, "error_value": "Provide days as number"}
    return Response(resp)


@api_view(["POST"])
def tasks_delete_many(request):
    response = {}
    delete_mongo = request.POST.get("delete_mongo", True)
    for task_id in request.POST.get("ids", "").split(",") or []:
        task_id = int(task_id)
        task = db.view_task(task_id)
        if task:
            if task.status == TASK_RUNNING:
                response.setdefault(task_id, "running")
                continue
            if db.delete_task(task_id):
                delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%d" % task_id))
            if delete_mongo:
                mongo_delete_data(task_id)
        else:
            response.setdefault(task_id, "not exists")
    response["status"] = "OK"
    return Response(response)


def limit_exceeded(request, exception):
    resp = {"error": True, "error_value": "Rate limit exceeded for this API"}
    return Response(resp)


dl_service_map = {
    "VirusTotal": "vtdl",
}


def common_download_func(service, request):
    resp = {}
    hashes = request.data.get(dl_service_map[service].strip())
    if not hashes:
        hashes = request.POST.get("hashes".strip(), None)
    if not hashes:
        return Response({"error": True, "error_value": f"hashes (hash list) or {dl_service_map[service]} value is empty"})
    resp["error"] = False
    # Parse potential POST options (see submission/views.py)
    options = request.POST.get("options", "")
    custom = request.POST.get("custom", "")
    machine = request.POST.get("machine", "")
    opt_filename = get_user_filename(options, custom)

    details = {}
    task_machines = []
    vm_list = []
    opt_apikey = False

    if service == "VirusTotal":
        opts = get_options(options)
        if opts:
            opt_apikey = opts.get("apikey", False)

        if not (settings.VTDL_KEY or opt_apikey):
            resp = {
                "error": True,
                "error_value": ("You specified VirusTotal but must edit the file and specify your VTDL_KEY variable"),
            }
            return Response(resp)

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
        "service": service,
        "user_id": request.user.id or 0,
    }

    if service == "VirusTotal":
        details["apikey"] = settings.VTDL_KEY or opt_apikey
        details = download_from_vt(hashes, details, opt_filename, settings)
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
def tasks_vtdl(request):
    # Check if this API function is enabled
    if not apiconf.vtdl.get("enabled"):
        return Response({"error": True, "error_value": "VTDL Create API is Disabled"})
    return common_download_func("VirusTotal", request)
