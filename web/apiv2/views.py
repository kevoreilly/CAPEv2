# encoding: utf-8
from __future__ import absolute_import
import json
import os
import sys
import time
import socket
import tarfile
import logging
from datetime import datetime, timedelta
import tempfile
import requests
import subprocess
from zlib import decompress
from django.conf import settings
from wsgiref.util import FileWrapper
from django.http import HttpResponse, StreamingHttpResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_safe
from io import BytesIO

from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.decorators import api_view, permission_classes, authentication_classes

from bson.objectid import ObjectId
from django.contrib.auth.decorators import login_required
try:
    from django_ratelimit.decorators import ratelimit
except ImportError:
    try:
        from ratelimit.decorators import ratelimit
    except ImportError:
        print("missed dependency: pip3 install django-ratelimit -U")

sys.path.append(settings.CUCKOO_PATH)
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.config import Config
from utils.cleaners import delete_mongo_data
from lib.cuckoo.core.database import TASK_REPORTED
from lib.cuckoo.common.saztopcap import saz_to_pcap
from lib.cuckoo.core.database import Database, Task
from lib.cuckoo.common.quarantine import unquarantine
from lib.cuckoo.common.exceptions import CuckooDemuxError
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_VERSION
from lib.cuckoo.common.utils import store_temp_file, delete_folder, sanitize_filename, generate_fake_name
from lib.cuckoo.common.utils import convert_to_printable, get_user_filename, get_options, validate_referrer
from lib.cuckoo.common.web_utils import perform_malscore_search, perform_search, perform_ttps_search, search_term_map, get_file_content, statistics
from lib.cuckoo.common.web_utils import get_magic_type, download_file, disable_x64, jsonize, validate_task, my_rate_minutes, my_rate_seconds, apilimiter, apiconf, rateblock, force_int, _download_file, parse_request_arguments
from lib.cuckoo.common.web_utils import download_from_vt

try:
    import pyzipper
    HAVE_PYZIPPER = True
except ImportError:
    HAVE_PYZIPPER = False
    print("Missed pyzipper dependency: pip3 install pyzipper -U")

log = logging.getLogger(__name__)

# FORMAT = '%(asctime)-15s %(clientip)s %(user)-8s %(message)s'

# Config variables
repconf = Config("reporting")
web_conf = Config("web")

if repconf.mongodb.enabled:
    import pymongo
    results_db = pymongo.MongoClient(settings.MONGO_HOST, port=settings.MONGO_PORT, username=settings.MONGO_USER, password=settings.MONGO_PASS, authSource=settings.MONGO_DB)[settings.MONGO_DB]

es_as_db = False
if repconf.elasticsearchdb.enabled and not repconf.elasticsearchdb.searchonly:
    from elasticsearch import Elasticsearch

    es_as_db = True
    baseidx = repconf.elasticsearchdb.index
    fullidx = baseidx + "-*"
    es = Elasticsearch(hosts=[{"host": repconf.elasticsearchdb.host, "port": repconf.elasticsearchdb.port,}], timeout=60)

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

#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['POST'])
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
    task_ids = list()
    for sample in files:
        tmp_path = store_temp_file(sample.read(), sanitize_filename(sample.name))
        try:
            task_id, extra_details = db.demux_sample_and_add_to_db(tmp_path, options=options, priority=priority, static=1, only_extraction=True, user_id=request.user.id or 0)
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
                resp["url"] = [ "{0}/submit/status/{1}/".format(apiconf.api.get("url"), task_ids[0])]
        else:
            resp["data"] = {}
            resp["data"]["message"] = "Task IDs {0} have been submitted".format(", ".join(str(x) for x in task_ids))
            if callback:
                resp["url"] = list()
                for tid in task_ids:
                    resp["url"].append("{0}/submit/status/{1}".format(apiconf.api.get("url"), tid))
            else:
                resp = {"error": True, "error_value": "Error adding task to database"}

    return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['POST'])
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
        quarantine = request.data.get("quarantine", "")
        pcap = request.data.get("pcap", "")
        unique = bool(request.data.get("unique", False))
        static = request.data.get("static", "")
        priority = force_int(request.data.get("priority"))
        options = request.data.get("options", "")
        machine = request.data.get("machine", "")

        if request.data.get("process_dump"):
            if options:
                options += ","
            options += "procmemdump=1,procdump=1"

        details = {
            "errors": [],
            "request": request,
            "task_id": [],
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
        vm_list = []
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
                resp = {"error": True, "error_value": ("Machine '{0}' does not exist. " "Available: {1}".format(machine, ", ".join(vm_list)))}
                return Response(resp)
        # Parse a max file size to be uploaded
        max_file_size = settings.MAX_UPLOAD_SIZE
        if not max_file_size or int(max_file_size) == 0:
            max_file_size = 5 * 1048576
        else:
            max_file_size = int(max_file_size) * 1048576

        files = list()
        # Check if we are allowing multiple file submissions
        multifile = apiconf.filecreate.get("multifile")
        if multifile:
            files = request.FILES.getlist("file")
        else:
            files = [request.FILES.getlist("file")[0]]
        # Handle all files
        for sample in files:
            if sample.size == 0:
                resp = {"error": True, "error_value": "You submitted an empty file"}
                return Response(resp)
            if sample.size > max_file_size:
                resp = {"error": True, "error_value": "File size exceeds API limit"}
                return Response(resp)
            tmp_path = store_temp_file(sample.read(), sanitize_filename(sample.name))
            details["path"] = tmp_path

            if (web_conf.uniq_submission.enabled or unique) and db.check_file_uniq(File(tmp_path).get_sha256(), hours=web_conf.uniq_submission.hours):
                details["errors"].append({sample.name: "Not unique, as unique option set on submit or in conf/web.conf"})
                continue
            if pcap:
                if sample.name.lower().endswith(".saz"):
                    saz = saz_to_pcap(tmp_path)
                    if saz:
                        try:
                            os.remove(tmp_path)
                        except Exception as e:
                            print(e, "removing pcap")
                        tmp_path = saz
                    else:
                        resp = {"error": True, "error_value": "Failed to convert SAZ to PCAP"}
                        return Response(resp)
                task_id = db.add_pcap(file_path=tmp_path)
                details["task_ids"].append(task_id)
                continue
            if static:
                task_id = db.add_static(file_path=tmp_path, priority=priority, user_id=request.user.id or 0)
                details["task_ids"].append(task_id)
                continue
            if quarantine:
                path = unquarantine(tmp_path)
                try:
                    os.remove(tmp_path)
                    tmp_path = path
                except Exception as e:
                    print(e, "removing quarantine")
                try:
                    File(path).get_type()
                except TypeError:
                    details["errors"].append({os.path.basename(tmp_path):"Error submitting file - bad file type"})
                    continue
            else:
                details["content"] = get_file_content(tmp_path)
                status, task_ids_tmp = download_file(**details)
                if status == "error":
                    details["errors"].append({os.path.basename(tmp_path): task_ids_tmp})
                else:
                    details["task_ids"] = task_ids_tmp

        if details.get("task_ids"):
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
                resp["data"]["message"] = "Task IDs {0} have been submitted".format(", ".join(str(x) for x in details.get("task_ids", [])))
                if callback:
                    resp["url"] = list()
                    for tid in details.get("task_ids", []):
                        resp["url"].append("{0}/submit/status/{1}".format(apiconf.api.get("url"), tid))
        else:
            resp = {"error": True, "error_value": "Error adding task to database", "errors": details["errors"]}

    return Response(resp)

#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['POST'])
def tasks_create_url(request):
    if not apiconf.urlcreate.get("enabled"):
        resp = {"error": True, "error_value": "URL Create API is Disabled"}
        return Response(resp)

    resp = {}
    if request.method == "POST":
        resp["error"] = False

        url = request.data.get("url", None)
        static, package, timeout, priority, options, machine, platform, tags, custom, memory, clock, enforce_timeout, \
            shrike_url, shrike_msg, shrike_sid, shrike_refer, unique, referrer, tlp, tags_tasks, route, cape = parse_request_arguments(request)

        task_ids = []
        task_machines = []
        vm_list = []
        for vm in db.list_machines():
            vm_list.append(vm.label)

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
                resp = {"error": True, "error_value": ("Machine '{0}' does not exist. " "Available: {1}".format(machine, ", ".join(vm_list)))}
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


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['POST'])
def tasks_create_dlnexec(request):
    resp = {}
    if request.method == "POST":
        if not apiconf.dlnexeccreate.get("enabled"):
            resp = {"error": True, "error_value": "DL&Exec Create API is Disabled"}
            return Response(resp)

        resp["error"] = False
        url = request.data.get("dlnexec", None)
        if not url:
            resp = {"error": True, "error_value": "URL value is empty"}
            return Response(resp)

        options = request.data.get("options", "")
        custom = request.data.get("custom", "")
        machine = request.data.get("machine", "")
        referrer = validate_referrer(request.data.get("referrer", None))

        details = {}
        task_machines = []
        vm_list = []
        for vm in db.list_machines():
            vm_list.append(vm.label)

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
                resp = {"error": True, "error_value": ("Machine '{0}' does not exist. Available: {1}".format(machine, ", ".join(vm_list)))}
                return Response(resp)

        if referrer:
            if options:
                options += ","
            options += "referrer=%s" % (referrer)

        url = url.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
        response = _download_file(request.data.get("route", None), url, options)
        if not response:
            return Response({"error": "Was impossible to retrieve url"})

        name = os.path.basename(url)
        if not "." in name:
            name = get_user_filename(options, custom) or generate_fake_name()

        path = store_temp_file(response, name)

        content = get_file_content(path)
        details = {
            "errors": [],
            "content": content,
            "request": request,
            "task_id": [],
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
            details["errors"].append({os.path.basename(path): task_ids_tmp})
        else:
            details["task_ids"] = task_ids_tmp

        if details.get("task_ids"):
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
                resp["data"]["message"] = "Task IDs {0} have been submitted".format(", ".join(str(x) for x in details.get("task_ids", [])))
        else:
            resp = {"error": True, "error_value": "Error adding task to database", "errors": details["errors"]}
    else:
        resp = {"error": True, "error_value": "Method not allowed"}

    return Response(resp)


# Download a file from VT for analysis
#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['POST'])
def tasks_vtdl(request):
    resp = {}
    if request.method == "POST":
        # Check if this API function is enabled
        if not apiconf.vtdl.get("enabled"):
            resp = {"error": True, "error_value": "VTDL Create API is Disabled"}
            return Response(resp)

        hashes = request.data.get("vtdl".strip(),None)
        if not hashes:
            hashes = request.data.get("hashes".strip(), None)

        if not hashes:
            resp = {"error": True, "error_value": "vtdl (hash list) value is empty"}
            return Response(resp)

        resp["error"] = False
        options = request.data.get("options", "")
        custom = request.data.get("custom", "")
        machine = request.data.get("machine", "")

        opt_filename = get_user_filename(options, custom)

        task_machines = []
        vm_list = []
        opt_apikey = False
        opts = get_options(options)
        if opts:
            opt_apikey = opts.get("apikey", False)

        if not (settings.VTDL_KEY or opt_apikey) or not settings.VTDL_PATH:
            resp = {"error": True, "error_value": "You specified VirusTotal but must edit the file and specify your VTDL_KEY variable and VTDL_PATH base directory"}
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
                resp = {"error": True, "error_value": ("Machine '{0}' does not exist. " "Available: {1}".format(machine, ", ".join(vm_list)))}
                return Response(resp)


        details = {
            "apikey": settings.VTDL_KEY or opt_apikey,
            "errors": [],
            "content": False,
            "request": request,
            "task_id": [],
            "url": False,
            "params": {},
            "headers": {},
            "service": "VirusTotal",
            "path": "",
            "fhash": False,
            "options": options,
            "only_extraction": False,
            "user_id": request.user.id or 0,
        }

        details = download_from_vt(hashes, details, opt_filename, settings)

        if details.get("task_ids"):
            tasks_count = len(details["task_ids"])
        else:
            tasks_count = 0
        if tasks_count > 0:
            resp["data"] = {}
            resp["errors"] = details["errors"]
            resp["data"]["task_ids"] = details["task_ids"]
            if len(details["task_ids"]) == 1:
                resp["data"]["message"] = "Task ID {0} has been submitted".format(str(details["task_ids"][0]))
            else:
                resp["data"]["message"] = "Task IDs {0} have been submitted".format(", ".join(str(x) for x in details["task_ids"]))
        else:
            resp = {"error": True, "error_value": "Error adding task to database", "errors": details["errors"]}
    else:
        resp = {"error": True, "error_value": "Method not allowed"}

    return Response(resp)


# Return Sample information.
#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def files_view(request, md5=None, sha1=None, sha256=None, sample_id=None):

    if not apiconf.fileview.get("enabled"):
        resp = {"error": True, "error_value": "File View API is Disabled"}
        return Response(resp)

    resp = {}
    if md5 or sha1 or sha256 or sample_id:
        resp["error"] = False
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
#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
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
            resp["data"] = list()
            for sid in sids:
                tasks = db.list_tasks(sample_id=sid)
                for task in tasks:
                    buf = task.to_dict()
                    # Remove path information, just grab the file name
                    buf["target"] = buf["target"].split("/")[-1]
                    resp["data"].append(buf)
        else:
            resp = {"data": [], "error": False}

    return Response(resp)


# Return Task ID's and data that match a hash.
#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['POST'])
def ext_tasks_search(request):
    resp = {}

    if not apiconf.extendedtasksearch.get("enabled"):
        resp = {"error": True, "error_value": "Extended Task Search API is Disabled"}
        return Response(resp)

    return_data = list()
    term = request.data.get("option", "")
    value = request.data.get("argument", "")

    if term and value:
        records = False
        if not term in search_term_map.keys() and term not in ("malscore", "ttp"):
            resp = {"error": True, "error_value": "Invalid Option. '%s' is not a valid option." % term}
            return Response(resp)

        if term in ("ids", "options", "tags_tasks"):
            if all([v.strip().isdigit() for v in value.split(",")]):
                value = [int(v.strip()) for v in filter(None, value.split(","))]
            else:
                return Response({"error": True, "error_value": "Not all values are integers"})
        if term == "ids":
            tmp_value = list()
            for task in db.list_tasks(task_ids=value) or []:
                if task.status == "reported":
                    tmp_value.append(task.id)
                else:
                    return_data.append({"analysis": {"status": task.status, "id": task.id}})
            value = tmp_value
            del tmp_value

        try:
            if term == "malscore":
                records = perform_malscore_search(value)
            elif term == "ttp":
                records = perform_ttps_search(value)
            else:
                records = perform_search(term, value)
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
#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_list(request, offset=None, limit=None, window=None):

    if not apiconf.tasklist.get("enabled", None):
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
    resp["data"] = list()
    resp["config"] = "Limit: {0}, Offset: {1}".format(limit, offset)
    resp["buf"] = 0

    for row in db.list_tasks(
        limit=limit,
        details=True,
        offset=offset,
        completed_after=completed_after,
        status=status,
        options_like=option,
        order_by=Task.completed_on.desc(),
    ):
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
            task["sample"] = sample.to_dict()

        if task["target"]:
            task["target"] = convert_to_printable(task["target"])

        resp["data"].append(task)

    return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_view(request, task_id):

    if not apiconf.taskview.get("enabled"):
        resp = {"error": True, "error_value": "Task View API is Disabled"}
        return Response(resp)

    resp = {}
    task = db.view_task(task_id, details=True)
    resp["error"] = False
    if task:
        entry = task.to_dict()
        if entry["category"] != "url":
            entry["target"] = entry["target"].split("/")[-1]
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

        resp["data"] = entry
    else:
        resp = {"error": True, "error_value": "Task not found in database"}

    return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_reschedule(request, task_id):

    if not apiconf.taskresched.get("enabled"):
        resp = {"error": True, "error_value": "Task Reschedule API is Disabled"}
        return Response(resp)

    if not db.view_task(task_id):
        resp = {"error": True, "error_value": "Task ID does not exist in the database"}
        return Response(resp)

    resp = {}
    if db.reschedule(task_id):
        resp["error"] = False
        resp["data"] = "Task ID {0} has been rescheduled".format(task_id)
    else:
        resp = {"error": True, "error_value": ("An error occured while trying to reschedule " "Task ID {0}".format(task_id))}

    return Response(resp)

#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
@permission_classes((IsAuthenticated, IsAdminUser))
def tasks_delete(request, task_id):
    """
        task_id: int or string if many
        example: 1 or 1,2,3,4

    """
    if not apiconf.taskdelete.get("enabled"):
        resp = {"error": True, "error_value": "Task Deletion API is Disabled"}
        return Response(resp)

    if isinstance(task_id, int):
        task_id = [task_id]
    else:
        task_id = [task.strip() for task in task_id.split(",")]

    resp = {}
    s_deleted = list()
    f_deleted = list()
    for task in task_id:
        check = validate_task(task)
        if check["error"]:
            f_deleted.append(task)
            continue

        # ToDo missed mongo?
        if db.delete_task(task):
            delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task))
            delete_mongo_data(task)

            s_deleted.append(task)
        else:
            f_deleted.append(task)

    if s_deleted:
        resp["data"] = "Task(s) ID(s) {0} has been deleted".format(",".join(s_deleted))

    if f_deleted:
        resp["error"] = True
        resp["failed"] = "Task(s) ID(s) {0} failed to remove".format(",".join(f_deleted))

    return Response(resp)

#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_status(request, task_id):

    if not apiconf.taskstatus.get("enabled"):
        resp = {"error": True, "error_value": "Task status API is disabled"}
        return Response(resp)

    status = db.view_task(task_id).to_dict()["status"]
    if not status:
        resp = {"error": True, "error_value": "Task does not exist"}
    else:
        resp = {"error": False, "data": status}

    return Response(resp)

#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_report(request, task_id, report_format="json"):

    if not apiconf.taskreport.get("enabled"):
        resp = {"error": True, "error_value": "Task Deletion API is Disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    resp = {}
    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports")

    # Report validity check
    if os.path.exists(srcdir) and len(os.listdir(srcdir)) == 0:
        resp = {"error": True, "error_value": "No reports created for task %s" % task_id}

    formats = {
        "json": "report.json",
        "html": "report.html",
        "htmlsummary": "summary-report.html",
        "pdf": "report.pdf",
        "maec": "report.maec-4.1.xml",
        "maec5": "report.maec-5.0.json",
        "metadata": "report.metadata.xml",
    }

    bz_formats = {
        "all": {"type": "-", "files": ["memory.dmp"]},
        "dropped": {"type": "+", "files": ["files"]},
        "dist": {"type": "-", "files": ["binary", "dump_sorted.pcap", "memory.dmp"]},
    }

    tar_formats = {
        "bz2": "w:bz2",
        "gz": "w:gz",
        "tar": "w",
    }

    if report_format.lower() in formats:
        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports", formats[report_format.lower()])
        if os.path.exists(report_path):
            if report_format in ("json", "maec5"):
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
            fname = "%s_report.%s" % (task_id, ext)
            resp = StreamingHttpResponse(FileWrapper(open(report_path, "rb"), 8096), content_type=content or "application/octet-stream;")
            resp["Content-Length"] = os.path.getsize(report_path)
            resp["Content-Disposition"] = "attachment; filename=" + fname
            return resp

        else:
            resp = {"error": True, "error_value": "Reports directory does not exist"}
            return Response(resp)

    elif report_format.lower() == "all":
        if not apiconf.taskreport.get("all"):
            resp = {"error": True, "error_value": "Downloading all reports in one call is disabled"}
            return Response(resp)

        fname = "%s_reports.tar.bz2" % task_id
        s = BytesIO()
        tar = tarfile.open(name=fname, fileobj=s, mode="w:bz2")
        for rep in os.listdir(srcdir):
            tar.add(os.path.join(srcdir, rep), arcname=rep)
        tar.close()
        s.seek(0)
        resp = StreamingHttpResponse(s, content_type="application/octet-stream;")
        resp["Content-Length"] = str(len(s.getvalue()))
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    elif report_format.lower() in bz_formats:
        bzf = bz_formats[report_format.lower()]
        srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id))
        s = BytesIO()

        # By default go for bz2 encoded tar files (for legacy reasons.)
        # tarmode = tar_formats.get("tar", "w:bz2")

        tar = tarfile.open(fileobj=s, mode="w:bz2")
        if not os.path.exists(srcdir):
            resp = {"error": True, "error_value": "Report doesn't exists"}
            return Response(resp)

        for filedir in os.listdir(srcdir):
            try:
                if bzf["type"] == "-" and filedir not in bzf["files"]:
                    tar.add(os.path.join(srcdir, filedir), arcname=filedir)
                if bzf["type"] == "+" and filedir in bzf["files"]:
                    tar.add(os.path.join(srcdir, filedir), arcname=filedir)
            except Exception as e:
                log.error(e, exc_info=True)
        tar.close()
        s.seek(0)
        resp = StreamingHttpResponse(s, content_type="application/octet-stream;")
        resp["Content-Length"] = str(len(s.getvalue()))
        resp["Content-Disposition"] = "attachment; filename=" + report_format.lower()
        return resp

    else:
        resp = {"error": True, "error_value": "Invalid report format specified"}
        return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_iocs(request, task_id, detail=None):

    if not apiconf.taskiocs.get("enabled"):
        resp = {"error": True, "error_value": "IOC download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    buf = {}
    if repconf.mongodb.get("enabled") and not buf:
        buf = results_db.analysis.find_one({"info.id": int(task_id)})
    if es_as_db and not buf:
        tmp = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % task_id)["hits"]["hits"]
        if tmp:
            buf = tmp[-1]["_source"]
        else:
            buf = None
    if buf is None:
        resp = {"error": True, "error_value": "Sample not found in database"}
        return Response(resp)
    if repconf.jsondump.get("enabled") and not buf:
        jfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports", "report.json")
        with open(jfile, "r") as jdata:
            buf = json.load(jdata)
    if not buf:
        resp = {"error": True, "error_value": "Unable to retrieve report to parse for IOCs"}
        return Response(resp)

    data = {}
    # if "certs" in buf:
    #    data["certs"] = buf["certs"]
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
            for x in data["target"]["file"]["yara"]:
                for i in range(0, len(x["strings"])):
                    x["strings"][i] = x["strings"][i].hex()

    data["network"] = {}
    if "network" in list(buf.keys()) and buf["network"]:
        data["network"]["traffic"] = {}
        for netitem in ["tcp", "udp", "irc", "http", "dns", "smtp", "hosts", "domains"]:
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
        data["network"]["ids"]["files"] = list()
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
        if "peid_signatures" in buf["static"] and buf["static"]["peid_signatures"]:
            pe["peid_signatures"] = buf["static"]["peid_signatures"]
        if "pe_timestamp" in buf["static"] and buf["static"]["pe_timestamp"]:
            pe["pe_timestamp"] = buf["static"]["pe_timestamp"]
        if "pe_imphash" in buf["static"] and buf["static"]["pe_imphash"]:
            pe["pe_imphash"] = buf["static"]["pe_imphash"]
        if "pe_icon_hash" in buf["static"] and buf["static"]["pe_icon_hash"]:
            pe["pe_icon_hash"] = buf["static"]["pe_icon_hash"]
        if "pe_icon_fuzzy" in buf["static"] and buf["static"]["pe_icon_fuzzy"]:
            pe["pe_icon_fuzzy"] = buf["static"]["pe_icon_fuzzy"]
        if "Objects" in buf["static"] and buf["static"]["Objects"]:
            pdf["objects"] = len(buf["static"]["Objects"])
        if "Info" in buf["static"] and buf["static"]["Info"]:
            if "PDF Header" in list(buf["static"]["Info"].keys()):
                pdf["header"] = buf["static"]["Info"]["PDF Header"]
        if "Streams" in buf["static"]:
            if "/Page" in list(buf["static"]["Streams"].keys()):
                pdf["pages"] = buf["static"]["Streams"]["/Page"]
        if "Macro" in buf["static"] and buf["static"]["Macro"]:
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
            "spawned_processes": [createProcessTreeNode(child_process) for child_process in buf["behavior"]["processtree"][0]["children"]],
        }
    if "dropped" in buf:
        for entry in buf["dropped"]:
            tmpdict = {}
            if entry.get("clamav", False):
                tmpdict["clamav"] = entry["clamav"]
            if entry["sha256"]:
                tmpdict["sha256"] = entry["sha256"]
            if entry["md5"]:
                tmpdict["md5"] = entry["md5"]
            if entry["yara"]:
                tmpdict["yara"] = entry["yara"]
            if entry.get("trid", False):
                tmpdict["trid"] = entry["trid"]
            if entry["type"]:
                tmpdict["type"] = entry["type"]
            if entry["guest_paths"]:
                tmpdict["guest_paths"] = entry["guest_paths"]
            data["dropped"].append(tmpdict)

    if not detail:
        resp = {"error": False, "data": data}
        return Response(resp)

    if "static" in buf:
        if "pe_versioninfo" in buf["static"] and buf["static"]["pe_versioninfo"]:
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
                data["network"]["http"]["data"] = req["data"].split("\r\n")[0]
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


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_screenshot(request, task_id, screenshot="all"):

    if not apiconf.taskscreenshot.get("enabled"):
        resp = {"error": True, "error_value": "Screenshot download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "shots")

    if len(os.listdir(srcdir)) == 0:
        resp = {"error": True, "error_value": "No screenshots created for task %s" % task_id}
        return Response(resp)

    if screenshot == "all":
        fname = "%s_screenshots.tar.bz2" % task_id
        s = BytesIO()
        tar = tarfile.open(fileobj=s, mode="w:bz2")
        for shot in os.listdir(srcdir):
            tar.add(os.path.join(srcdir, shot), arcname=shot)
        tar.close()
        s.seek(0)
        resp = StreamingHttpResponse(s, content_type="application/octet-stream;")
        resp["Content-Length"] = str(len(s.getvalue()))
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    else:
        shot = srcdir + "/" + screenshot.zfill(4) + ".jpg"
        if os.path.exists(shot):
            resp = StreamingHttpResponse(FileWrapper(open(shot, "rb"), 8096), content_type="image/jpeg")
            resp["Content-Length"] = os.path.getsize(shot)
            return

        else:
            resp = {"error": True, "error_value": "Screenshot does not exist"}
            return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_pcap(request, task_id):

    if not apiconf.taskpcap.get("enabled"):
        resp = {"error": True, "error_value": "PCAP download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    srcfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "dump.pcap")
    if os.path.exists(srcfile):
        fname = "%s_dump.pcap" % task_id
        resp = StreamingHttpResponse(FileWrapper(open(srcfile, "rb"), 8096), content_type="application/vnd.tcpdump.pcap")
        resp["Content-Length"] = os.path.getsize(srcfile)
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    else:
        resp = {"error": True, "error_value": "PCAP does not exist"}
        return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_dropped(request, task_id):

    if not apiconf.taskdropped.get("enabled"):
        resp = {"error": True, "error_value": "Dropped File download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "files")

    if not os.path.exists(srcdir) or not len(os.listdir(srcdir)):
        resp = {"error": True, "error_value": "No files dropped for task %s" % task_id}
        return Response(resp)

    else:
        fname = "%s_dropped.tar.bz2" % task_id
        s = BytesIO()
        tar = tarfile.open(fileobj=s, mode="w:bz2")
        for dirfile in os.listdir(srcdir):
            tar.add(os.path.join(srcdir, dirfile), arcname=dirfile)
        tar.close()
        s.seek(0)
        resp = StreamingHttpResponse(s, content_type="application/octet-stream;")
        resp["Content-Length"] = str(len(s.getvalue()))
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_surifile(request, task_id):

    if not apiconf.taskdropped.get("enabled"):
        resp = {"error": True, "error_value": "Suricata File download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    srcfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "logs", "files.zip")

    if os.path.exists(srcfile):
        fname = "%s_surifiles.zip" % task_id
        resp = StreamingHttpResponse(FileWrapper(open(srcfile, "rb"), 8192), content_type="application/octet-stream;")
        resp["Content-Length"] = os.path.getsize(srcfile)
        resp["Content-Disposition"] = "attachment; filename=" + fname
        return resp

    else:
        resp = {"error": True, "error_value": "No suricata files captured for task %s" % task_id}
        return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
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
        results_db.analysis.find({"suricata.alerts": {"$exists": True}, "_id": {"$gte": dummy_id}}, {"suricata.alerts": 1, "info.id": 1})
    )
    resp = []
    for e in result:
        for alert in e["suricata"]["alerts"]:
            alert["id"] = e["info"]["id"]
            resp.append(alert)

    return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
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
        result = results_db.analysis.find(
            {
                "info.shrike_url": {"$exists": True, "$ne": None},
                "_id": {"$gte": dummy_id},
                "info.shrike_msg": {"$regex": msgfilter, "$options": "-1"},
            },
            {"info.id": 1, "info.shrike_msg": 1, "info.shrike_sid": 1, "info.shrike_url": 1, "info.shrike_refer": 1},
            sort=[("_id", pymongo.DESCENDING)],
        )
    else:
        result = results_db.analysis.find(
            {"info.shrike_url": {"$exists": True, "$ne": None}, "_id": {"$gte": dummy_id}},
            {"info.id": 1, "info.shrike_msg": 1, "info.shrike_sid": 1, "info.shrike_url": 1, "info.shrike_refer": 1},
            sort=[("_id", pymongo.DESCENDING)],
        )

    resp = []
    for e in result:
        tmp = {}
        tmp["id"] = e["info"]["id"]
        tmp["shrike_msg"] = e["info"]["shrike_msg"]
        tmp["shrike_sid"] = e["info"]["shrike_sid"]
        tmp["shrike_url"] = e["info"]["shrike_url"]
        if "shrike_refer" in e["info"] and e["info"]["shrike_refer"]:
            tmp["shrike_refer"] = e["info"]["shrike_refer"]
        resp.append(tmp)

    return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_procmemory(request, task_id, pid="all"):

    if not apiconf.taskprocmemory.get("enabled"):
        resp = {"error": True, "error_value": "Process memory download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    # Check if any process memory dumps exist
    srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "memory")
    if not os.path.exists(srcdir):
        resp = {"error": True, "error_value": "No memory dumps saved"}
        return Response(resp)

    if pid == "all":
        if not apiconf.taskprocmemory.get("all"):
            resp = {"error": True, "error_value": "Downloading of all process memory dumps is disabled"}
            return Response(resp)

        fname = "%s_procdumps.tar.bz2" % task_id
        s = BytesIO()
        tar = tarfile.open(fileobj=s, mode="w:bz2")
        for memdump in os.listdir(srcdir):
            tar.add(os.path.join(srcdir, memdump), arcname=memdump)
        tar.close()
        s.seek(0)
        resp = StreamingHttpResponse(s, content_type="application/octet-stream;")
        resp["Content-Length"] = str(len(s.getvalue()))
        resp["Content-Disposition"] = "attachment; filename=" + fname
    else:
        srcfile = srcdir + "/" + pid + ".dmp"
        if os.path.exists(srcfile):
            if apiconf.taskprocmemory.get("compress"):
                fname = srcfile.split("/")[-1]
                s = BytesIO()
                tar = tarfile.open(fileobj=s, mode="w:bz2")
                tar.add(srcfile, arcname=fname)
                tar.close()
                s.seek(0)
                resp = StreamingHttpResponse(s, content_type="application/octet-stream;")
                archive = "%s-%s_dmp.tar.bz2" % (task_id, pid)
                resp["Content-Length"] = str(len(s.getvalue()))
                resp["Content-Disposition"] = "attachment; filename=" + archive
            else:
                mime = "application/octet-stream"
                fname = "%s-%s.dmp" % (task_id, pid)
                resp = StreamingHttpResponse(FileWrapper(open(srcfile, "rb"), 8096), content_type=mime)
                resp["Content-Length"] = os.path.getsize(srcfile)
                resp["Content-Disposition"] = "attachment; filename=" + fname
        else:
            resp = {"error": True, "error_value": "Process memory dump does not exist for " "pid %s" % pid}
            return Response(resp)

    return resp


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_fullmemory(request, task_id):

    if not apiconf.taskfullmemory.get("enabled"):
        resp = {"error": True, "error_value": "Full memory download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    filename = ""
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "memory.dmp")
    if os.path.exists(file_path):
        filename = os.path.basename(file_path)
    elif os.path.exists(file_path + ".zip"):
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task_id), "memory.dmp.zip")
        if os.path.exists(file_path):
            filename = os.path.basename(file_path)
    elif repconf.distributed.enabled:
        # check for memdump on slave
        try:
            res = requests.get("http://127.0.0.1:9003/task/{task_id}".format(task_id=task_id), verify=False, timeout=30)
            if res and res.ok and res.json()["status"] == 1:
                url = res.json()["url"]
                dist_task_id = res.json()["task_id"]
                return redirect(url.replace(":8090", ":8000") + "apiv2/tasks/get/fullmemory/" + str(dist_task_id) + "/", permanent=True)
        except Exception as e:
            log.error(e)

    if filename:
        content_type = "application/octet-stream"
        chunk_size = 8192
        response = StreamingHttpResponse(FileWrapper(open(file_path, "rb"), chunk_size), content_type=content_type)
        response["Content-Length"] = os.path.getsize(file_path)
        response["Content-Disposition"] = "attachment; filename=%s" % filename
        return response
    else:
        resp = {"error": True, "error_value": "Memory dump not found for task " + task_id}
        return Response(resp)

#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def file(request, stype, value):

    if not apiconf.sampledl.get("enabled"):
        resp = {"error": True, "error_value": "Sample download API is disabled"}
        return Response(resp)

    file_hash = False
    if stype == "md5":
        file_hash = db.find_sample(md5=value).to_dict()["sha256"]
    elif stype == "sha1":
        file_hash = db.find_sample(sha1=value).to_dict()["sha256"]
    elif stype == "sha256":
        file_hash = value
    elif stype == "task":
        check = validate_task(value)
        if check["error"]:
            return Response(check)
        sid = db.view_task(value).to_dict()["sample_id"]
        file_hash = db.view_sample(sid).to_dict()["sha256"]

    sample = os.path.join(CUCKOO_ROOT, "storage", "binaries", file_hash)
    if os.path.exists(sample):
        resp = StreamingHttpResponse(FileWrapper(open(sample, "rb"), 8096), content_type="application/octet-stream")
        resp["Content-Length"] = os.path.getsize(sample)
        resp["Content-Disposition"] = "attachment; filename=" + "%s.bin" % file_hash
        return resp

    else:
        resp = {"error": True, "error_value": "Sample %s was not found" % file_hash}
        return Response(file_hash)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
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


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
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

#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@api_view(['GET'])
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
        resp["data"] = dict(
            version=CUCKOO_VERSION,
            hostname=socket.gethostname(),
            machines=dict(total=len(db.list_machines()), available=db.count_machines_available()),
            tasks=dict(
                total=db.count_tasks(),
                pending=db.count_tasks("pending"),
                running=db.count_tasks("running"),
                completed=db.count_tasks("completed"),
                reported=db.count_tasks("reported"),
            ),
        )
    return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def task_x_hours(request):

    session = db.Session()
    res = session.query(Task).filter(Task.added_on.between(datetime.datetime.now(), datetime.datetime.now() - datetime.timedelta(days=1))).all()
    results = dict()
    if res:
        for date, samples in res:
            results.setdefault(date.strftime("%Y-%m-%eT%H:%M:00"), samples)
    session.close()
    resp = {"error": False, "stats": results}
    return Response(resp)

#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_latest(request, hours):

    resp = {}
    resp["error"] = False
    timestamp = datetime.now() - timedelta(hours=int(hours))
    ids = db.list_tasks(completed_after=timestamp)
    resp["ids"] = [id.to_dict() for id in ids]
    return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_payloadfiles(request, task_id):

    if not apiconf.payloadfiles.get("enabled"):
        resp = {"error": True, "error_value": "CAPE payload file download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    try:
        zippwd = settings.ZIP_PWD
    except AttributeError:
        zippwd = b"infected"

    capepath = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "CAPE")

    if os.path.exists(capepath):
        if not HAVE_PYZIPPER:
            return Response({"error": True, "error_value": "Install pyzipper to be able to download files"})
        mem_zip = BytesIO()
        with pyzipper.AESZipFile(mem_zip, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(zippwd)
            for fname in next(os.walk(capepath))[2]:
                if len(fname) == 64:
                    filepath = os.path.join(capepath, fname)
                    with open(filepath, "rb") as f:
                        zf.writestr(os.path.basename(filepath), f.read())


        mem_zip.seek(0)
        resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
        resp["Content-Length"] = len(mem_zip.getvalue())
        resp["Content-Disposition"] = f"attachment; filename=cape_payloads_{task_id}.zip"
        return resp
    else:
        return Response({"error": True, "error_value": f"No CAPE file(s) for task {task_id}."})


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_procdumpfiles(request, task_id):

    if not apiconf.procdumpfiles.get("enabled"):
        resp = {"error": True, "error_value": "Procdump file download API is disabled"}
        return Response(resp)

    check = validate_task(task_id)
    if check["error"]:
        return Response(check)

    try:
        zippwd = settings.ZIP_PWD
    except AttributeError:
        zippwd = b"infected"

    # ToDo add all/one

    procdumppath = os.path.join(CUCKOO_ROOT, "storage", "analyses", task_id, "procdump")

    #ToDo check bad rturn
    if os.path.exists(procdumppath):
        if not HAVE_PYZIPPER:
            return Response({"error": True, "error_value": "Install pyzipper to be able to download files"})
        mem_zip = BytesIO()
        with pyzipper.AESZipFile(mem_zip, 'w', compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(zippwd)
            for fname in next(os.walk(procdumppath))[2]:
                if len(fname) == 64:
                    filepath = os.path.join(procdumppath, fname)
                    with open(filepath, "rb") as f:
                        zf.writestr(os.path.basename(filepath), f.read())

        mem_zip.seek(0)
        resp = StreamingHttpResponse(mem_zip, content_type="application/zip")
        resp["Content-Length"] = len(mem_zip.getvalue())
        resp["Content-Disposition"] = f"attachment; filename=cape_payloads_{task_id}.zip"
        return resp
    else:
        resp = {"error": True, "error_value": f"No procdump file(s) for task {task_id}."}
        return Response(resp)


#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def tasks_config(request, task_id, cape_name=False):

    if not apiconf.capeconfig.get("enabled"):
        resp = {"error": True, "error_value": "Config download API is disabled"}
        return Response(resp)
    check = validate_task(task_id)

    if check["error"]:
        return Response(check)

    buf = dict()
    if repconf.mongodb.get("enabled"):
        buf = results_db.analysis.find_one({"info.id": int(task_id)}, {"CAPE": 1}, sort=[("_id", pymongo.DESCENDING)])
    if repconf.jsondump.get("enabled") and not buf:
        jfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports", "report.json")
        with open(jfile, "r") as jdata:
            buf = json.load(jdata)
    if es_as_db and not buf:
        tmp = es.search(index=fullidx, doc_type="analysis", q='info.id: "%s"' % str(task_id))["hits"]["hits"]
        if len(tmp) > 1:
            buf = tmp[-1]["_source"]
        elif len(tmp) == 1:
            buf = tmp[0]["_source"]
        else:
            buf = None

    if buf.get("CAPE"):
        try:
            buf["CAPE"] = json.loads(decompress(buf["CAPE"]))
        except:
            pass

        if isinstance(buf, dict) and buf.get("CAPE", False):
            try:
                buf["CAPE"] = json.loads(decompress(buf["CAPE"]))
            except:
                # In case compress results processing module is not enabled
                pass
            data = []
            if not isinstance(buf["CAPE"], list) and buf["CAPE"].get("configs"):
                if cape_name and buf["CAPE"]["configs"].get("cape_name", "") == cape_name:
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
    else:
        resp = {"error": True, "error_value": "Unable to retrieve results for task {}.".format(task_id)}
        return Response(resp)


"""
#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['POST'])
#should be securized by checking category, this is just an example how easy to extend webgui with external tools
def post_processing(request, category, task_id):

    content = request.data.get("content", "")
    if content and category:
        content = json.loads(content)
        if not content:
            return Response({"error": True, "msg": "Missed content data or category"})
        buf = results_db.analysis.find_one({"info.id": int(task_id)}, {"_id": 1})
        if not buf:
            return Response({"error": True, "msg": "Task id doesn't exist"})
        results_db.analysis.update({"_id": ObjectId(buf["_id"])}, {"$set": {category: content}})
        resp = {"error": False, "msg": "Added under the key {}".format(category)}
    else:
        resp = {"error": True, "msg": "Missed content data or category"}

    return Response(resp)
"""

#@ratelimit(key="ip", rate=my_rate_seconds, block=rateblock)
#@ratelimit(key="ip", rate=my_rate_minutes, block=rateblock)
@csrf_exempt
@api_view(['GET'])
def statistics_data(requests, days):
    resp = {}
    if days.isdigit():
        details = statistics(int(days))
        resp = {"Error": False, "data": details}
    else:
        resp = {"Error": True, "error_value": "Provide days as number"}
    return Response(resp)


def limit_exceeded(request, exception):
    resp = {"error": True, "error_value": "Rate limit exceeded for this API"}
    return Response(resp)
