#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import argparse
import json
import os
import socket
import sys
import tarfile
from datetime import datetime
from io import StringIO, BytesIO
from bson import json_util
from zipfile import ZipFile, ZIP_STORED

from zlib import decompress

try:
    from bottle import route, run, request, hook, response, HTTPError
    from bottle import default_app, BaseRequest
except ImportError:
    sys.exit("ERROR: Bottle.py library is missing")

sys.path.append(os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.objects import File
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.saztopcap import saz_to_pcap
from lib.cuckoo.common.web_utils import validate_task
from lib.cuckoo.common.constants import CUCKOO_VERSION, CUCKOO_ROOT
from lib.cuckoo.common.utils import store_temp_file, delete_folder
from lib.cuckoo.common.email_utils import find_attachments_in_email
from lib.cuckoo.common.exceptions import CuckooDemuxError
from lib.cuckoo.core.database import Database, TASK_RUNNING, Task

# Global DB pointer.
db = Database()
repconf = Config("reporting")

# this required for Iocs API
FULL_DB = False
if repconf.mongodb.enabled:
    import pymongo

    results_db = pymongo.MongoClient(
        repconf.mongodb.host,
        port=repconf.mongodb.port,
        username=repconf.mongodb.get("username", None),
        password=repconf.mongodb.get("password", None),
        authSource=repconf.mongodb.db,
    )[repconf.mongodb.db]
    FULL_DB = True

# Increase request size limit
BaseRequest.MEMFILE_MAX = 1024 * 1024 * 4


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


def jsonize(data):
    """Converts data dict to JSON.
    @param data: data dict
    @return: JSON formatted data
    """
    response.content_type = "application/json; charset=UTF-8"
    return json.dumps(data, sort_keys=False, indent=4)


@hook("after_request")
def custom_headers():
    """Set some custom headers across all HTTP responses."""
    response.headers["Server"] = "Machete Server"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Pragma"] = "no-cache"
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Expires"] = "0"


@route("/tasks/create/file", method="POST")
@route("/v1/tasks/create/file", method="POST")
def tasks_create_file():
    response = {}

    data = request.files.file
    pcap = request.POST.get("pcap", "")
    package = request.forms.get("package", "")
    timeout = request.forms.get("timeout", "")
    priority = request.forms.get("priority", 1)
    options = request.forms.get("options", "")
    machine = request.forms.get("machine", "")
    platform = request.forms.get("platform", "")
    tags = request.forms.get("tags", None)
    custom = request.forms.get("custom", "")
    memory = request.forms.get("memory", "False")
    clock = request.forms.get("clock", datetime.now().strftime("%m-%d-%Y %H:%M:%S"))
    if clock is False or clock is None:
        clock = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    if "1970" in clock:
        clock = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    shrike_url = request.forms.get("shrike_url", None)
    shrike_msg = request.forms.get("shrike_msg", None)
    shrike_sid = request.forms.get("shrike_sid", None)
    shrike_refer = request.forms.get("shrike_refer", None)
    static = bool(request.POST.get("static", False))
    unique = bool(request.forms.get("unique", False))
    if memory.upper() == "FALSE" or memory == "0":
        memory = False
    else:
        memory = True

    enforce_timeout = request.forms.get("enforce_timeout", "False")
    if enforce_timeout.upper() == "FALSE" or enforce_timeout == "0":
        enforce_timeout = False
    else:
        enforce_timeout = True

    temp_file_path = store_temp_file(data.file.read(), data.filename)

    if unique and db.check_file_uniq(File(temp_file_path).get_sha256()):
        resp = {"error": True, "error_value": "Duplicated file, disable unique option to force submission"}
        return jsonize(resp)

    if pcap:
        if data.filename.lower().endswith(".saz"):
            saz = saz_to_pcap(temp_file_path)
            if saz:
                path = saz
                try:
                    os.remove(temp_file_path)
                except:
                    pass
            else:
                resp = {"error": True, "error_value": "Failed to convert PCAP to SAZ"}
                return jsonize(resp)
        else:
            path = temp_file_path
        task_id = db.add_pcap(file_path=path)
        task_ids = [task_id]
    else:

        try:
            task_ids, extra_details = db.demux_sample_and_add_to_db(
                file_path=temp_file_path,
                package=package,
                timeout=timeout,
                options=options,
                priority=priority,
                machine=machine,
                platform=platform,
                custom=custom,
                memory=memory,
                enforce_timeout=enforce_timeout,
                tags=tags,
                clock=clock,
                shrike_url=shrike_url,
                shrike_msg=shrike_msg,
                shrike_sid=shrike_sid,
                shrike_refer=shrike_refer,
                static=static,
            )
        except CuckooDemuxError as e:
            return HTTPError(500, e)

    response["task_ids"] = task_ids
    return jsonize(response)


@route("/tasks/create/url", method="POST")
@route("/v1/tasks/create/url", method="POST")
def tasks_create_url():
    response = {}

    url = request.forms.get("url")
    package = request.forms.get("package", "")
    timeout = request.forms.get("timeout", "")
    priority = request.forms.get("priority", 1)
    options = request.forms.get("options", "")
    machine = request.forms.get("machine", "")
    platform = request.forms.get("platform", "")
    tags = request.forms.get("tags", None)
    custom = request.forms.get("custom", "")
    memory = request.forms.get("memory", False)
    shrike_url = request.forms.get("shrike_url", None)
    shrike_msg = request.forms.get("shrike_msg", None)
    shrike_sid = request.forms.get("shrike_sid", None)
    shrike_refer = request.forms.get("shrike_refer", None)
    enforce_timeout = request.forms.get("enforce_timeout", False)

    try:
        if int(memory):
            memory = True
    except:
        pass
    try:
        if int(enforce_timeout):
            enforce_timeout = True
    except:
        pass

    clock = request.forms.get("clock", None)
    if clock is False or clock is None:
        clock = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    if "1970" in clock:
        clock = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    task_id = db.add_url(
        url=url,
        package=package,
        timeout=timeout,
        options=options,
        priority=priority,
        machine=machine,
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
    )

    response["task_id"] = task_id
    return jsonize(response)


@route("/tasks/list", method="GET")
@route("/v1/tasks/list", method="GET")
@route("/tasks/list/<limit:int>", method="GET")
@route("/v1/tasks/list/<limit:int>", method="GET")
@route("/tasks/list/<limit:int>/<offset:int>", method="GET")
@route("/v1/tasks/list/<limit:int>/<offset:int>", method="GET")
def tasks_list(limit=None, offset=None):
    response = {}

    response["tasks"] = []

    completed_after = request.GET.get("completed_after")
    if completed_after:
        completed_after = datetime.fromtimestamp(int(completed_after))

    status = request.GET.get("status")

    # optimisation required for dist speedup
    ids = request.GET.get("ids")

    for row in db.list_tasks(
        limit=limit, details=True, offset=offset, completed_after=completed_after, status=status, order_by=Task.completed_on.asc()
    ):
        task = row.to_dict()
        if ids:
            task = {"id": task["id"], "completed_on": task["completed_on"]}

        else:
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

        response["tasks"].append(task)

    return jsonize(response)


@route("/tasks/view/<task_id:int>", method="GET")
@route("/v1/tasks/view/<task_id:int>", method="GET")
def tasks_view(task_id):
    response = {}

    task = db.view_task(task_id, details=True)
    if task:
        entry = task.to_dict()
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

        response["task"] = entry
    else:
        return HTTPError(404, "Task not found")

    return jsonize(response)


@route("/tasks/reschedule/<task_id:int>", method="GET")
@route("/v1/tasks/reschedule/<task_id:int>", method="GET")
def tasks_reschedule(task_id):
    response = {}

    if not db.view_task(task_id):
        return HTTPError(404, "There is no analysis with the specified ID")

    if db.reschedule(task_id):
        response["status"] = "OK"
    else:
        return HTTPError(500, "An error occurred while trying to " "reschedule the task")

    return jsonize(response)


@route("/tasks/delete_many", method="POST")
@route("/v1/tasks/delete_many", method="POST")
def tasks_delete():
    response = {}
    tasks = request.forms.get("ids", "")
    tasks = tasks.split(",")
    for task_id in tasks:
        task_id = int(task_id)
        task = db.view_task(task_id)
        if task:
            if task.status == TASK_RUNNING:
                response.setdefault(task_id, "running")
                continue
            if db.delete_task(task_id):
                delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%d" % task_id))
            if FULL_DB:
                task = results_db.analysis.find_one({"info.id": task_id})
                if task is not None:
                    for processes in task.get("behavior", {}).get("processes", []):
                        [results_db.calls.remove(call) for call in processes.get("calls", [])]

                    results_db.analysis.remove({"info.id": task_id})
            else:
                response.setdefault(task_id, "deletion failed")
        else:
            response.setdefault(task_id, "not exists")
    response["status"] = "OK"
    return jsonize(response)


@route("/tasks/delete/<task_id:int>", method="GET")
@route("/v1/tasks/delete/<task_id:int>", method="GET")
def tasks_delete(task_id):
    response = {}
    task = db.view_task(task_id)
    if task:
        if task.status == TASK_RUNNING:
            return HTTPError(500, "The task is currently being " "processed, cannot delete")

        if db.delete_task(task_id):
            delete_folder(os.path.join(CUCKOO_ROOT, "storage", "analyses", "%d" % task_id))
            if FULL_DB:
                task = results_db.analysis.find_one({"info.id": task_id})
                if task is not None:
                    for processes in task.get("behavior", {}).get("processes", []):
                        [results_db.calls.remove(call) for call in processes.get("calls", [])]

                    results_db.analysis.remove({"info.id": task_id})

            response["status"] = "OK"
        else:
            return HTTPError(500, "An error occurred while trying to " "delete the task")
    else:
        return HTTPError(404, "Task not found")

    return jsonize(response)


@route("/tasks/report/<task_id:int>", method="GET")
@route("/v1/tasks/report/<task_id:int>", method="GET")
@route("/tasks/report/<task_id:int>/<report_format>", method="GET")
@route("/v1/tasks/report/<task_id:int>/<report_format>", method="GET")
def tasks_report(task_id, report_format="json"):
    formats = {
        "json": "report.json",
        "html": "report.html",
        "htmlsumary": "summary-report.html",
        "pdf": "report.pdf",
        "maec": "report.maec-4.1.xml",
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
        report_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%d" % task_id, "reports", formats[report_format.lower()])
    elif report_format.lower() in bz_formats:
        bzf = bz_formats[report_format.lower()]
        srcdir = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%d" % task_id)
        s = StringIO()

        # By default go for bz2 encoded tar files (for legacy reasons.)
        tarmode = tar_formats.get(request.GET.get("tar"), "w:bz2")

        tar = tarfile.open(fileobj=s, mode=tarmode)
        if not os.path.exists(srcdir):
            return HTTPError(400, "Path doesn't exists")

        for filedir in os.listdir(srcdir):
            try:
                if bzf["type"] == "-" and filedir not in bzf["files"]:
                    tar.add(os.path.join(srcdir, filedir), arcname=filedir)
                if bzf["type"] == "+" and filedir in bzf["files"]:
                    tar.add(os.path.join(srcdir, filedir), arcname=filedir)
            except Exception as e:
                print(e)
        tar.close()
        response.content_type = "application/x-tar; charset=UTF-8"
        return s.getvalue()
    else:
        return HTTPError(400, "Invalid report format")

    if os.path.exists(report_path):
        return open(report_path, "rb").read()
    else:
        return HTTPError(404, "Report not found")


@route("/tasks/iocs/<task_id:int>", method="GET")
@route("/v1/tasks/iocs/<task_id:int>", method="GET")
def tasks_iocs(task_id, detail=False):

    buf = {}
    if FULL_DB:
        buf = results_db.analysis.find_one({"info.id": task_id})

    if not buf:
        jfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports", "report.json")

        if os.path.exists(jfile):
            with open(jfile, "r") as jdata:
                buf = json.load(jdata)

    if buf is None:
        resp = {"error": True, "error_value": "Sample not found in database"}
        return jsonize(resp)

    data = {}
    if "tr_extractor" in buf:
        data["tr_extractor"] = buf["tr_extractor"]
    if "certs" in buf:
        data["certs"] = buf["certs"]
    data["malfamily"] = buf.get("malfamily", "")
    data["malscore"] = buf.get("malscore", "")
    data["info"] = buf.get("info", {})
    if data["info"].get("custom", ""):
        del data["info"]["custom"]
    # The machines key won't exist in cases where an x64 binary is submitted
    # when there are no x64 machines.
    if "machine" in data.get("info", {}):
        del data["info"]["machine"]["manager"]
        del data["info"]["machine"]["label"]
        del data["info"]["machine"]["id"]
    data["signatures"] = []
    # Grab sigs
    for sig in buf.get("signatures", []):
        del sig["alert"]
        data["signatures"].append(sig)
    # Grab target file info
    if "target" in list(buf.keys()):
        data["target"] = buf["target"]
        if data["target"].get("category", "") == "file":
            del data["target"]["file"]["path"]
            del data["target"]["file"]["guest_paths"]
    data["network"] = {}
    if "network" in list(buf.keys()):
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
    if "suricata" in list(buf.keys()):
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
            if entry["clamav"]:
                tmpdict["clamav"] = entry["clamav"]
            if entry["sha256"]:
                tmpdict["sha256"] = entry["sha256"]
            if entry["md5"]:
                tmpdict["md5"] = entry["md5"]
            if entry["yara"]:
                tmpdict["yara"] = entry["yara"]
            if entry["type"]:
                tmpdict["type"] = entry["type"]
            if entry["guest_paths"]:
                tmpdict["guest_paths"] = entry["guest_paths"]
            data["dropped"].append(tmpdict)

    if not detail:
        resp = {"error": False, "data": data}
        return jsonize(resp)

    if "static" in buf:
        if "pe_versioninfo" in buf["static"] and buf["static"]["pe_versioninfo"]:
            data["static"]["pe"]["pe_versioninfo"] = buf["static"]["pe_versioninfo"]

    if "behavior" in buf and "summary" in buf["behavior"]:
        if "read_files" in buf["behavior"]["summary"]:
            data["files"]["read"] = buf["behavior"]["summary"]["read_files"]
        if "read_keys" in buf["behavior"]["summary"]:
            data["registry"]["read"] = buf["behavior"]["summary"]["read_keys"]

    if buf.get("network", {}) and "http" in buf["network"]:
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

    resp = {"error": False, "data": data}
    return jsonize(resp)


@route("/files/view/md5/<md5>", method="GET")
@route("/v1/files/view/md5/<md5>", method="GET")
@route("/files/view/sha1/<md5>", method="GET")
@route("/v1/files/view/sha1/<md5>", method="GET")
@route("/files/view/sha256/<sha256>", method="GET")
@route("/v1/files/view/sha256/<sha256>", method="GET")
@route("/files/view/id/<sample_id:int>", method="GET")
@route("/v1/files/view/id/<sample_id:int>", method="GET")
def files_view(md5=None, sha1=None, sha256=None, sample_id=None):
    response = {}

    if md5:
        sample = db.find_sample(md5=md5)
    elif sha1:
        sample = db.find_sample(sha1=sha1)
    elif sha256:
        sample = db.find_sample(sha256=sha256)
    elif sample_id:
        sample = db.view_sample(sample_id)
    else:
        return HTTPError(400, "Invalid lookup term")

    if sample:
        response["sample"] = sample.to_dict()
    else:
        return HTTPError(404, "File not found")

    return jsonize(response)


@route("/files/get/<sha256:re:[\w\d]{64}>", method="GET")
@route("/v1/files/get/<sha256:re:[\w\d]{64}>", method="GET")
def files_get(sha256):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256)
    if os.path.exists(file_path):
        response.content_type = "application/octet-stream; charset=UTF-8"
        return open(file_path, "rb").read()
    else:
        return HTTPError(404, "File not found")


@route("/pcap/get/<task_id:int>", method="GET")
@route("/v1/pcap/get/<task_id:int>", method="GET")
def pcap_get(task_id):
    file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%d" % task_id, "dump.pcap")
    if os.path.exists(file_path):
        response.content_type = "application/octet-stream; charset=UTF-8"
        try:
            return open(file_path, "rb").read()
        except:
            return HTTPError(500, "An error occurred while reading PCAP")
    else:
        return HTTPError(404, "File not found")


@route("/machines/list", method="GET")
@route("/v1/machines/list", method="GET")
def machines_list():
    response = {}

    machines = db.list_machines()

    response["data"] = []
    for row in machines:
        response["data"].append(row.to_dict())

    return jsonize(response)


@route("/machines/delete/<machine_name>", method="GET")
@route("/v1/machines/delete/<machine_name>", method="GET")
def machines_delete(machine_name):
    response = {}

    status = db.delete_machine(machine_name)

    response["status"] = status
    if status == "success":
        response["data"] = "Deleted machine %s" % machine_name
    return jsonize(response)


@route("/cuckoo/status", method="GET")
@route("/v1/cuckoo/status", method="GET")
def cuckoo_status():
    response = dict(
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

    return jsonize(response)


@route("/machines/view/<name>", method="GET")
@route("/v1/machines/view/<name>", method="GET")
def machines_view(name=None):
    response = {}

    machine = db.view_machine(name=name)
    if machine:
        response["machine"] = machine.to_dict()
    else:
        return HTTPError(404, "Machine not found")

    return jsonize(response)


@route("/tasks/screenshots/<task:int>", method="GET")
@route("/v1/tasks/screenshots/<task:int>", method="GET")
@route("/tasks/screenshots/<task:int>/<screenshot>", method="GET")
@route("/v1/tasks/screenshots/<task:int>/<screenshot>", method="GET")
def task_screenshots(task=0, screenshot=None):
    folder_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task), "shots")

    if os.path.exists(folder_path):
        if screenshot:
            screenshot_name = "{0}.jpg".format(screenshot)
            screenshot_path = os.path.join(folder_path, screenshot_name)
            if os.path.exists(screenshot_path):
                # TODO: Add content disposition.
                response.content_type = "image/jpeg"
                return open(screenshot_path, "rb").read()
            else:
                return HTTPError(404, screenshot_path)
        else:
            zip_data = BytesIO()
            with ZipFile(zip_data, "w", ZIP_STORED) as zip_file:
                for shot_name in os.listdir(folder_path):
                    zip_file.write(os.path.join(folder_path, shot_name), shot_name)

            # TODO: Add content disposition.
            response.content_type = "application/zip"
            return zip_data.getvalue()
    else:
        return HTTPError(404, folder_path)


@route("/api/tasks/get/config/<task_id:int>/", method="GET")
@route("/api/tasks/get/config/<task_id:int>/<cape_name>", method="GET")
def tasks_config(task_id, cape_name=False):
    check = validate_task(task_id)

    if check["error"]:
        return jsonize(check)

    buf = dict()
    if repconf.mongodb.get("enabled"):
        buf = results_db.analysis.find_one({"info.id": int(task_id)}, {"CAPE": 1}, sort=[("_id", pymongo.DESCENDING)])
    if repconf.jsondump.get("enabled") and not buf:
        jfile = os.path.join(CUCKOO_ROOT, "storage", "analyses", "%s" % task_id, "reports", "report.json")
        with open(jfile, "r") as jdata:
            buf = json.load(jdata)

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
            for cape in buf["CAPE"]:
                if isinstance(cape, dict) and cape.get("cape_config"):
                    if cape_name and cape.get("cape_name", "") == cape_name:
                        return jsonize(cape["cape_config"])
                    data.append(cape)
            if data:
                resp = {"error": False, "configs": data}
            else:
                resp = {"error": True, "error_value": "CAPE config for task {} does not exist.".format(task_id)}
            return jsonize(resp)
        else:
            resp = {"error": True, "error_value": "CAPE config for task {} does not exist.".format(task_id)}
            return jsonize(resp)
    else:
        resp = {"error": True, "error_value": "Unable to retrieve results for task {}.".format(task_id)}
        return jsonize(resp)


application = default_app()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host to bind the API server on", default="localhost", action="store", required=False)
    parser.add_argument("-p", "--port", help="Port to bind the API server on", default=8090, action="store", required=False)
    args = parser.parse_args()

    print("Depricated in favour of /api/ that is integrated in webgui")
    run(host=args.host, port=args.port)
