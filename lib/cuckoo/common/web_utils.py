from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import json
import magic
import logging
import requests
import hashlib
import tempfile
from datetime import datetime, timedelta
from random import choice
from collections import OrderedDict

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))
sys.path.append(CUCKOO_ROOT)

from django.http import HttpResponse
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import HAVE_PEFILE, pefile, IsPEImage
from lib.cuckoo.core.rooter import _load_socks5_operational
from lib.cuckoo.core.database import Database, Task, Sample, TASK_REPORTED
from lib.cuckoo.common.utils import get_ip_address, bytes2str, validate_referrer, sanitize_filename

cfg = Config("cuckoo")
repconf = Config("reporting")
socks5_conf = Config("socks5")
routing_conf = Config("routing")
machinery = Config(cfg.cuckoo.machinery)
disable_x64 = cfg.cuckoo.get("disable_x64", False)

apiconf = Config("api")
rateblock = apiconf.api.get("ratelimit", False)

db = Database()

HAVE_DIST = False
# Distributed CAPE
if repconf.distributed.enabled:
    try:
        # Tags
        from lib.cuckoo.common.dist_db import Machine, create_session, Task as DTask, Node
        HAVE_DIST = True
        dist_session = create_session(repconf.distributed.db)
    except Exception as e:
        print(e)


ht = False
try:
    """
        To enable: sudo apt install apache2-utils

    """
    from passlib.apache import HtpasswdFile

    HAVE_PASSLIB = True
    if apiconf.api.get("users_db") and os.path.exists(apiconf.api.get("users_db")):
        ht = HtpasswdFile(apiconf.api.get("users_db"))
except ImportError:
    HAVE_PASSLIB = False

if repconf.mongodb.enabled:
    import pymongo

    results_db = pymongo.MongoClient(
        repconf.mongodb.host,
        port=repconf.mongodb.port,
        username=repconf.mongodb.get("username", None),
        password=repconf.mongodb.get("password", None),
        authSource=repconf.mongodb.get("db", "cuckoo"),
    )[repconf.mongodb.get("db", "cuckoo")]

es_as_db = False
essearch = False
if repconf.elasticsearchdb.enabled:
    from elasticsearch import Elasticsearch

    essearch = repconf.elasticsearchdb.searchonly
    if not essearch:
        es_as_db = True
    baseidx = repconf.elasticsearchdb.index
    fullidx = baseidx + "-*"
    es = Elasticsearch(hosts=[{"host": repconf.elasticsearchdb.host, "port": repconf.elasticsearchdb.port,}], timeout=60)

VALID_LINUX_TYPES = ["Bourne-Again", "POSIX shell script", "ELF", "Python"]

hashes = {
    32: hashlib.md5,
    40: hashlib.sha1,
    64: hashlib.sha256,
    128: hashlib.sha512,
}

user_agents = [
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko",
]

log = logging.getLogger(__name__)

db = Database()

if cfg.cuckoo.machinery == "multi":
    for mmachinery in Config("multi").multi.get("machinery").split(","):
        try:
            iface = getattr(Config(mmachinery), mmachinery).interface
            break
        except Exception as e:
            log.error(e)
else:
    iface = getattr(machinery, cfg.cuckoo.machinery).interface

try:
    iface_ip = get_ip_address(iface)
except Exception as e:
    print(e)
    iface_ip = "127.0.0.1"

apilimiter = {
    "tasks_create_file": apiconf.filecreate,
    "tasks_create_url": apiconf.urlcreate,
    "tasks_create_static": apiconf.staticextraction,
    "tasks_create_dlnexec": apiconf.dlnexeccreate,
    "tasks_vtdl": apiconf.vtdl,
    "files_view": apiconf.fileview,
    "tasks_search": apiconf.tasksearch,
    "ext_tasks_search": apiconf.extendedtasksearch,
    "tasks_list": apiconf.tasklist,
    "tasks_view": apiconf.taskview,
    "tasks_reschedule": apiconf.taskresched,
    "tasks_delete": apiconf.taskdelete,
    "tasks_status": apiconf.taskstatus,
    "tasks_report": apiconf.taskreport,
    "tasks_iocs": apiconf.taskiocs,
    "tasks_screenshot": apiconf.taskscreenshot,
    "tasks_pcap": apiconf.taskpcap,
    "tasks_dropped": apiconf.taskdropped,
    "tasks_surifile": apiconf.tasksurifile,
    "tasks_rollingsuri": apiconf.rollingsuri,
    "tasks_rollingshrike": apiconf.rollingshrike,
    "task_procdump": apiconf.taskprocdump,
    "tasks_procmemory": apiconf.taskprocmemory,
    "tasks_fullmemory": apiconf.taskprocmemory,
    "get_files": apiconf.sampledl,
    "machines_list": apiconf.machinelist,
    "machines_view": apiconf.machineview,
    "cuckoo_status": apiconf.cuckoostatus,
    "task_x_hours": apiconf.task_x_hours,
    "tasks_latest": apiconf.tasks_latest,
    # "post_processing":
    "tasks_payloadfiles": apiconf.payloadfiles,
    "tasks_procdumpfiles": apiconf.procdumpfiles,
    "tasks_config": apiconf.capeconfig,
    "file": apiconf.download_file,
    "filereport": apiconf.filereport,
    "statistics": apiconf.statistics,
    "full_memory_dump_file": apiconf.full_memory_dump_file,
    "full_memory_dump_file_strings": apiconf.full_memory_dump_file_strings,
    "comments": apiconf.comments,
    "search": apiconf.web_search,
}

# https://django-ratelimit.readthedocs.io/en/stable/rates.html#callables
def my_rate_seconds(group, request):
    # RateLimits not enabled
    if rateblock is False:
        return "99999999999999/s"

    username = False
    password = False
    group = group.split(".")[-1]
    if group in apilimiter and apilimiter[group].get("enabled"):

        # better way to handle this?
        if request.method == "POST":
            username = request.POST.get("username", "")
            password = request.POST.get("password", "")
        elif request.method == "GET":
            username = request.GET.get("username", "")
            password = request.GET.get("password", "")
        if username and password and HAVE_PASSLIB and ht and ht.check_password(username, password):
            return None
        elif apilimiter[group].get("auth_only"):
            return "0/s"
        else:
            return apilimiter[group].get("rps")

    return "0/s"

def my_rate_minutes(group, request):
    # RateLimits not enabled
    if rateblock is False:
        return "99999999999999/m"

    group = group.split(".")[-1]
    if group in apilimiter and apilimiter[group].get("enabled"):
        username = False
        password = False

        # better way to handle this?
        if request.method == "POST":
            username = request.POST.get("username", "")
            password = request.POST.get("password", "")
        elif request.method == "GET":
            username = request.GET.get("username", "")
            password = request.GET.get("password", "")

        if username and password and HAVE_PASSLIB and ht and ht.check_password(username, password):
            return None
        elif apilimiter[group].get("auth_only"):
            return "0/m"
        else:
            return apilimiter[group].get("rpm")

    return "0/m"

def load_vms_tags():
    all_tags = list()
    if HAVE_DIST and repconf.distributed.enabled:
        try:
            db = dist_session()
            for vm in db.query(Machine).all():
                all_tags += vm.tags
            all_tags = sorted(filter(None, all_tags))
            db.close()
        except Exception as e:
            print(e)

    for machine in Database().list_machines():
        for tag in machine.tags:
            all_tags.append(tag.name)

    return all_tags

all_vms_tags = load_vms_tags()


def statistics(s_days: int) -> dict:
    date_since = datetime.now()-timedelta(days=s_days)
    date_till = datetime.now()

    details = {
        "signatures": {},
        "processing": {},
        "reporting": {},
        "top_samples": {},
        "detections": {},
    }

    tmp_data = dict()
    results_db = pymongo.MongoClient(repconf.mongodb.host, repconf.mongodb.port)[repconf.mongodb.db]
    data = results_db.analysis.find({"statistics":{"$exists":True}, "info.started": {"$gte": date_since.isoformat()}}, {"statistics": 1, "malfamily": 1, "detections":1, "_id": 0})
    for analysis in data or []:

        malfamily = False
        if "detections" in analysis:
            malfamily = analysis["detections"]
        elif "malfamily" in analysis:
            malfamily = analysis["malfamily"]
        if malfamily:
            details["detections"].setdefault(malfamily, 0)
            details["detections"][malfamily] += 1

        for type_entry in analysis.get("statistics", []) or []:
            if type_entry not in tmp_data:
                tmp_data.setdefault(type_entry, dict())
            for entry in analysis["statistics"][type_entry]:
                if entry["name"] not in tmp_data[type_entry]:
                    tmp_data[type_entry].setdefault(entry["name"], dict())
                    tmp_data[type_entry][entry["name"]]["time"] = entry["time"]
                    tmp_data[type_entry][entry["name"]]["runs"] = 1
                else:
                    tmp_data[type_entry][entry["name"]]["time"] += entry["time"]
                    tmp_data[type_entry][entry["name"]]["runs"] += 1

    for module_name in [u'signatures', u'processing', u'reporting']:
        s = sorted(tmp_data[module_name], key=tmp_data[module_name].get("time"), reverse=True)[:20]
        for entry in s:
            times_in_mins = tmp_data[module_name][entry]["time"]/60
            if not times_in_mins:
                continue
            details[module_name].setdefault(entry, dict())
            details[module_name][entry]["total"] = float("{:.2f}".format(round(times_in_mins, 2)))
            details[module_name][entry]["runs"] = tmp_data[module_name][entry]["runs"]
            details[module_name][entry]["average"] = float("{:.2f}".format(round(times_in_mins/tmp_data[module_name][entry]["runs"], 2)))

        details[module_name] = OrderedDict(sorted(details[module_name].items(), key=lambda x: x[1]["total"], reverse=True))

    top_samples = dict()
    session = db.Session()
    tasks = session.query(Task).join(Sample, Task.sample_id==Sample.id).filter(Task.added_on.between(date_since, date_till)).all()
    details["total"] = len(tasks)
    details["average"] = "{:.2f}".format(round(details["total"]/s_days, 2))
    details["tasks"] = dict()
    for task in tasks or []:
        day = task.added_on.strftime("%Y-%m-%d")
        if day not in details["tasks"]:
            details["tasks"].setdefault(day, {})
            details["tasks"][day].setdefault("failed", 0)
            details["tasks"][day].setdefault("reported", 0)
            details["tasks"][day].setdefault("added", 0)
        if day not in top_samples:
            top_samples.setdefault(day, dict())
        if task.sample.sha256 not in top_samples[day]:
            top_samples[day].setdefault(task.sample.sha256, 0)
        top_samples[day][task.sample.sha256] += 1
        details["tasks"][day]["added"] += 1
        if task.status in ("failed_analysis", "failed_reporting", "failed_processing"):
            details["tasks"][day]["failed"] += 1
        elif task.status == "reported":
            details["tasks"][day]["reported"] += 1

    details["tasks"] = OrderedDict(sorted(details["tasks"].items(), key=lambda x: datetime.strptime(x[0], "%Y-%m-%d"), reverse=True))

    if HAVE_DIST and repconf.distributed.enabled:
        details["distributed_tasks"] = dict()
        dist_db = dist_session()
        dist_tasks = dist_db.query(DTask).filter(DTask.clock.between(date_since, date_till)).all()
        id2name = dict()
        #load node names
        for node in dist_db.query(Node).all() or []:
            id2name.setdefault(node.id, node.name)

        for task in dist_tasks or []:
            day = task.clock.strftime("%Y-%m-%d")
            if day not in details["distributed_tasks"]:
                details["distributed_tasks"].setdefault(day, {})
            if id2name[task.node_id] not in details["distributed_tasks"][day]:
                details["distributed_tasks"][day].setdefault(id2name[task.node_id], 0)
            details["distributed_tasks"][day][id2name[task.node_id]] += 1
        dist_db.close()

        details["distributed_tasks"] = OrderedDict(sorted(details["distributed_tasks"].items(), key=lambda x: x[1], reverse=True))

    # Get top15 of samples per day and seen more than once
    for day in top_samples:
        if day not in details["top_samples"]:
            details["top_samples"].setdefault(day, {})
        for sha256 in OrderedDict(sorted(top_samples[day].items(), key=lambda x: x[1], reverse=True)[:15]):
            if top_samples[day][sha256] > 1:
                details["top_samples"][day][sha256] = top_samples[day][sha256]

        details["top_samples"][day] = OrderedDict(sorted(details["top_samples"][day].items(), key=lambda x: x[1], reverse=True))
    details["top_samples"] = OrderedDict(sorted(details["top_samples"].items(), key=lambda x: datetime.strptime(x[0], "%Y-%m-%d"), reverse=True))

    # top 15 detections
    details["detections"] = OrderedDict(sorted(details["detections"].items(), key=lambda x: x[1], reverse=True)[:20])

    session.close()
    return details

# Same jsonize function from api.py except we can now return Django
# HttpResponse objects as well. (Shortcut to return errors)
def jsonize(data, response=False):
    """Converts data dict to JSON.
    @param data: data dict
    @return: JSON formatted data or HttpResponse object with json data
    """
    if response:
        jdata = json.dumps(data, sort_keys=False, indent=4)
        return HttpResponse(jdata, content_type="application/json; charset=UTF-8")
    else:
        return json.dumps(data, sort_keys=False, indent=4)


def get_file_content(paths):
    content = False
    if not isinstance(paths, list):
        paths = [paths]
    for path in paths:
        if os.path.exists(path):
            with open(path, "rb") as f:
                content = f.read()
            break
    return content


def fix_section_permission(path):
    if not HAVE_PEFILE:
        log.info("[-] Missed dependency pefile")
        return
    try:
        if not IsPEImage:
            return
        pe = pefile.PE(path)
        if not pe:
            return
        for id in range(len(pe.sections)):
            if pe.sections[id].Name.rstrip("\0") == ".rdata" and hex(pe.sections[id].Characteristics)[:3] == "0x4":
                pe.sections[id].Characteristics += pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]
                pe.write(filename=path)
        pe.close()
    except Exception as e:
        log.info(e)


# Submission hooks to set options based on some naming patterns
def recon(filename, orig_options, timeout, enforce_timeout):
    filename = filename.lower()
    if not isinstance(filename, str):
        filename = bytes2str(filename)
    if "name" in filename:
        orig_options += ",timeout=400,enforce_timeout=1,procmemdump=1,procdump=1"
        timeout = 400
        enforce_timeout = True

    return orig_options, timeout, enforce_timeout


def get_magic_type(data):
    try:
        if os.path.exists(data):
            return magic.from_file(data)
        else:
            return magic.from_buffer(data)
    except Exception as e:
        print(e)

    return False


def get_platform(magic):
    if magic and any(x in magic for x in VALID_LINUX_TYPES):
        return "linux"
    else:
        return "windows"

def download_file(**kwargs):
    """ Example of kwargs
    {
        "errors": [],
        "content": content,
        "request": request,
        "task_id": [],
        "url": False,
        "params": {},
        "headers": {},
        "service": "tasks_create_file_API",
        "path": tmp_path,
        "fhash": False,
        "options": options,
        "only_extraction": False,
    }
    """

    static, package, timeout, priority, _, machine, platform, tags, custom, memory, \
            clock, enforce_timeout, shrike_url, shrike_msg, shrike_sid, shrike_refer, unique, referrer, \
            tlp, tags_tasks, route, cape = parse_request_arguments(kwargs["request"])
    onesuccess = False


    if package:
        if package == "Emotet":
            return "error", {"error": "Hey guy update your script, this package doesn't exist anymore"}

    if tags:
        if not all([tag.strip() in all_vms_tags for tag in tags.split(",")]):
            return "error", {"error": "Check Tags help, you have introduced incorrect tag(s)"}
        elif all([tag in tags for tag in ("x64", "x86")]):
            return "error", {"error": "Check Tags help, you have introduced x86 and x64 tags for the same task, choose only 1"}

    if not kwargs.get("content", False) and kwargs.get("url", False):
        try:
            r = requests.get(kwargs["url"], params=kwargs.get("params", {}), headers=kwargs.get("headers", {}), verify=False)
        except requests.exceptions.RequestException as e:
            logging.error(e)
            return "error", {"error": "Provided hash not found on {}".format(kwargs["service"])}

        if r.status_code == 200 and r.content != b"Hash Not Present" and b"The request requires higher privileges than provided by the access token" not in r.content:
            kwargs["content"] = r.content
        elif r.status_code == 403:
            return "error", {"error": "API key provided is not a valid {0} key or is not authorized for {0} downloads".format(kwargs["service"])}

        elif r.status_code == 404:
            return "error", {"error": "Server returns 404 from {}".format(kwargs["service"])}
        else:
            return "error", {"error": "Was impossible to download from {0}".format(kwargs["service"])}


    if not kwargs["content"]:
        return "error", {"error": "Error downloading file from {}".format(kwargs["service"])}
    try:
        if kwargs.get("fhash", False):
            retrieved_hash = hashes[len(kwargs["fhash"])](kwargs["content"]).hexdigest()
            if retrieved_hash != kwargs["fhash"].lower():
                return "error", {"error": "Hashes mismatch, original hash: {} - retrieved hash: {}".format(kwargs["fhash"], retrieved_hash)}
        if not os.path.exists(kwargs.get("path")):
            f = open(kwargs["path"], 'wb')
            f.write(kwargs["content"])
            f. close()
    except Exception as e:
        print(e)
        return "error", {"error": "Error writing {} storing/download file to temporary path".format(kwargs["service"])}

    onesuccess = True
    magic_type = get_magic_type(kwargs["path"])
    if disable_x64 is True and kwargs["path"] and magic_type and ("x86-64" in magic_type or "PE32+" in magic_type):
        if len(kwargs["request"].FILES) == 1:
            return "error", {"error": "Sorry no x64 support yet"}

    kwargs["options"], timeout, enforce_timeout = recon(kwargs["path"], kwargs["options"], timeout, enforce_timeout)
    if not kwargs.get("task_machines", []):
        kwargs["task_machines"] = [None]

    platform = get_platform(magic_type)
    if machine.lower() == "all":
        kwargs["task_machines"] = [vm.name for vm in db.list_machines(platform=platform)]
    elif machine:
        machine_details = db.view_machine(machine)
        if hasattr(machine_details, "platform") and not machine_details.platform == platform:
            return "error", {"error": "Wrong platform, {} VM selected for {} sample".format(machine_details.platform, platform)}
        else:
            kwargs["task_machines"] = [machine]
    else:
        kwargs["task_machines"] = ["first"]

    for machine in kwargs.get("task_machines", []):
        if machine == "first":
            machine = None

        # Keep this as demux_sample_and_add_to_db in DB
        task_ids_new, extra_details = db.demux_sample_and_add_to_db(
            file_path=kwargs["path"],
            package=package,
            timeout=timeout,
            options=kwargs["options"],
            priority=priority,
            machine=machine,
            custom=custom,
            platform=platform,
            tags=tags,
            memory=memory,
            enforce_timeout=enforce_timeout,
            clock=clock,
            static=static,
            shrike_url=shrike_url,
            shrike_msg=shrike_msg,
            shrike_sid=shrike_sid,
            shrike_refer=shrike_refer,
            tlp=tlp,
            tags_tasks=tags_tasks,
            route=route,
            cape=cape,
            user_id=kwargs.get("user_id"),
            #parent_id=kwargs.get("parent_id", None),
            #sample_parent_id=kwargs.get("sample_parent_id", None)
        )
        if isinstance(kwargs.get("task_ids", False), list):
            kwargs["task_ids"].extend(task_ids_new)
        else:
            kwargs["task_ids"] = list()
            kwargs["task_ids"].extend(task_ids_new)

    if not onesuccess:
        return "error", {"error": "Provided hash not found on {}".format(kwargs["service"])}

    return "ok", kwargs["task_ids"]


def _download_file(route, url, options):
    socks5s = _load_socks5_operational()
    proxies = dict()
    response = False
    headers = {"User-Agent": choice(user_agents)}

    if route:
        if route == "tor":
            proxies = {
                "http": "socks5://127.0.0.1:9050",
                "https": "socks5://127.0.0.1:9050",
            }

        elif route in socks5s:
            proxies = {
                "http": "socks5://{}:{}".format(socks5s[route]["host"], socks5s[route]["port"]),
                "https": "socks5://{}:{}".format(socks5s[route]["host"], socks5s[route]["port"]),
            }

    # load headers
    for option in options.split(","):
        if option.startswith("dne_"):
            key, value = option.split("=")
            headers[key.replace("dne_", "")] = value

    try:
        response = requests.get(url, headers=headers, proxies=proxies)
        if response and response.status_code == 200:
            return response.content
    except Exception as e:
        log.error(e)
        print(e)

    return response


def validate_task(tid):
    task = db.view_task(tid)
    if not task:
        return {"error": True, "error_value": "Task does not exist"}

    if task.status != TASK_REPORTED:
        return {"error": True, "error_value": "Task is still being analyzed"}

    return {"error": False}


perform_search_filters = {
    "info": 1,
    "info.id": 1,
    "virustotal_summary": 1,
    "detections": 1,
    "malfamily_tag": 1,
    "info.custom": 1,
    "info.shrike_msg": 1,
    "malscore": 1,
    "network.pcap_sha256": 1,
    "mlist_cnt": 1,
    "f_mlist_cnt": 1,
    "info.package": 1,
    "target.file.clamav": 1,
    "target.file.sha256": 1,
    "suri_tls_cnt": 1,
    "suri_alert_cnt": 1,
    "suri_http_cnt": 1,
    "suri_file_cnt": 1,
    "trid": 1,
    "CAPE_childrens": 1,
    "_id": 0,
}

search_term_map = {
    "id": "info.id",
    "ids": "info.id",
    "tags_tasks": "info.id",
    "name": "target.file.name",
    "type": "target.file.type",
    "string": "strings",
    "ssdeep": "target.file.ssdeep",
    "trid": "trid",
    "crc32": "target.file.crc32",
    "file": "behavior.summary.files",
    "command": "behavior.summary.executed_commands",
    "resolvedapi": "behavior.summary.resolved_apis",
    "key": "behavior.summary.keys",
    "mutex": "behavior.summary.mutexes",
    "domain": "network.domains.domain",
    "ip": "network.hosts.ip",
    "signature": "signatures.description",
    "signame": "signatures.name",
    "detections": "detections",
    "url": "target.url",
    "iconhash": "static.pe.icon_hash",
    "iconfuzzy": "static.pe.icon_fuzzy",
    "imphash": "static.pe.imphash",
    "surihttp": "suricata.http",
    "suritls": "suricata.tls",
    "surisid": "suricata.alerts.sid",
    "surialert": "suricata.alerts.signature",
    "surimsg": "suricata.alerts.signature",
    "suriurl": "suricata.http.uri",
    "suriua": "suricata.http.ua",
    "surireferrer": "suricata.http.referrer",
    "suritlssubject": "suricata.tls.subject",
    "suritlsissuerdn": "suricata.tls.issuer",
    "suritlsfingerprint": "suricata.tls.fingerprint",
    "clamav": "target.file.clamav",
    "yaraname": "target.file.yara.name",
    "capeyara": "target.file.cape_yara.name",
    "procmemyara": "procmemory.yara.name",
    "virustotal": "virustotal.results.sig",
    "comment": "info.comments.Data",
    "shrikemsg": "info.shrike_msg",
    "shrikeurl": "info.shrike_url",
    "shrikerefer": "info.shrike_refer",
    "shrikesid": "info.shrike_sid",
    "custom": "info.custom",
    "md5": "target.file.md5",
    "sha1": "target.file.sha1",
    "sha256": "target.file.sha256",
    "sha512": "target.file.sha512",
    "tlp": "info.tlp",
    "ja3_hash": "suricata.tls.ja3.hash",
    "ja3_string": "suricata.tls.ja3.string",
}


def perform_ttps_search(value):
    if repconf.mongodb.enabled and len(value) == 5 and value.upper().startswith("T") and value[1:].isdigit():
        return results_db.analysis.find({"ttps." + value.uppwer(): {"$exist": 1}}, {"info.id": 1, "_id": 0}).sort([["_id", -1]])


def perform_malscore_search(value):
    if repconf.mongodb.enabled:
        return results_db.analysis.find({"malscore": {"$gte": float(value)}}, perform_search_filters).sort([["_id", -1]])


def perform_search(term, value):
    if repconf.mongodb.enabled and repconf.elasticsearchdb.enabled and essearch and not term:
        numhits = es.search(index=fullidx, doc_type="analysis", q="%s" % value, size=0)["hits"]["total"]
        return es.search(index=fullidx, doc_type="analysis", q="%s" % value, sort="task_id:desc", size=numhits)["hits"]["hits"]

    query_val = False
    if term in ("md5", "sha1", "sha256", "sha512"):
        query_val = value
    elif term in ("surisid", "id"):
        try:
            query_val = int(value)
        except:
            pass
    elif term in ("ids", "options", "tags_tasks"):
        try:
            ids = []
            if term == "ids":
                ids = value
            elif term == "tags_tasks":
                ids = [int(v.id) for v in db.list_tasks(tags_tasks_like=value)]
            else:
                ids = [int(v.id) for v in db.list_tasks(options_like=value)]
            if ids:
                if len(ids) > 1:
                    query_val = {"$in": ids}
                else:
                    term = "id"
                    if isinstance(value, list):
                        value = value[0]
                    query_val = int(value)
        except Exception as e:
            print(term, value, e)
    else:
        query_val = {"$regex": value, "$options": "-i"}

    if term not in search_term_map:
        return None

    if repconf.mongodb.enabled and query_val:
        return results_db.analysis.find({search_term_map[term]: query_val}, perform_search_filters).sort([["_id", -1]])
    if es_as_db:
        return es.search(index=fullidx, doc_type="analysis", q=search_term_map[term] + ": %s" % value)["hits"]["hits"]


def force_int(value):
    try:
        value = int(value)
    except:
        value = 0
    finally:
        return value


def parse_request_arguments(request):
    static = request.POST.get("static", "")
    referrer = validate_referrer(request.POST.get("referrer", None))
    package = request.POST.get("package", "")
    timeout = force_int(request.POST.get("timeout"))
    priority = force_int(request.POST.get("priority"))
    options = request.POST.get("options", "")
    machine = request.POST.get("machine", "")
    platform = request.POST.get("platform", "")
    tags_tasks = request.POST.get("tags_tasks", None)
    tags = request.POST.get("tags", None)
    custom = request.POST.get("custom", "")
    memory = bool(request.POST.get("memory", False))
    clock = request.POST.get("clock", datetime.now().strftime("%m-%d-%Y %H:%M:%S"))
    if not clock:
        clock = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    if "1970" in clock:
        clock = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    enforce_timeout = bool(request.POST.get("enforce_timeout", False))
    shrike_url = request.POST.get("shrike_url", None)
    shrike_msg = request.POST.get("shrike_msg", None)
    shrike_sid = request.POST.get("shrike_sid", None)
    shrike_refer = request.POST.get("shrike_refer", None)
    unique = bool(request.POST.get("unique", False))
    tlp = request.POST.get("tlp", None)
    lin_options = request.POST.get("lin_options", "")
    route = request.POST.get("route", routing_conf.routing.route)
    cape = request.POST.get("cape", "")
    # Linux options
    if lin_options:
        options = lin_options

    return static, package, timeout, priority, options, machine, platform, tags, custom, memory, clock, enforce_timeout, \
        shrike_url, shrike_msg, shrike_sid, shrike_refer, unique, referrer, tlp, tags_tasks, route, cape

def get_hash_list(hashes):
    hashlist = []
    if "," in hashes:
        hashlist = filter(None, hashes.replace(" ", "").strip().split(","))
    else:
        hashlist = hashes.split()

    return hashlist

def download_from_vt(vtdl, details, opt_filename, settings):
    for h in get_hash_list(vtdl):
        folder = os.path.join(settings.VTDL_PATH, "cape-vt")
        if not os.path.exists(folder):
            os.makedirs(folder)
        base_dir = tempfile.mkdtemp(prefix='vtdl', dir=folder)
        if opt_filename:
            filename = base_dir + "/" + opt_filename
        else:
            filename = base_dir + "/" + sanitize_filename(h)
        paths = db.sample_path_by_hash(h)

        # clean old content
        if "content" in details:
            del details["content"]

        if paths:
            details["content"] = get_file_content(paths)
        if settings.VTDL_KEY:
            details["headers"] = {'x-apikey': settings.VTDL_KEY}
        elif details.get("apikey", False):
            details["headers"] = {'x-apikey': details["apikey"]}
        else:
            details["errors"].append({"error": "Apikey not configured, neither passed as opt_apikey"})
            return details
        details["url"] = "https://www.virustotal.com/api/v3/files/{id}/download".format(id = h.lower())
        details["fhash"] = h
        details["path"] = filename
        details["service"] = "VirusTotal"
        if not details.get("content", False):
            status, task_ids_tmp = download_file(**details)
        else:
            details["service"] = "Local"
            status, task_ids_tmp = download_file(**details)
        if status == "error":
            details["errors"].append({h: task_ids_tmp})
        else:
            details["task_ids"] = task_ids_tmp

    return details
