from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import json
import time
import logging
import hashlib
import tempfile
from random import choice
from datetime import datetime, timedelta
from collections import OrderedDict

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))
sys.path.append(CUCKOO_ROOT)

import magic
import requests
from django.http import HttpResponse
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import HAVE_PEFILE, pefile, IsPEImage
from lib.cuckoo.core.rooter import vpns, _load_socks5_operational
from lib.cuckoo.core.database import Database, Task, Sample, TASK_REPORTED, ALL_DB_STATUSES
from lib.cuckoo.common.utils import get_ip_address, bytes2str, validate_referrer, sanitize_filename, get_options

cfg = Config("cuckoo")
web_cfg = Config("web")
repconf = Config("reporting")
routing_conf = Config("routing")
machinery = Config(cfg.cuckoo.machinery)
disable_x64 = cfg.cuckoo.get("disable_x64", False)

apiconf = Config("api")

linux_enabled = web_cfg.linux.get("enabled", False)
rateblock = web_cfg.ratelimit.get("enabled", False)
rps = web_cfg.ratelimit.get("rps", "1/rps")
rpm = web_cfg.ratelimit.get("rpm", "5/rpm")

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


if repconf.mongodb.enabled:
    import pymongo

    results_db = pymongo.MongoClient(
        repconf.mongodb.host,
        port=repconf.mongodb.port,
        username=repconf.mongodb.get("username", None),
        password=repconf.mongodb.get("password", None),
        authSource=repconf.mongodb.get("authsource", "cuckoo"),
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
    es = Elasticsearch(
        hosts=[
            {
                "host": repconf.elasticsearchdb.host,
                "port": repconf.elasticsearchdb.port,
            }
        ],
        timeout=60,
    )

VALID_LINUX_TYPES = ["Bourne-Again", "POSIX shell script", "ELF", "Python"]

hash_len = {
    32: "md5",
    40: "sha1",
    64: "sha256",
    128: "sha512",
}

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

# https://django-ratelimit.readthedocs.io/en/stable/rates.html#callables
def my_rate_seconds(group, request):
    # RateLimits not enabled
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    print(request.user.username, ip)
    """

    if rateblock is False or request.user.is_authenticated:
        return "99999999999999/s"
    else:
        return rps


def my_rate_minutes(group, request):
    # RateLimits not enabled
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    print(request.user.username, ip)
    """
    if rateblock is False or request.user.is_authenticated:
        return "99999999999999/m"
    else:
        return rpm


def load_vms_exits():
    all_exits = dict()
    if HAVE_DIST and repconf.distributed.enabled:
        try:
            db = dist_session()
            for node in db.query(Node).all():
                if hasattr(node, "exitnodes"):
                    for exit in node.exitnodes:
                        all_exits.setdefault(exit.name, list())
                        all_exits[exit.name].append(node.name)
            db.close()
        except Exception as e:
            print(e)

    return all_exits


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
        all_tags += [tag.name for tag in machine.tags if tag not in all_tags]

    return list(set(all_tags))


all_nodes_exits = load_vms_exits()
all_nodes_exits_list = list(all_nodes_exits.keys())

all_vms_tags = load_vms_tags()
all_vms_tags_str = ",".join(all_vms_tags)


def top_detections(date_since: datetime = False, results_limit: int = 20) -> dict:

    t = int(time.time())

    # caches results for 10 minutes
    if hasattr(top_detections, "cache"):
        ct, data = top_detections.cache
        if t - ct < 600:
            return data

    """function that gets detection: count
    based on: https://gist.github.com/clarkenheim/fa0f9e5400412b6a0f9d
    """
    data = False

    aggregation_command = [
        {"$match": {"detections": {"$exists": True}}},
        {"$group": {"_id": "$detections", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}},
        {"$addFields": {"family": "$_id"}},
        {"$project": {"_id": 0}},
        {"$limit": results_limit},
    ]

    if date_since:
        aggregation_command[0]["$match"].setdefault("info.started", {"$gte": date_since.isoformat()})

    data = results_db.analysis.aggregate(aggregation_command)
    if data:
        data = list(data)

    # save to cache
    top_detections.cache = (t, data)

    return data


# ToDo extend this to directly extract per day
def get_stats_per_category(date_since, date_to, category):
    aggregation_command = [
        {
            "$match": {
                "info.started": {
                    "$gte": date_since.isoformat(),
                    "$lt": date_to.isoformat(),
                },
                "statistics.{}".format(category): {"$exists": True},
            }
        },
        {"$unwind": "$statistics.{}".format(category)},
        {
            "$group": {
                "_id": "$statistics.{}.name".format(category),
                "total_time": {"$sum": "$statistics.{}.time".format(category)},
                "total_run": {"$sum": 1},
            }
        },
        {"$addFields": {"name": "$_id"}},
        {"$project": {"_id": 0}},
        {"day": {"$dayOfMonth": "$info.started"}},
        {"$sort": {"total_time": -1}},
    ]
    data = results_db.analysis.aggregate(aggregation_command)
    if data:
        return data


def statistics(s_days: int) -> dict:
    date_since = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=s_days)
    date_till = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

    details = {
        "signatures": {},
        "processing": {},
        "reporting": {},
        "top_samples": {},
        "detections": {},
    }

    tmp_custom = dict()
    tmp_data = dict()
    data = results_db.analysis.find(
        {"statistics": {"$exists": True}, "info.started": {"$gte": date_since.isoformat()}}, {"statistics": 1, "_id": 0}
    )
    for analysis in data or []:
        for type_entry in analysis.get("statistics", []) or []:
            if type_entry not in tmp_data:
                tmp_data.setdefault(type_entry, dict())
            for entry in analysis["statistics"][type_entry]:
                if entry["name"] in analysis.get("custom_statistics", {}):
                    if entry["name"] not in tmp_custom:
                        tmp_custom.setdefault(entry["name"], dict())
                        if isinstance(analysis["custom_statistics"][entry["name"]], float):
                            tmp_custom[entry["name"]]["time"] = analysis["custom_statistics"][entry["name"]]
                            tmp_custom[entry["name"]]["successful"] = 0
                        else:
                            tmp_custom[entry["name"]]["time"] = analysis["custom_statistics"][entry["name"]]["time"]
                            tmp_custom[entry["name"]]["successful"] = analysis["custom_statistics"][entry["name"]].get(
                                "extracted", 0
                            )
                        tmp_custom[entry["name"]]["runs"] = 1

                    else:
                        tmp_custom.setdefault(entry["name"], dict())
                        if isinstance(analysis["custom_statistics"][entry["name"]], float):
                            tmp_custom[entry["name"]]["time"] = analysis["custom_statistics"][entry["name"]]
                            tmp_custom[entry["name"]]["successful"] += 0
                        else:
                            tmp_custom[entry["name"]]["time"] += analysis["custom_statistics"][entry["name"]]["time"]
                            tmp_custom[entry["name"]]["successful"] += analysis["custom_statistics"][entry["name"]].get(
                                "extracted", 0
                            )
                        tmp_custom[entry["name"]]["runs"] += 1
                if entry["name"] not in tmp_data[type_entry]:
                    tmp_data[type_entry].setdefault(entry["name"], dict())
                    tmp_data[type_entry][entry["name"]]["time"] = entry["time"]
                    tmp_data[type_entry][entry["name"]]["runs"] = 1
                else:
                    tmp_data[type_entry][entry["name"]]["time"] += entry["time"]
                    tmp_data[type_entry][entry["name"]]["runs"] += 1

    if not data:
        return details

    for module_name in ["signatures", "processing", "reporting"]:
        if module_name not in tmp_data:
            continue
        # module_data = get_stats_per_category(module_name)
        s = sorted(tmp_data[module_name].items(), key=lambda x: x[1].get("time"), reverse=True)[:20]

        for entry in s:
            entry = entry[0]
            times_in_mins = tmp_data[module_name][entry]["time"] / 60
            if not times_in_mins:
                continue
            details[module_name].setdefault(entry, dict())
            details[module_name][entry]["total"] = float("{:.2f}".format(round(times_in_mins, 2)))
            details[module_name][entry]["runs"] = tmp_data[module_name][entry]["runs"]
            details[module_name][entry]["average"] = float(
                "{:.2f}".format(round(times_in_mins / tmp_data[module_name][entry]["runs"], 2))
            )
        details[module_name] = OrderedDict(sorted(details[module_name].items(), key=lambda x: x[1]["total"], reverse=True))

    # custom average
    for entry in tmp_custom:
        times_in_mins = tmp_custom[entry]["time"] / 60
        if not times_in_mins:
            continue
        tmp_custom[entry]["total"] = float("{:.2f}".format(round(times_in_mins, 2)))
        tmp_custom[entry]["average"] = float("{:.2f}".format(round(times_in_mins / tmp_custom[entry]["runs"], 2)))

    details["custom_signatures"] = OrderedDict(sorted(tmp_custom.items(), key=lambda x: x[1].get("total", "average"), reverse=True))

    top_samples = dict()
    session = db.Session()
    added_tasks = (
        session.query(Task).join(Sample, Task.sample_id == Sample.id).filter(Task.added_on.between(date_since, date_till)).all()
    )
    tasks = (
        session.query(Task).join(Sample, Task.sample_id == Sample.id).filter(Task.completed_on.between(date_since, date_till)).all()
    )
    details["total"] = len(tasks)
    details["average"] = "{:.2f}".format(round(details["total"] / s_days, 2))
    details["tasks"] = dict()
    for task in tasks or []:
        day = task.completed_on.strftime("%Y-%m-%d")
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
        # details["tasks"][day]["added"] += 1
        if task.status in ("failed_analysis", "failed_reporting", "failed_processing"):
            details["tasks"][day]["failed"] += 1
        elif task.status == "reported":
            details["tasks"][day]["reported"] += 1

    for added_task in added_tasks or []:
        day = added_task.added_on.strftime("%Y-%m-%d")
        if day not in details["tasks"]:
            continue
        details["tasks"][day]["added"] += 1

    details["tasks"] = OrderedDict(
        sorted(details["tasks"].items(), key=lambda x: datetime.strptime(x[0], "%Y-%m-%d"), reverse=True)
    )

    if HAVE_DIST and repconf.distributed.enabled:
        details["distributed_tasks"] = dict()
        dist_db = dist_session()
        dist_tasks = dist_db.query(DTask).filter(DTask.clock.between(date_since, date_till)).all()
        id2name = dict()
        # load node names
        for node in dist_db.query(Node).all() or []:
            id2name.setdefault(node.id, node.name)

        for task in dist_tasks or []:
            day = task.clock.strftime("%Y-%m-%d")
            if day not in details["distributed_tasks"]:
                details["distributed_tasks"].setdefault(day, {})
            if task.node_id in id2name and id2name[task.node_id] not in details["distributed_tasks"][day]:
                details["distributed_tasks"][day].setdefault(id2name[task.node_id], 0)
            details["distributed_tasks"][day][id2name[task.node_id]] += 1
        dist_db.close()

        details["distributed_tasks"] = OrderedDict(sorted(details["distributed_tasks"].items(), key=lambda x: x[0], reverse=True))

    # Get top15 of samples per day and seen more than once
    for day in top_samples:
        if day not in details["top_samples"]:
            details["top_samples"].setdefault(day, {})
        for sha256 in OrderedDict(sorted(top_samples[day].items(), key=lambda x: x[1], reverse=True)[:15]):
            if top_samples[day][sha256] > 1:
                details["top_samples"][day][sha256] = top_samples[day][sha256]

        details["top_samples"][day] = OrderedDict(sorted(details["top_samples"][day].items(), key=lambda x: x[1], reverse=True))
    details["top_samples"] = OrderedDict(
        sorted(details["top_samples"].items(), key=lambda x: datetime.strptime(x[0], "%Y-%m-%d"), reverse=True)
    )

    details["detections"] = top_detections(date_since=date_since, results_limit=20)

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
    """Example of kwargs
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

    (
        static,
        package,
        timeout,
        priority,
        _,
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
    ) = parse_request_arguments(kwargs["request"])
    onesuccess = False

    username = False
    """
    put here your custom username assignation from your custom auth, Ex:
    request_url = kwargs["request"].build_absolute_uri()
    if "yourdomain.com/submit/" in request_url:
        username = kwargs["request"].COOKIES.get("X-user")
    """

    # in case if user didn't specify routing, and we have enabled random route
    if not route:
        socks5s = _load_socks5_operational()

        socks5s_random = ""
        vpn_random = ""

        if routing_conf.socks5.random_socks5 and socks5s:
            socks5s_random = choice(socks5s.values()).get("name", False)

        if routing_conf.vpn.random_vpn:
            vpn_random = choice(list(vpns.values())).get("name", False)

        if vpn_random and socks5s_random:
            route = choice((vpn_random, socks5s_random))
        elif vpn_random:
            route = vpn_random
        elif socks5s_random:
            route = socks5s_random

    if package:
        if package == "Emotet":
            return "error", {"error": "Hey guy update your script, this package doesn't exist anymore"}

        if package.endswith("_x64"):
            if tags:
                if "x64" not in tags:
                    tags += ",x64"
            else:
                tags = "x64"
    if tags:
        if not all([tag.strip() in all_vms_tags for tag in tags.split(",")]):
            return "error", {
                "error": f"Check Tags help, you have introduced incorrect tag(s). Your tags: {tags} - Supported tags: {all_vms_tags_str}"
            }
        elif all([tag in tags for tag in ("x64", "x86")]):
            return "error", {"error": "Check Tags help, you have introduced x86 and x64 tags for the same task, choose only 1"}

    if not kwargs.get("content", False) and kwargs.get("url", False):
        try:
            r = requests.get(kwargs["url"], params=kwargs.get("params", {}), headers=kwargs.get("headers", {}), verify=False)
        except requests.exceptions.RequestException as e:
            logging.error(e)
            return "error", {"error": "Provided hash not found on {}".format(kwargs["service"])}

        if (
            r.status_code == 200
            and r.content != b"Hash Not Present"
            and b"The request requires higher privileges than provided by the access token" not in r.content
        ):
            kwargs["content"] = r.content
        elif r.status_code == 403:
            return "error", {
                "error": "API key provided is not a valid {0} key or is not authorized for {0} downloads".format(kwargs["service"])
            }

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
                return "error", {
                    "error": "Hashes mismatch, original hash: {} - retrieved hash: {}".format(kwargs["fhash"], retrieved_hash)
                }
        if not os.path.exists(kwargs.get("path")):
            f = open(kwargs["path"], "wb")
            f.write(kwargs["content"])
            f.close()
    except Exception as e:
        print(e)
        return "error", {"error": "Error writing {} storing/download file to temporary path".format(kwargs["service"])}

    # Distribute task based on route support by worker
    if route and route not in ("none", "None") and all_nodes_exits_list:
        parsed_options = get_options(kwargs["options"])
        node = parsed_options.get("node")

        if node and route not in all_nodes_exits.get(node):
            return "error", {"error": f"Specified worker {node} doesn't support this route: {route}"}
        elif route not in all_nodes_exits_list:
            return "error", {"error": "Specified route doesn't exist on any worker"}

        if not node:
            # get nodes that supports this exit
            tmp_workers = list()
            for node, exitnodes in all_nodes_exits.items():
                if route in exitnodes:
                    tmp_workers.append(node)
            if tmp_workers:
                if kwargs["options"]:
                    kwargs["options"] += ",node=" + choice(tmp_workers)
                else:
                    kwargs["options"] = "node=" + choice(tmp_workers)

        # Remove workers prefixes
        if route.startswith(("socks5:", "vpn:")):
            route = route.replace("socks5:", "", 1).replace("vpn:", "", 1)

    onesuccess = True
    magic_type = get_magic_type(kwargs["path"])
    if disable_x64 is True and kwargs["path"] and magic_type and ("x86-64" in magic_type or "PE32+" in magic_type):
        if len(kwargs["request"].FILES) == 1:
            return "error", {"error": "Sorry no x64 support yet"}

    kwargs["options"], timeout, enforce_timeout = recon(kwargs["path"], kwargs["options"], timeout, enforce_timeout)
    if not kwargs.get("task_machines", []):
        kwargs["task_machines"] = [None]

    platform = get_platform(magic_type)
    if platform == "linux" and not linux_enabled and "Python" not in magic_type:
        return "error", {"error": "Linux binaries analysis isn't enabled"}

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

    # Try to extract before submit to VM
    if not static and "dist_extract" in kwargs["options"]:
        static = True

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
            username=username,
            source_url=kwargs.get("source_url", False)
            # parent_id=kwargs.get("parent_id", None),
            # sample_parent_id=kwargs.get("sample_parent_id", None)
        )
        if isinstance(kwargs.get("task_ids", False), list):
            kwargs["task_ids"].extend(task_ids_new)
        else:
            kwargs["task_ids"] = list()
            kwargs["task_ids"].extend(task_ids_new)

    if not onesuccess:
        return "error", {"error": "Provided hash not found on {}".format(kwargs["service"])}

    return "ok", kwargs["task_ids"]


def url_defang(url):
    url_defang = url.replace("[.]", ".").replace("[.", ".").repalce(".]", ".").replace("hxxp", "http").replace("hxtp", "http")
    if not url_defang.startswith("http"):
        url_defang = "http://" + url_defang
    return url_defang


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
        url = url_defang(url)
        response = requests.get(url, headers=headers, proxies=proxies)
        if response and response.status_code == 200:
            return response.content
    except Exception as e:
        log.error(e)
        print(e)

    return response


def validate_task(tid, status=TASK_REPORTED):
    task = db.view_task(tid)
    if not task:
        return {"error": True, "error_value": "Task does not exist"}

    if status and status not in ALL_DB_STATUSES:
        return {"error": True, "error_value": "Specified wrong task status"}
    elif status == task.status:
        return {"error": False}
    elif task.status != TASK_REPORTED:
        return {"error": True, "error_value": "Task is still being analyzed"}

    return {"error": False}


perform_search_filters = {
    "info": 1,
    "virustotal_summary": 1,
    "detections": 1,
    "malfamily_tag": 1,
    "malscore": 1,
    "network.pcap_sha256": 1,
    "mlist_cnt": 1,
    "f_mlist_cnt": 1,
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
    "ssdeep": ("target.file.ssdeep", "dropped.ssdeep", "procdump.ssdeep", "CAPE.payloads.ssdeep"),
    "trid": "trid",
    "crc32": ("target.file.crc32", "dropped.crc32", "procdump.crc32", "CAPE.payloads.crc32"),
    "file": "behavior.summary.files",
    "command": "behavior.summary.executed_commands",
    "configs": "CAPE.configs",
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
    # probably needs extend
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
    "md5": ("target.file.md5", "dropped.md5", "procdump.md5", "CAPE.payloads.md5"),
    "sha1": ("target.file.sha1", "dropped.sha1", "procdump.sha1", "CAPE.payloads.sha1"),
    "sha3": ("target.file.sha3_384", "dropped.sha3_384", "procdump.sha3_384", "CAPE.payloads.sha3_384"),
    "sha256": ("target.file.sha256", "dropped.sha256", "procdump.sha256", "CAPE.payloads.sha256"),
    "sha512": ("target.file.sha512", "dropped.sha512", "procdump.sha512", "CAPE.payloads.sha512"),
    "tlp": "info.tlp",
    "ja3_hash": "suricata.tls.ja3.hash",
    "ja3_string": "suricata.tls.ja3.string",
    "payloads": "CAPE.payloads.",
    "dhash": "static.pe.icon_dhash",
    "dport": ("network.tcp.dport", "network.udp.dport", "network.smtp_ex.dport"),
    "sport": ("network.tcp.dport", "network.udp.dport", "network.smtp_ex.dport"),
    "port": (
        "network.tcp.dport",
        "network.udp.dport",
        "network.smtp_ex.dport",
        "network.tcp.dport",
        "network.udp.dport",
        "network.smtp_ex.dport",
    ),
}

# search terms that will be forwarded to mongodb in a lowered normalized form
normalized_lower_terms = (
    "target_sha256",
    "md5",
    "sha1",
    "sha3",
    "sha256",
    "sha512",
    "ip",
    "domain",
    "ja3_hash",
    "dhash",
    "iconhash",
    "imphash",
)

normalized_int_terms = (
    "sport",
    "dport",
    "port",
)

# ToDo verify if still working
def perform_ttps_search(value):
    if repconf.mongodb.enabled and len(value) == 5 and value.upper().startswith("T") and value[1:].isdigit():
        return results_db.analysis.find({"ttps." + value.uppwer(): {"$exist": 1}}, {"info.id": 1, "_id": 0}).sort([["_id", -1]])


def perform_malscore_search(value):
    if repconf.mongodb.enabled:
        return results_db.analysis.find({"malscore": {"$gte": float(value)}}, perform_search_filters).sort([["_id", -1]])


def perform_search(term, value, search_limit=False):
    if repconf.mongodb.enabled and repconf.elasticsearchdb.enabled and essearch and not term:
        numhits = es.search(index=fullidx, doc_type="analysis", q="%s" % value, size=0)["hits"]["total"]
        return es.search(index=fullidx, doc_type="analysis", q="%s" % value, sort="task_id:desc", size=numhits)["hits"]["hits"]

    query_val = False
    if term in normalized_lower_terms:
        query_val = value.lower()
    elif term in normalized_int_terms:
        query_val = int(value)
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

    if not search_limit:
        search_limit = web_cfg.general.get("search_limit", 50)

    if term == "payloads" and len(value) in (32, 40, 64, 128):
        search_term_map[term] = "CAPE.payloads." + hash_len.get(len(value))

    elif term == "configs":
        # check if family name is string only maybe?
        search_term_map[term] = f"CAPE.configs.{value}"
        query_val = {"$exists": True}

    if repconf.mongodb.enabled and query_val:
        if type(search_term_map[term]) is str:
            mongo_search_query = {search_term_map[term]: query_val}
        else:
            mongo_search_query = {"$or": [{search_term: query_val} for search_term in search_term_map[term]]}
        return (
            results_db.analysis.find(mongo_search_query, perform_search_filters)
            .sort([["_id", -1]])
            .limit(web_cfg.general.get("search_limit", 50))
        )
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
    route = request.POST.get("route")
    cape = request.POST.get("cape", "")
    # Linux options
    if lin_options:
        options = lin_options

    return (
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
    )


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
        base_dir = tempfile.mkdtemp(prefix="vtdl", dir=folder)
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
            details["headers"] = {"x-apikey": settings.VTDL_KEY}
        elif details.get("apikey", False):
            details["headers"] = {"x-apikey": details["apikey"]}
        else:
            details["errors"].append({"error": "Apikey not configured, neither passed as opt_apikey"})
            return details
        details["url"] = "https://www.virustotal.com/api/v3/files/{id}/download".format(id=h.lower())
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
