import hashlib
import io
import json
import logging
import os
import sys
import tempfile
import time
from collections import OrderedDict
from contextlib import suppress
from datetime import datetime, timedelta
from pathlib import Path
from random import choice

import magic
import requests
from django.http import HttpResponse

HAVE_PYZIPPER = False
with suppress(ImportError):
    import pyzipper

    HAVE_PYZIPPER = True

from dev_utils.mongo_hooks import FILE_REF_KEY, FILES_COLL, NORMALIZED_FILE_FIELDS
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.parse_pe import HAVE_PEFILE, IsPEImage, pefile
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists, path_mkdir, path_write_file
from lib.cuckoo.common.utils import (
    bytes2str,
    generate_fake_name,
    get_ip_address,
    get_options,
    get_platform,
    get_user_filename,
    sanitize_filename,
    store_temp_file,
    validate_referrer,
    validate_ttp,
)
from lib.cuckoo.core.database import (
    ALL_DB_STATUSES,
    TASK_FAILED_ANALYSIS,
    TASK_FAILED_PROCESSING,
    TASK_FAILED_REPORTING,
    TASK_RECOVERED,
    TASK_REPORTED,
    Database,
    Sample,
    Task,
)
from lib.cuckoo.core.rooter import _load_socks5_operational, vpns

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))
sys.path.append(CUCKOO_ROOT)

cfg = Config("cuckoo")
web_cfg = Config("web")
repconf = Config("reporting")
dist_conf = Config("distributed")
routing_conf = Config("routing")
machinery = Config(cfg.cuckoo.machinery)
disable_x64 = cfg.cuckoo.get("disable_x64", False)

apiconf = Config("api")

linux_enabled = web_cfg.linux.get("enabled", False)
rateblock = web_cfg.ratelimit.get("enabled", False)
rps = web_cfg.ratelimit.get("rps", "1/rps")
rpm = web_cfg.ratelimit.get("rpm", "5/rpm")

db = Database()

try:
    import re2 as re
except ImportError:
    import re

DYNAMIC_PLATFORM_DETERMINATION = web_cfg.general.dynamic_platform_determination

HAVE_DIST = False
# Distributed CAPE
if dist_conf.distributed.enabled:
    try:
        # Tags
        from lib.cuckoo.common.dist_db import Machine, Node
        from lib.cuckoo.common.dist_db import Task as DTask
        from lib.cuckoo.common.dist_db import create_session

        HAVE_DIST = True
        dist_session = create_session(dist_conf.distributed.db)
    except Exception as e:
        print(e)


if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_aggregate, mongo_find, mongo_find_one

es_as_db = False
essearch = False
if repconf.elasticsearchdb.enabled:
    from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index

    essearch = repconf.elasticsearchdb.searchonly
    if not essearch:
        es_as_db = True

    es = elastic_handler

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
        ip = x_forwarded_for.split(',', 1)[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    print(request.user.username, ip)
    """

    if not rateblock or request.user.is_authenticated:
        return "99999999999999/s"
    return rps


def my_rate_minutes(group, request):
    # RateLimits not enabled
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')

    if x_forwarded_for:
        ip = x_forwarded_for.split(',', 1)[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    print(request.user.username, ip)
    """
    if not rateblock or request.user.is_authenticated:
        return "99999999999999/m"
    return rpm


def load_vms_exits():
    all_exits = {}
    if HAVE_DIST and dist_conf.distributed.enabled:
        try:
            db = dist_session()
            for node in db.query(Node).all():
                if hasattr(node, "exitnodes"):
                    for exit in node.exitnodes:
                        all_exits.setdefault(exit.name, []).append(node.name)
            db.close()
        except Exception as e:
            print(e)

    return all_exits


def load_vms_tags():
    all_tags = []
    if HAVE_DIST and dist_conf.distributed.enabled:
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


def top_asn(date_since: datetime = False, results_limit: int = 20) -> dict:
    if web_cfg.general.get("top_asn", False) is False:
        return False

    t = int(time.time())

    # caches results for 10 minutes
    if hasattr(top_asn, "cache"):
        ct, data = top_asn.cache
        if t - ct < 600:
            return data

    """function that gets detection: count
    Original: https://gist.github.com/clarkenheim/fa0f9e5400412b6a0f9d
    New: https://stackoverflow.com/a/21509359/1294762
    """

    aggregation_command = [
        {"$match": {"network.hosts.asn": {"$exists": True}}},
        {"$project": {"_id": 0, "network.hosts.asn": 1}},
        {"$unwind": "$network.hosts"},
        {"$group": {"_id": "$network.hosts.asn", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}},
        {"$addFields": {"asn": "$_id"}},
        {"$project": {"_id": 0}},
        {"$limit": results_limit},
    ]

    if date_since:
        aggregation_command[0]["$match"].setdefault("info.started", {"$gte": date_since.isoformat()})

    if repconf.mongodb.enabled:
        data = mongo_aggregate("analysis", aggregation_command)
    else:
        data = False

    if data:
        data = list(data)

    # save to cache
    top_asn.cache = (t, data)

    return data


def top_detections(date_since: datetime = False, results_limit: int = 20) -> dict:
    if web_cfg.general.get("top_detections", False) is False:
        return False

    t = int(time.time())

    # caches results for 10 minutes
    if hasattr(top_detections, "cache"):
        ct, data = top_detections.cache
        if t - ct < 600:
            return data

    """function that gets detection: count
    Original: https://gist.github.com/clarkenheim/fa0f9e5400412b6a0f9d
    New: https://stackoverflow.com/a/21509359/1294762
    """

    aggregation_command = [
        {"$match": {"detections.family": {"$exists": True}}},
        {"$project": {"_id": 0, "detections.family": 1}},
        {"$unwind": "$detections"},
        {"$group": {"_id": "$detections.family", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}},
        {"$addFields": {"family": "$_id"}},
        {"$project": {"_id": 0}},
        {"$limit": results_limit},
    ]

    if date_since:
        aggregation_command[0]["$match"].setdefault("info.started", {"$gte": date_since.isoformat()})

    if repconf.mongodb.enabled:
        data = mongo_aggregate("analysis", aggregation_command)
    elif repconf.elasticsearchdb.enabled:
        # ToDo update to new format
        q = {
            "query": {"bool": {"must": [{"exists": {"field": "detections.family"}}]}},
            "size": 0,
            "aggs": {"family": {"terms": {"field": "detections.family.keyword", "size": results_limit}}},
        }

        if date_since:
            q["query"]["bool"]["must"].append({"range": {"info.started": {"gte": date_since.isoformat()}}})

        res = es.search(index=get_analysis_index(), body=q)
        data = [{"total": r["doc_count"], "family": r["key"]} for r in res["aggregations"]["family"]["buckets"]]
    else:
        data = False

    if data:
        data = list(data)

    # save to cache
    top_detections.cache = (t, data)

    return data


# ToDo extend this to directly extract per day
def get_stats_per_category(category: str, date_since):
    aggregation_command = [
        {
            "$match": {
                "info.started": {
                    "$gte": date_since.isoformat(),
                },
                f"{category}": {"$exists": True},
            }
        },
        {"$unwind": f"${category}"},
        {
            "$group": {
                "_id": f"${category}.name",
                "total_time": {"$sum": {"$cond": [{"$eq": [f"${category}.time", 0]}, 0, {"$divide": [f"${category}.time", 60]}]}},
                "successful": {"$sum": {"$cond": [{"$eq": [f"${category}.extracted", 0]}, 0, 1]}},
                "runs": {"$sum": 1},
            }
        },
        {"$addFields": {"name": "$_id"}},
        {"$project": {"_id": 0}},
        {"$sort": {"total_time": -1}},
        {
            "$project": {
                "name": 1,
                "successful": 1,
                "runs": 1,
                # "average": 1,
                "total": {"$round": ["$total_time", 2]},
                "average": {"$round": [{"$divide": ["$total_time", "$runs"]}, 2]},
            }
        },
        {"$limit": 20},
    ]
    return mongo_aggregate("analysis", aggregation_command)


def statistics(s_days: int) -> dict:
    date_since = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=s_days)
    date_till = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)

    details = {
        "signatures": {},
        "processing": {},
        "reporting": {},
        "top_samples": {},
        "detections": {},
        "custom_statistics": {},
    }

    if repconf.mongodb.enabled:
        data = True

    elif repconf.elasticsearchdb.enabled:
        # ToDo need proper query upgrade as in mongo
        data = False
        """
        q = {
            "query": {
                "bool": {
                    "must": [{"exists": {"field": "statistics"}}, {"range": {"info.started": {"gte": date_since.isoformat()}}}]
                }
            }
        }
        data = [d["_source"] for d in es.search(index=get_analysis_index(), body=q, _source=["statistics"])["hits"]["hits"]]
        """
    else:
        data = None

    if not data:
        return details

    for module_name in ("statistics.signatures", "statistics.processing", "statistics.reporting", "custom_statistics"):
        module_data = get_stats_per_category(module_name, date_since)
        for entry in module_data or []:
            name = entry["name"]
            details[module_name.split(".")[-1]].setdefault(name, entry)

    top_samples = {}
    session = db.Session()
    added_tasks = (
        session.query(Task).join(Sample, Task.sample_id == Sample.id).filter(Task.added_on.between(date_since, date_till)).all()
    )
    tasks = (
        session.query(Task).join(Sample, Task.sample_id == Sample.id).filter(Task.completed_on.between(date_since, date_till)).all()
    )
    details["total"] = len(tasks)
    details["average"] = f"{round(details['total'] / s_days, 2):.2f}"
    details["tasks"] = {}
    for task in tasks or []:
        day = task.completed_on.strftime("%Y-%m-%d")
        if day not in details["tasks"]:
            details["tasks"].setdefault(day, {})
            details["tasks"][day].setdefault("failed", 0)
            details["tasks"][day].setdefault("reported", 0)
            details["tasks"][day].setdefault("added", 0)
        if day not in top_samples:
            top_samples.setdefault(day, {})
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

    if HAVE_DIST and dist_conf.distributed.enabled:
        details["distributed_tasks"] = {}
        dist_db = dist_session()
        dist_tasks = dist_db.query(DTask).filter(DTask.clock.between(date_since, date_till)).all()
        id2name = {}
        # load node names
        for node in dist_db.query(Node).all() or []:
            id2name.setdefault(node.id, node.name)

        for task in dist_tasks or []:
            day = task.clock.strftime("%Y-%m-%d")
            if day not in details["distributed_tasks"]:
                details["distributed_tasks"].setdefault(day, {})
            if id2name.get(task.node_id) not in details["distributed_tasks"][day]:
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

    details["detections"] = top_detections(date_since=date_since)
    details["asns"] = top_asn(date_since=date_since)

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
    return json.dumps(data, sort_keys=False, indent=4)


def get_file_content(paths):
    content = False
    if not isinstance(paths, list):
        paths = [paths]
    for path in paths:
        path = path.decode() if isinstance(path, bytes) else path
        p = Path(path)
        if p.exists():
            return p.read_bytes()
    return content


def fix_section_permission(path):
    if not HAVE_PEFILE:
        log.info("[-] Missed dependency pefile")
        return
    try:
        if not IsPEImage:
            return
        pe = pefile.PE(path, fast_load=True)
        if not pe:
            return
        for pe_section in pe.sections:
            if pe_section.Name.rstrip("\0") == ".rdata" and hex(pe_section.Characteristics)[:3] == "0x4":
                pe_section.Characteristics += pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]
                pe.write(filename=path)
        pe.close()
    except Exception as e:
        log.info(e)


# Submission hooks to manipulate arguments of tasks execution
def recon(
    filename,
    orig_options,
    timeout,
    enforce_timeout,
    package,
    tags,
    static,
    priority,
    machine,
    platform,
    custom,
    memory,
    clock,
    unique,
    referrer,
    tlp,
    tags_tasks,
    route,
    cape,
):
    if not isinstance(filename, str):
        filename = bytes2str(filename)

    lowered_filename = filename.lower()

    if web_cfg.general.yara_recon:
        hits = File(filename).get_yara("binaries")
        for hit in hits:
            cape_name = hit["meta"].get("cape_type", "")
            if not cape_name.endswith(("Crypter", "Packer", "Obfuscator", "Loader")):
                continue

            parsed_options = get_options(hit["meta"].get("cape_options", ""))
            if "tags" in parsed_options:
                tags = "," + parsed_options["tags"] if tags else parsed_options["tags"]
            # custom packages should be added to lib/cuckoo/core/database.py -> sandbox_packages list
            if "package" in parsed_options:
                package = parsed_options["package"]

    if "name" in lowered_filename:
        orig_options += ",timeout=400,enforce_timeout=1,procmemdump=1,procdump=1"
        timeout = 400
        enforce_timeout = True

    return (
        static,
        priority,
        machine,
        platform,
        custom,
        memory,
        clock,
        unique,
        referrer,
        tlp,
        tags_tasks,
        route,
        cape,
        orig_options,
        timeout,
        enforce_timeout,
        package,
        tags,
    )


def get_magic_type(data):
    try:
        if path_exists(data):
            return magic.from_file(data)
        else:
            return magic.from_buffer(data)
    except Exception as e:
        print(e, "get_magic_type")

    return False


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
            socks5s_random = choice(list(socks5s.keys()))

        if routing_conf.vpn.random_vpn and vpns:
            vpn_random = choice(list(vpns.keys()))

        if vpn_random and socks5s_random:
            route = choice((vpn_random, socks5s_random))
        elif vpn_random:
            route = vpn_random
        elif socks5s_random:
            route = socks5s_random

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
            return "error", {"error": f"Provided hash not found on {kwargs['service']}"}

        if (
            r.status_code == 200
            and r.content != b"Hash Not Present"
            and b"The request requires higher privileges than provided by the access token" not in r.content
        ):
            kwargs["content"] = r.content
        elif r.status_code == 403:
            return "error", {
                "error": f"API key provided is not a valid {kwargs['service']} key or is not authorized for {kwargs['service']} downloads"
            }

        elif r.status_code == 404:
            return "error", {"error": f"Server returns 404 from {kwargs['service']}"}
        else:
            return "error", {"error": f"Was impossible to download from {kwargs['service']}"}

    if not kwargs.get("content"):
        return "error", {"error": f"Error downloading file from {kwargs['service']}"}
    try:
        if kwargs.get("fhash", False):
            retrieved_hash = hashes[len(kwargs["fhash"])](kwargs["content"]).hexdigest()
            if retrieved_hash != kwargs["fhash"].lower():
                return "error", {"error": f"Hashes mismatch, original hash: {kwargs['fhash']} - retrieved hash: {retrieved_hash}"}

        path = kwargs.get("path") if isinstance(kwargs.get("path", ""), str) else kwargs.get("path").decode()
        if not path_exists(path):
            _ = path_write_file(path, kwargs["content"])
    except Exception as e:
        print(e, sys.exc_info())
        return "error", {"error": f"Error writing {kwargs['service']} storing/download file to temporary path"}

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
            tmp_workers = [node for node, exitnodes in all_nodes_exits.items() if route in exitnodes]
            if tmp_workers:
                if kwargs["options"]:
                    kwargs["options"] += f",node={choice(tmp_workers)}"
                else:
                    kwargs["options"] = f"node={choice(tmp_workers)}"

        # Remove workers prefixes
        if route.startswith(("socks5:", "vpn:")):
            route = route.replace("socks5:", "", 1).replace("vpn:", "", 1)

    onesuccess = True
    magic_type = get_magic_type(kwargs["path"])
    if disable_x64 and kwargs["path"] and magic_type and ("x86-64" in magic_type or "PE32+" in magic_type):
        if len(kwargs["request"].FILES) == 1:
            return "error", {"error": "Sorry no x64 support yet"}

    (
        static,
        priority,
        machine,
        platform,
        custom,
        memory,
        clock,
        unique,
        referrer,
        tlp,
        tags_tasks,
        route,
        cape,
        kwargs["options"],
        timeout,
        enforce_timeout,
        package,
        tags,
    ) = recon(
        kwargs["path"],
        kwargs["options"],
        timeout,
        enforce_timeout,
        package,
        tags,
        static,
        priority,
        machine,
        platform,
        custom,
        memory,
        clock,
        unique,
        referrer,
        tlp,
        tags_tasks,
        route,
        cape,
    )

    if not kwargs.get("task_machines", []):
        kwargs["task_machines"] = [None]

    if DYNAMIC_PLATFORM_DETERMINATION:
        platform = get_platform(magic_type)
    if platform == "linux" and not linux_enabled and "Python" not in magic_type:
        return "error", {"error": "Linux binaries analysis isn't enabled"}

    if machine.lower() == "all":
        kwargs["task_machines"] = [vm.label for vm in db.list_machines(platform=platform)]
    elif machine:
        machine_details = db.view_machine(machine)
        if platform and hasattr(machine_details, "platform") and not machine_details.platform == platform:
            return "error", {"error": f"Wrong platform, {machine_details.platform} VM selected for {platform} sample"}
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
            source_url=kwargs.get("source_url", False),
            # parent_id=kwargs.get("parent_id"),
        )

        try:
            save_script_to_storage(task_ids_new, kwargs)
        except Exception as e:
            log.error("Error saving scripts to storage: %s", e)
            return "error", {"error": "Error: Storing scripts to tempstorage"}

        if isinstance(kwargs.get("task_ids", False), list):
            kwargs["task_ids"].extend(task_ids_new)
        else:
            kwargs["task_ids"] = []
            kwargs["task_ids"].extend(task_ids_new)

    if not onesuccess:
        return "error", {"error": f"Provided hash not found on {kwargs['service']}"}

    return "ok", kwargs["task_ids"]


def save_script_to_storage(task_ids, kwargs):
    """
    Parameters: task_ids, kwargs
    Retrieve pre_script and during_script contents and save it to a temp storage
    """
    for task_id in task_ids:
        # Temp Folder for storing scripts
        script_temp_path = os.path.join("/tmp/cuckoo-tmp", str(task_id))
        if "pre_script_name" in kwargs and "pre_script_content" in kwargs:
            file_ext = os.path.splitext(kwargs["pre_script_name"])[-1]
            if file_ext not in (".py", ".ps1", ".exe"):
                raise ValueError(f"Unknown file_extention of {file_ext} to run for pre_script")

            path_mkdir(script_temp_path, exist_ok=True)
            log.info("Writing pre_script to temp folder %s", script_temp_path)
            _ = Path(os.path.join(script_temp_path, f"pre_script{file_ext}")).write_bytes(kwargs["pre_script_content"])
        if "during_script_name" in kwargs and "during_script_content" in kwargs:
            file_ext = os.path.splitext(kwargs["during_script_name"])[-1]
            if file_ext not in (".py", ".ps1", ".exe"):
                raise ValueError(f"Unknown file_extention of {file_ext} to run for during_script")

            path_mkdir(script_temp_path, exist_ok=True)
            log.info("Writing during_script to temp folder %s", script_temp_path)
            _ = Path(os.path.join(script_temp_path, f"during_script{file_ext}")).write_bytes(kwargs["during_script_content"])


def url_defang(url):
    url = url.replace("[.]", ".").replace("[.", ".").replace(".]", ".").replace("hxxp", "http").replace("hxtp", "http")
    if not url.startswith("http"):
        url = f"http://{url}"
    return url


def _download_file(route, url, options):
    socks5s = _load_socks5_operational()
    proxies = {}
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
                "http": f"socks5://{socks5s[route]['host']}:{socks5s[route]['port']}",
                "https": f"socks5://{socks5s[route]['host']}:{socks5s[route]['port']}",
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


def category_all_files(task_id, category, base_path):
    analysis = False
    query_category = category
    if category == "CAPE":
        category = "CAPE.payloads"
    if repconf.mongodb.enabled:
        analysis = mongo_find_one("analysis", {"info.id": int(task_id)}, {f"{category}.sha256": 1, "_id": 0}, sort=[("_id", -1)])
    # if es_as_db:
    #    # ToDo missed category
    #    analysis = es.search(index=get_analysis_index(), query=get_query_by_info_id(task_id))["hits"]["hits"][0]["_source"]

    if analysis:
        if query_category == "CAPE":
            return [os.path.join(base_path, block["sha256"]) for block in analysis.get(query_category, {}).get("payloads", [])]
        else:
            return [os.path.join(base_path, block["sha256"]) for block in analysis.get(category, [])]


def validate_task(tid, status=TASK_REPORTED):
    task = db.view_task(tid, details=True)
    task_id = tid
    if not task:
        return {"error": True, "error_value": "Task does not exist"}

    if task.status == TASK_RECOVERED and task.custom:
        m = re.match(r"^Recovery_(?P<taskid>\d+)$", task.custom)
        if m:
            task_id = int(m.group("taskid"))
            task = db.view_task(task_id, details=True)

    if status and status not in ALL_DB_STATUSES:
        return {"error": True, "error_value": "Specified wrong task status"}
    elif status == task.status:
        if tid != task_id:
            return {"error": False, "rtid": task_id}
        return {"error": False}
    elif task.status in {TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING}:
        return {"error": True, "error_value": "Task failed"}
    elif task.status != TASK_REPORTED:
        return {"error": True, "error_value": "Task is still being analyzed"}

    return {"error": False}


def validate_task_by_path(tid):
    analysis_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(tid))
    # verify path with
    # if not os.path.normpath(srcdir).startswith(ANALYSIS_BASE_PATH):
    #    return render(request, "error.html", {"error": f"File not found {os.path.basename(srcdir)}"})

    return path_exists(analysis_path)


perform_search_filters = {
    "info": 1,
    "virustotal_summary": 1,
    "detections.family": 1,
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
    "_id": 0,
}

hash_searches = {
    "ssdeep": "ssdeep",
    "crc32": "crc32",
    "md5": "md5",
    "sha1": "sha1",
    "sha3": "sha3_384",
    "sha256": "sha256",
    "sha512": "sha512",
}

search_term_map = {
    "id": "info.id",
    "ids": "info.id",
    "tags_tasks": "info.id",
    "package": "info.package",
    "ttp": "ttps.ttp",
    "malscore": "malscore",
    "name": "target.file.name",
    "type": "target.file.type",
    "file": "behavior.summary.files",
    "command": "behavior.summary.executed_commands",
    "configs": "CAPE.configs",
    "resolvedapi": "behavior.summary.resolved_apis",
    "key": "behavior.summary.keys",
    "mutex": "behavior.summary.mutexes",
    "domain": "network.domains.domain",
    "ip": "network.hosts.ip",
    "asn": "network.hosts.asn",
    "asn_name": "network.hosts.asn_name",
    "signature": "signatures.description",
    "signame": "signatures.name",
    "detections": "detections.family",
    "url": "target.url",
    "iconhash": "static.pe.icon_hash",
    "iconfuzzy": "static.pe.icon_fuzzy",
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
    "procmemyara": ("procmemory.yara.name", "procmemory.cape_yara.name"),
    "procdumpyara": ("procdump.yara.name", "procdump.cape_yara.name"),
    "virustotal": "virustotal.results.sig",
    "machinename": "info.machine.name",
    "machinelabel": "info.machine.label",
    "comment": "info.comments.Data",
    "shrikemsg": "info.shrike_msg",
    "shrikeurl": "info.shrike_url",
    "shrikerefer": "info.shrike_refer",
    "shrikesid": "info.shrike_sid",
    "custom": "info.custom",
    # initial binary
    "target_sha256": ("target.file.sha256", f"target.file.{FILE_REF_KEY}"),
    "tlp": "info.tlp",
    "ja3_hash": "suricata.tls.ja3.hash",
    "ja3_string": "suricata.tls.ja3.string",
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
    # File_extra_info
    "extracted_tool": (
        "info.parent_sample.extracted_files_tool",
        "target.file.extracted_files_tool",
        "dropped.extracted_files_tool",
        "procdump.extracted_files_tool",
        "CAPE.payloads.extracted_files_tool",
    ),
}

search_term_map_repetetive_blocks = {
    "ssdeep": "ssdeep",
    "clamav": "clamav",
    "yaraname": "yara.name",
    "capeyara": "cape_yara.name",
    "capetype": "cape_type.name",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha3": "sha3_384",
    "sha512": "sha512",
    "crc32": "crc32",
    "die": "die",
    "trid": "trid",
    "imphash": "imphash",
}

search_term_map_base_naming = (
    ("info.parent_sample",) + NORMALIZED_FILE_FIELDS + tuple(f"{category}.extracted_files" for category in NORMALIZED_FILE_FIELDS)
)

for key, value in search_term_map_repetetive_blocks.items():
    search_term_map.update({key: [f"{path}.{value}" for path in search_term_map_base_naming]})

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
    "package",
)

normalized_int_terms = (
    "sport",
    "dport",
    "port",
)


def perform_search(term, value, search_limit=False, user_id=False, privs=False, web=True, projection=None):
    if repconf.mongodb.enabled and repconf.elasticsearchdb.enabled and essearch and not term:
        multi_match_search = {"query": {"multi_match": {"query": value, "fields": ["*"]}}}
        numhits = es.search(index=get_analysis_index(), body=multi_match_search, size=0)["hits"]["total"]
        return [
            d["_source"]
            for d in es.search(index=get_analysis_index(), body=multi_match_search, sort="task_id:desc", size=numhits)["hits"][
                "hits"
            ]
        ]

    query_val = False
    search_limit = web_cfg.general.get("search_limit", 50) if web else 0
    if term in normalized_lower_terms:
        query_val = value.lower()
    elif term in normalized_int_terms:
        query_val = int(value)
    elif term in ("surisid", "id"):
        with suppress(Exception):
            query_val = int(value)
    elif term in ("ids", "options", "tags_tasks", "user_tasks"):
        try:
            ids = []
            if term == "ids":
                ids = value
            elif term == "tags_tasks":
                ids = [int(v.id) for v in db.list_tasks(tags_tasks_like=value, limit=search_limit)]
            elif term == "user_tasks":
                if not user_id:
                    ids = 0
                else:
                    # ToDo allow to admin search by user tasks
                    ids = [int(v.id) for v in db.list_tasks(user_id=user_id, limit=search_limit)]
            else:
                ids = [int(v.id) for v in db.list_tasks(options_like=value, limit=search_limit)]
            if ids:
                if len(ids) > 1:
                    term = "ids"
                    query_val = {"$in": ids}
                else:
                    term = "id"
                    if isinstance(value, list):
                        value = value[0]
                    query_val = int(value)
        except Exception as e:
            print(term, value, e)
    elif term == "configs":
        # check if family name is string only maybe?
        query_val = {f"{search_term_map[term]}.{value}": {"$exist": True}, "$options": "i"}
    elif term == "ttp":
        if validate_ttp(value):
            query_val = value.upper()
        else:
            raise ValueError("Invalid TTP enterred")
    elif term == "malscore":
        query_val = {"$gte": float(value)}
    else:
        query_val = {"$regex": value, "$options": "i"}

    if term not in search_term_map:
        return None

    if not search_limit:
        search_limit = web_cfg.general.get("search_limit", 50)

    elif term == "configs":
        # check if family name is string only maybe?
        search_term_map[term] = f"CAPE.configs.{value}"
        query_val = {"$exists": True}

    if repconf.mongodb.enabled and query_val:
        if isinstance(search_term_map[term], str):
            mongo_search_query = {search_term_map[term]: query_val}
        else:
            search_terms = [{search_term: query_val} for search_term in search_term_map[term]]
            if term in hash_searches:
                # For analyses where files have been stored in the "files" collection, search
                # there for the _id (i.e. sha256) of documents matching the given hash. As a
                # special case, we don't need to do that query if the requested hash type is
                # "sha256" since that's what's stored in the "file_refs" key.
                # We do all this in addition to search the old keys for backwards-compatibility
                # with documents that do not use this mechanism for storing file data.
                if term == "sha256":
                    file_refs = [query_val]
                else:
                    file_docs = mongo_find(FILES_COLL, {hash_searches[term]: query_val}, {"_id": 1})
                    file_refs = [doc["_id"] for doc in file_docs]
                if file_refs:
                    if len(file_refs) > 1:
                        query = {"$in": file_refs}
                    else:
                        query = file_refs[0]
                    search_terms.extend([{f"{pfx}.{FILE_REF_KEY}": query} for pfx in NORMALIZED_FILE_FIELDS])
            mongo_search_query = {"$or": search_terms}

        # Allow to overwrite perform_search_filters for custom results
        if not projection:
            projection = perform_search_filters
        if "target.file.sha256" in projection:
            projection = dict(**projection)
            projection[f"target.file.{FILE_REF_KEY}"] = 1
        retval = list(mongo_find("analysis", mongo_search_query, projection, limit=search_limit))
        for doc in retval:
            target_file = doc.get("target", {}).get("file", {})
            if FILE_REF_KEY in target_file and "sha256" not in target_file:
                target_file["sha256"] = target_file.pop(FILE_REF_KEY)
        return retval

    if es_as_db:
        _source_fields = list(perform_search_filters.keys())[:-1]
        if isinstance(search_term_map[term], str):
            q = {"query": {"match": {search_term_map[term]: value}}}
            return [d["_source"] for d in es.search(index=get_analysis_index(), body=q, _source=_source_fields)["hits"]["hits"]]
        else:
            queries = [{"match": {search_term: value}} for search_term in search_term_map[term]]
            q = {"query": {"bool": {"should": queries, "minimum_should_match": 1}}}
            return [d["_source"] for d in es.search(index=get_analysis_index(), body=q, _source=_source_fields)["hits"]["hits"]]


def force_int(value):
    try:
        value = int(value)
    except Exception:
        value = 0
    finally:
        return value


def force_bool(value):
    if isinstance(value, bool):
        return value

    if not value:
        return False

    if value.lower() in ("false", "no", "off", "0"):
        return False
    elif value.lower() in ("true", "yes", "on", "1"):
        return True
    else:
        log.warning("Value of %s cannot be converted from string to bool", value)
        return False


def parse_request_arguments(request, keyword="POST"):
    # Django uses request.POST and API uses request.data
    static = getattr(request, keyword).get("static", "")
    referrer = validate_referrer(getattr(request, keyword).get("referrer"))
    package = getattr(request, keyword).get("package", "")
    timeout = force_int(getattr(request, keyword).get("timeout"))
    priority = force_int(getattr(request, keyword).get("priority"))
    options = getattr(request, keyword).get("options", "")
    machine = getattr(request, keyword).get("machine", "")
    platform = getattr(request, keyword).get("platform", "")
    tags_tasks = getattr(request, keyword).get("tags_tasks")
    tags = getattr(request, keyword).get("tags")
    custom = getattr(request, keyword).get("custom", "")
    memory = force_bool(getattr(request, keyword).get("memory", False))
    clock = getattr(request, keyword).get("clock", datetime.now().strftime("%m-%d-%Y %H:%M:%S"))
    if not clock:
        clock = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    if "1970" in clock:
        clock = datetime.now().strftime("%m-%d-%Y %H:%M:%S")
    enforce_timeout = force_bool(getattr(request, keyword).get("enforce_timeout", False))
    shrike_url = getattr(request, keyword).get("shrike_url")
    shrike_msg = getattr(request, keyword).get("shrike_msg")
    shrike_sid = getattr(request, keyword).get("shrike_sid")
    shrike_refer = getattr(request, keyword).get("shrike_refer")
    unique = force_bool(getattr(request, keyword).get("unique", False))
    tlp = getattr(request, keyword).get("tlp")
    lin_options = getattr(request, keyword).get("lin_options", "")
    route = getattr(request, keyword).get("route", "")
    cape = getattr(request, keyword).get("cape", "")

    if referrer:
        if options:
            options += ","
        options += f"referrer={referrer}"

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


_bazaar_map = {
    32: "md5_hash",
    40: "sha1_hash",
    64: "sha256_hash",
}


def _malwarebazaar_dl(hash):
    sample = None
    if len(hash) not in _bazaar_map:
        return False

    try:
        data = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_file", _bazaar_map[len(hash)]: hash})
        if data.ok and b"file_not_found" not in data.content:
            try:
                with pyzipper.AESZipFile(io.BytesIO(data.content)) as zf:
                    zf.setpassword(b"infected")
                    sample = zf.read(zf.namelist()[0])
            except pyzipper.zipfile.BadZipFile:
                print(data.content)
    except Exception as e:
        logging.error(e, exc_info=True)

    return sample


def thirdpart_aux(samples, prefix, opt_filename, details, settings):
    folder = os.path.join(settings.TEMP_PATH, "cape-external")
    if not path_exists(folder):
        path_mkdir(folder, exist_ok=True)
    for h in get_hash_list(samples):
        base_dir = tempfile.mkdtemp(prefix=prefix, dir=folder)
        if opt_filename:
            filename = f"{base_dir}/{opt_filename}"
        else:
            filename = f"{base_dir}/{sanitize_filename(h)}"
        details["path"] = filename
        details["fhash"] = h
        paths = db.sample_path_by_hash(h)

        # clean old content
        if "content" in details:
            del details["content"]

        if paths:
            details["content"] = get_file_content(paths)

        if prefix == "vt":
            details["url"] = f"https://www.virustotal.com/api/v3/files/{h.lower()}/download"
        elif prefix == "bazaar":
            content = _malwarebazaar_dl(h)
            if content:
                details["content"] = content

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


def download_from_vt(samples, details, opt_filename, settings):
    if settings.VTDL_KEY:
        details["headers"] = {"x-apikey": settings.VTDL_KEY}
    elif details.get("apikey", False):
        details["headers"] = {"x-apikey": details["apikey"]}
    else:
        details["errors"].append({"error": "Apikey not configured, neither passed as opt_apikey"})
        return details

    details["service"] = "VirusTotal"
    return thirdpart_aux(samples, "vt", opt_filename, details, settings)


def download_from_bazaar(samples, details, opt_filename, settings):
    if not HAVE_PYZIPPER:
        print("Malware Bazaar download: Missed pyzipper dependency: pip3 install pyzipper -U")
        return

    details["service"] = "MalwareBazaar"
    return thirdpart_aux(samples, "bazaar", opt_filename, details, settings)


def process_new_task_files(request, samples, details, opt_filename, unique):
    list_of_files = []
    for sample in samples:
        # Error if there was only one submitted sample, and it's empty.
        # But if there are multiple and one was empty, just ignore it.
        if not sample.size:
            details["errors"].append({sample.name: "You uploaded an empty file."})
            continue

        size = sample.size
        if size > web_cfg.general.max_sample_size and not (
            web_cfg.general.allow_ignore_size and "ignore_size_check" in details["options"]
        ):
            if not web_cfg.general.enable_trim:
                details["errors"].append(
                    {
                        sample.name: f"Uploaded file exceeds the maximum allowed size in conf/web.conf. Sample size is: {size / float(1 << 20):,.0f} Allowed size is: {web_cfg.general.max_sample_size / float(1 << 20):,.0f}"
                    }
                )
                continue

        data = sample.read()

        if opt_filename:
            filename = opt_filename
        else:
            filename = sanitize_filename(sample.name)

        # Moving sample from django temporary file to CAPE temporary storage for persistence, if configured by user.
        try:
            path = store_temp_file(data, filename)
            target_file = File(path)
            sha256 = target_file.get_sha256()
        except OSError:
            details["errors"].append(
                {filename: "Temp folder from cuckoo.conf, disk is out of space. Clean some space before continue."}
            )
            continue

        if (
            not request.user.is_staff
            and (web_cfg.uniq_submission.enabled or unique)
            and db.check_file_uniq(sha256, hours=web_cfg.uniq_submission.hours)
        ):
            details["errors"].append(
                {filename: "Duplicated file, disable unique option on submit or in conf/web.conf to force submission"}
            )
            continue

        list_of_files.append((data, path, sha256))

    return list_of_files, details


def process_new_dlnexec_task(url, route, options, custom):
    url = url.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
    response = _download_file(route, url, options)
    if not response:
        return False, False, False

    name = os.path.basename(url)
    if "." not in name:
        name = get_user_filename(options, custom) or generate_fake_name()

    path = store_temp_file(response, name)

    return path, response, ""


def submit_task(
    target: str,
    package: str = "",
    timeout: int = 0,
    task_options: str = "",
    priority: int = 1,
    machine: str = "",
    platform: str = "",
    memory: bool = False,
    enforce_timeout: bool = False,
    clock: str = None,
    tags: str = None,
    parent_id: int = None,
    tlp: bool = None,
    distributed: bool = False,
    filename: str = "",
    server_url: str = "",
):
    """
    ToDo add url support in future
    """
    if not path_exists(target):
        log.info("File doesn't exist")
        return

    task_id = False
    if distributed:
        options = {
            "package": package,
            "timeout": timeout,
            "options": task_options,
            "priority": priority,
            # "machine": machine,
            "platform": platform,
            "memory": memory,
            "enforce_timeout": enforce_timeout,
            "clock": clock,
            "tags": tags,
            "parent_id": parent_id,
            "filename": filename,
        }

        multipart_file = [("file", (os.path.basename(target), open(target, "rb")))]
        try:
            res = requests.post(server_url, files=multipart_file, data=options)
            if res and res.ok:
                task_id = res.json()["data"]["task_ids"][0]
        except Exception as e:
            log.error(e)
    else:
        task_id = db.add_path(
            file_path=target,
            package=package,
            timeout=timeout,
            options=task_options,
            priority=priority,
            machine=machine,
            platform=platform,
            memory=memory,
            enforce_timeout=enforce_timeout,
            parent_id=parent_id,
            tlp=tlp,
            filename=filename,
        )
    if not task_id:
        log.warn("Error adding CAPE task to database: %s", package)
        return task_id

    log.info('CAPE detection on file "%s": %s - added as CAPE task with ID %s', target, package, task_id)
    return task_id


# https://stackoverflow.com/questions/14989858/get-the-current-git-hash-in-a-python-script/68215738#68215738
def get_running_commit() -> str:
    git_folder = Path(CUCKOO_ROOT, ".git")
    head_name = Path(git_folder, "HEAD").read_text().split("\n")[0].split(" ")[-1]
    return Path(git_folder, head_name).read_text().replace("\n", "")
