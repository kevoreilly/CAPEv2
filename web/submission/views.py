# encoding: utf-8
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import logging
import tempfile
import random
import datetime

try:
    import re2 as re
except ImportError:
    import re

from django.conf import settings
from django.shortcuts import redirect, render
from django.contrib.auth.decorators import login_required

sys.path.append(settings.CUCKOO_PATH)
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.quarantine import unquarantine
from lib.cuckoo.common.saztopcap import saz_to_pcap
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.rooter import vpns, _load_socks5_operational
from lib.cuckoo.common.utils import store_temp_file, validate_referrer, sanitize_filename, get_user_filename, generate_fake_name, get_options
from lib.cuckoo.common.web_utils import download_file, disable_x64, get_file_content, _download_file, parse_request_arguments, all_vms_tags, download_from_vt, perform_search


# this required for hash searches
FULL_DB = False
cfg = Config("cuckoo")
routing = Config("routing")
repconf = Config("reporting")
processing = Config("processing")
aux_conf = Config("auxiliary")
web_conf = Config("web")

VALID_LINUX_TYPES = ["Bourne-Again", "POSIX shell script", "ELF", "Python"]

db = Database()

from urllib3 import disable_warnings

disable_warnings()

logger = logging.getLogger(__name__)


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

def get_form_data(platform):
    files = os.listdir(os.path.join(settings.CUCKOO_PATH, "analyzer", platform, "modules", "packages"))

    packages = []
    for name in files:
        name = os.path.splitext(name)[0]
        if name == "__init__":
            continue
        packages.append(name)

    # Prepare a list of VM names, description label based on tags.
    machines = []
    for machine in db.list_machines():
        tags = []
        for tag in machine.tags:
            tags.append(tag.name)

        if tags:
            label = "{}:{}".format(machine.label, ",".join(tags))
        else:
            label = "{}".format(machine.label)

        if web_conf.linux.enabled:
            label = machine.platform + ":" + label

        machines.append((machine.label, label))

    # Prepend ALL/ANY options. Disable until a platform can be verified in scheduler
    machines.insert(0, ("", "First available"))
    if web_conf.all_vms.enabled:
        machines.insert(1, ("all", "All"))

    return packages, machines


# Conditional decorator for web authentication
class conditional_login_required(object):
    def __init__(self, dec, condition):
        self.decorator = dec
        self.condition = condition

    def __call__(self, func):
        if not self.condition:
            return func
        return self.decorator(func)


def force_int(value):
    try:
        value = int(value)
    except:
        value = 0
    finally:
        return value


def get_platform(magic):
    if magic and any(x in magic for x in VALID_LINUX_TYPES):
        return "linux"
    else:
        return "windows"


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request, resubmit_hash=False):
    if request.method == "POST":

        static, package, timeout, priority, options, machine, platform, tags, custom, memory, \
            clock, enforce_timeout, shrike_url, shrike_msg, shrike_sid, shrike_refer, unique, referrer, \
            tlp, tags_tasks, route, cape = parse_request_arguments(request)

        # This is done to remove spaces in options but not breaks custom paths
        options = ",".join("=".join(value.strip() for value in option.split("=", 1)) for option in options.split(",") if option and "=" in option)
        opt_filename = get_user_filename(options, custom)

        if priority and web_conf.public.enabled and web_conf.public.priority:
            priority = web_conf.public.priority

        if timeout and web_conf.public.enabled and web_conf.public.timeout:
            timeout = web_conf.public.timeout

        if options:
            options += ","

        if referrer:
            options += "referrer=%s," % (referrer)

        if request.POST.get("free"):
            options += "free=yes,"

        if request.POST.get("nohuman"):
            options += "nohuman=yes,"

        if request.POST.get("tor"):
            options += "tor=yes,"

        if request.POST.get("process_dump"):
            options += "procdump=0,"

        if request.POST.get("process_memory"):
            options += "procmemdump=1,"

        if request.POST.get("import_reconstruction"):
            options += "import_reconstruction=1,"

        if request.POST.get("disable_cape"):
            options += "disable_cape=1,"

        if request.POST.get("kernel_analysis"):
            options += "kernel_analysis=yes,"

        if request.POST.get("norefer"):
            options += "norefer=1,"

        if request.POST.get("oldloader"):
            options += "loader=oldloader.exe,loader_64=oldloader_x64.exe,"

        if request.POST.get("unpack"):
            options += "unpack=yes,"

        options = options[:-1]

        opt_apikey = False
        opts = get_options(options)
        if opts:
            opt_apikey = opts.get("apikey", False)

        status = "ok"
        task_ids_tmp = list()
        existent_tasks = dict()
        details = {
            "errors": [],
            "content": False,
            "request": request,
            "task_ids": [],
            "url": False,
            "params": {},
            "headers": {},
            "service": "Local",
            "path": "",
            "fhash": False,
            "options": options,
            "only_extraction": False,
            "user_id": request.user.id or 0,
        }

        if "hash" in request.POST and request.POST.get("hash", False) and request.POST.get("hash")[0] != '':
            resubmission_hash = request.POST.get("hash").strip()
            paths = db.sample_path_by_hash(resubmission_hash)
            if paths:
                content = get_file_content(paths)
                if not content:
                    return render(request, "error.html", {"error": "Can't find {} on disk, {}".format(resubmission_hash, str(paths))})
                folder = os.path.join(settings.TEMP_PATH, "cape-resubmit")
                if not os.path.exists(folder):
                    os.makedirs(folder)
                base_dir = tempfile.mkdtemp(prefix='resubmit_', dir=folder)
                if opt_filename:
                    filename = base_dir + "/" + opt_filename
                else:
                    filename = base_dir + "/" + sanitize_filename(resubmission_hash)
                path = store_temp_file(content, filename)
                details["path"] = path
                details["content"] = content
                status, task_ids_tmp = download_file(**details)
                if status == "error":
                    details["errors"].append({os.path.basename(filename): task_ids_tmp})
                else:
                    details["task_ids"] = task_ids_tmp
                    records = perform_search("sha256", resubmission_hash)
                    for record in records:
                        existent_tasks.setdefault(record["target"]["file"]["sha256"], list())
                        existent_tasks[record["target"]["file"]["sha256"]].append(record)
            else:
                return render(request, "error.html", {"error": "File not found on hdd for resubmission"})

        elif "sample" in request.FILES:
            samples = request.FILES.getlist("sample")
            details["service"] = "WebGUI"
            for sample in samples:
                # Error if there was only one submitted sample and it's empty.
                # But if there are multiple and one was empty, just ignore it.
                if not sample.size:
                    details["errors"].append({sample.name: "You uploaded an empty file."})
                    continue
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    details["errors"].append({sample.name:  "You uploaded a file that exceeds the maximum allowed upload size specified in web/web/local_settings.py."})
                    continue

                if opt_filename:
                    filename = opt_filename
                else:
                    filename = sanitize_filename(sample.name)
                # Moving sample from django temporary file to CAPE temporary storage to let it persist between reboot (if user like to configure it in that way).
                path = store_temp_file(sample.read(), filename)
                sha256 = File(path).get_sha256()
                if (web_conf.uniq_submission.enabled or unique) and db.check_file_uniq(sha256, hours=web_conf.uniq_submission.hours):
                    details["errors"].append({filename: "Duplicated file, disable unique option on submit or in conf/web.conf to force submission"})
                    continue

                if timeout and web_conf.public.enabled and web_conf.public.timeout and timeout > web_conf.public.timeout:
                    timeout = web_conf.public.timeout

                details["path"] = path
                details["content"] = get_file_content(path)
                status, task_ids_tmp = download_file(**details)
                if status == "error":
                    details["errors"].append({os.path.basename(path): task_ids_tmp})
                else:
                    records = perform_search("sha256", sha256)
                    for record in records:
                        if record.get("target").get("file", {}).get("sha256"):
                            existent_tasks.setdefault(record["target"]["file"]["sha256"], list())
                            existent_tasks[record["target"]["file"]["sha256"]].append(record)
                    details["task_ids"] = task_ids_tmp

        elif "quarantine" in request.FILES:
            samples = request.FILES.getlist("quarantine")
            for sample in samples:
                # Error if there was only one submitted sample and it's empty.
                # But if there are multiple and one was empty, just ignore it.
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html", {"error": "You uploaded an empty quarantine file."})
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request, "error.html", {"error": "You uploaded a quarantine file that exceeds the maximum allowed upload size specified in web/web/local_settings.py."})

                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                tmp_path = store_temp_file(sample.read(), sample.name)

                path = unquarantine(tmp_path)
                try:
                    os.remove(tmp_path)
                except Exception as e:
                    print(e)

                if not path:
                    return render(request, "error.html", {"error": "You uploaded an unsupported quarantine file."})

                details["path"] = path
                details["content"] = get_file_content(path)
                status, task_ids_tmp = download_file(**details)
                if status == "error":
                    details["errors"].append({sample.name: task_ids_tmp})
                else:
                    details["task_ids"] = task_ids_tmp

        elif "static" in request.FILES:
            samples = request.FILES.getlist("static")
            for sample in samples:
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html", {"error": "You uploaded an empty file."})
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request, "error.html", {"error": "You uploaded a file that exceeds the maximum allowed upload size specified in web/web/local_settings.py."})

                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                path = store_temp_file(sample.read(), sample.name)

                task_id = db.add_static(file_path=path, priority=priority, tlp=tlp)
                if not task_id:
                    return render(request, "error.html", {"error": "We don't have static extractor for this"})
                details["task_ids"].append(task_id)

        elif "pcap" in request.FILES:
            samples = request.FILES.getlist("pcap")
            for sample in samples:
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html", {"error": "You uploaded an empty PCAP file."})
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request, "error.html", {"error": "You uploaded a PCAP file that exceeds the maximum allowed upload size specified in web/web/local_settings.py."})

                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                path = store_temp_file(sample.read(), sample.name)

                if sample.name.lower().endswith(".saz"):
                    saz = saz_to_pcap(path)
                    if saz:
                        try:
                            os.remove(path)
                        except Exception as e:
                            pass
                        path = saz
                    else:
                        return render(request, "error.html", {"error": "Conversion from SAZ to PCAP failed."})

                task_id = db.add_pcap(file_path=path, priority=priority, tlp=tlp, user_id=request.user.id or 0)
                if task_id:
                    details["task_ids"].append(task_id)

        elif "url" in request.POST and request.POST.get("url").strip():
            url = request.POST.get("url").strip()
            if not url:
                return render(request, "error.html", {"error": "You specified an invalid URL!"})

            url = url.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")

            if machine.lower() == "all":
                machines = [vm.name for vm in db.list_machines(platform=platform)]
            elif machine:
                machine_details = db.view_machine(machine)
                if platform and hasattr(machine_details, "platform") and not machine_details.platform == platform:
                    return render(request, "error.html", {"error": "Wrong platform, {} VM selected for {} sample".format(machine_details.platform, platform)}, )
                else:
                    machines = [machine]

            else:
                machines = [None]
            for entry in machines:
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
                    tags_tasks=tags_tasks,
                    user_id=request.user.id or 0,
                )
                details["task_ids"].append(task_id)

        elif "dlnexec" in request.POST and request.POST.get("dlnexec").strip():
            url = request.POST.get("dlnexec").strip()
            if not url:
                return render(request, "error.html", {"error": "You specified an invalid URL!"})

            url = url.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
            response = _download_file(request.POST.get("route", None), url, options)
            if not response:
                 return render(request, "error.html", {"error": "Was impossible to retrieve url"})

            name = os.path.basename(url)
            if not "." in name:
                name = get_user_filename(options, custom) or generate_fake_name()

            path = store_temp_file(response, name)
            details["path"] = path
            details["content"] = get_file_content(path)
            details["service"] = "DLnExec"
            status, task_ids_tmp = download_file(**details)
            if status == "error":
                details["errors"].append({name: task_ids_tmp})
            else:
                details["task_ids"] = task_ids_tmp
        elif settings.VTDL_ENABLED and "vtdl" in request.POST and request.POST.get("vtdl", False) and request.POST.get("vtdl")[0] != "":
            if not settings.VTDL_KEY or not settings.VTDL_PATH:
                    return render(request, "error.html", {"error": "You specified VirusTotal but must edit the file and specify your VTDL_KEY variable and VTDL_PATH base directory"})
            else:
                if opt_apikey:
                    details["apikey"] = opt_apikey
                details = download_from_vt(request.POST.get("vtdl").strip(), details, opt_filename, settings)

        if details.get("task_ids"):
            tasks_count = len(details["task_ids"])
        else:
            tasks_count = 0
        if tasks_count > 0:
            data = {"tasks": details["task_ids"], "tasks_count": tasks_count, "errors": details["errors"], "existent_tasks": existent_tasks}
            return render(request, "submission/complete.html", data)
        else:
            return render(request, "error.html", {"error": "Error adding task(s) to CAPE's database.", "errors": details["errors"]})
    else:
        enabledconf = dict()
        enabledconf["vt"] = settings.VTDL_ENABLED
        enabledconf["kernel"] = settings.OPT_ZER0M0N
        enabledconf["memory"] = processing.memory.get("enabled")
        enabledconf["procmemory"] = processing.procmemory.get("enabled")
        enabledconf["dlnexec"] = settings.DLNEXEC
        enabledconf["url_analysis"] = settings.URL_ANALYSIS
        enabledconf["tags"] = False
        enabledconf["dist_master_storage_only"] = repconf.distributed.master_storage_only
        enabledconf["linux_on_gui"] = web_conf.linux.enabled
        enabledconf["tlp"] = web_conf.tlp.enabled

        if all_vms_tags:
            enabledconf["tags"] = True

        if not enabledconf["tags"]:
            # load multi machinery tags:
            # Get enabled machinery
            machinery = cfg.cuckoo.get("machinery")
            if machinery == "multi":
                for mmachinery in Config(machinery).multi.get("machinery").split(","):
                    vms = [x.strip() for x in getattr(Config(mmachinery), mmachinery).get("machines").split(",")]
                    if any(["tags" in list(getattr(Config(mmachinery), vmtag).keys()) for vmtag in vms]):
                        enabledconf["tags"] = True
                        break
            else:
                # Get VM names for machinery config elements
                vms = [x.strip() for x in getattr(Config(machinery), machinery).get("machines").split(",")]
                # Check each VM config element for tags
                if any(["tags" in list(getattr(Config(machinery), vmtag).keys()) for vmtag in vms]):
                    enabledconf["tags"] = True

        packages, machines = get_form_data("windows")

        socks5s = _load_socks5_operational()
        socks5s_random = ""
        if socks5s:
            socks5s_random = random.choice(list(socks5s.values())).get("description", False)

        existent_tasks = dict()
        if resubmit_hash:
            records = perform_search("sha256", resubmit_hash)
            for record in records:
                existent_tasks.setdefault(record["target"]["file"]["sha256"], list())
                existent_tasks[record["target"]["file"]["sha256"]].append(record)

        return render(
            request,
            "submission/index.html",
            {
                "packages": sorted(packages),
                "machines": machines,
                "vpns": list(vpns.values()),
                "socks5s": list(socks5s.values()),
                "socks5s_random": socks5s_random,
                "route": routing.routing.route,
                "internet": routing.routing.internet,
                "inetsim": routing.inetsim.enabled,
                "tor": routing.tor.enabled,
                "config": enabledconf,
                "resubmit": resubmit_hash,
                "tags": sorted(list(set(all_vms_tags))),
                "existent_tasks": existent_tasks,
            },
        )


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def status(request, task_id):
    task = db.view_task(task_id)
    if not task:
        return render(request, "error.html", {"error": "The specified task doesn't seem to exist."})

    completed = False
    if task.status == "reported":
        return redirect("report", task_id=task_id)

    status = task.status
    if status == "completed":
        status = "processing"

    return render(request, "submission/status.html", {"completed": completed, "status": status, "task_id": task_id})
