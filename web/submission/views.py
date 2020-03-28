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

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.utils import store_temp_file, validate_referrer, sanitize_filename, get_user_filename, generate_fake_name
from lib.cuckoo.common.quarantine import unquarantine
from lib.cuckoo.common.saztopcap import saz_to_pcap
from lib.cuckoo.common.exceptions import CuckooDemuxError
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.rooter import vpns, _load_socks5_operational
from lib.cuckoo.common.web_utils import get_magic_type, download_file, disable_x64, get_file_content, recon, _download_file
from lib.cuckoo.common.objects import File

# this required for hash searches
FULL_DB = False
HAVE_DIST = False
cfg = Config("cuckoo")
routing = Config("routing")
repconf = Config("reporting")
processing = Config("processing")
aux_conf = Config("auxiliary")

VALID_LINUX_TYPES = ["Bourne-Again", "POSIX shell script", "ELF", "Python"]

db = Database()

if repconf.distributed.enabled:
    try:
        # Tags
        from lib.cuckoo.common.dist_db import Machine, create_session
        HAVE_DIST = True
    except Exception as e:
        print(e)

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
        authSource=repconf.mongodb.db
        )[repconf.mongodb.db]
    FULL_DB = True

if HAVE_DIST:
    session = create_session(repconf.distributed.db)

def load_vms_tags():
    all_tags = list()
    if HAVE_DIST and repconf.distributed.enabled:
        try:
            tmp_db = session()
            for vm in tmp_db.query(Machine).all():
                all_tags += vm.tags
            all_tags = sorted([_f for _f in all_tags if _f])
            tmp_db.close()
        except Exception as e:
            print(e)

    for machine in db.list_machines():
        for tag in machine.tags:
            all_tags.append(tag.name)

    return all_tags


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
            label = "{}:{}:{}".format(machine.platform, machine.label, ",".join(tags))
        else:
            label = "{}:{}".format(machine.platform, machine.label)

        machines.append((machine.label, label))

    # Prepend ALL/ANY options. Disable until a platform can be verified in scheduler
    machines.insert(0, ("", "First available"))
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
        package = request.POST.get("package", "")
        timeout = min(force_int(request.POST.get("timeout")), 60 * 60 * 24)
        options = request.POST.get("options", "")
        lin_options = request.POST.get("lin_options", "")
        priority = force_int(request.POST.get("priority"))
        machine = request.POST.get("machine", "")
        clock = request.POST.get("clock", datetime.datetime.now().strftime("%m-%d-%Y %H:%M:%S"))
        if not clock:
            clock = datetime.datetime.now().strftime("%m-%d-%Y %H:%M:%S")
        if "1970" in clock:
            clock = datetime.datetime.now().strftime("%m-%d-%Y %H:%M:%S")
        custom = request.POST.get("custom", "")
        memory = bool(request.POST.get("memory", False))
        enforce_timeout = bool(request.POST.get("enforce_timeout", False))
        referrer = validate_referrer(request.POST.get("referrer", None))
        tags = request.POST.get("tags", None)
        static = bool(request.POST.get("static", False))
        all_tags = load_vms_tags()
        if tags and not all([tag.strip() in all_tags for tag in tags.split(",")]):
            return render(request, "error.html",
                {"error": "Check Tags help, you have introduced incorrect tag(s)"})

        if lin_options:
            options = lin_options
        # This is done to remove spaces in options but not breaks custom paths
        options = ','.join('='.join(value.strip() for value in option.split("=", 1)) for option in options.split(",")
                           if option and '=' in option)
        opt_filename = get_user_filename(options, custom)

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

        if request.POST.get("route", None):
            options += "route={0},".format(request.POST.get("route", None))

        if request.POST.get("process_dump"):
            options += "procmemdump=1,procdump=1,"

        if request.POST.get("process_memory"):
            options += "procmemdump=1,procdump=1,"

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

        unique = request.POST.get("unique", False)

        orig_options = options
        task_ids = []
        task_machines = []

        status = "ok"
        failed_hashes = list()
        task_ids_tmp = list()
        if "hash" in request.POST and request.POST.get("hash", False) and request.POST.get("hash")[0] != '':
            resubmission_hash = request.POST.get("hash").strip()
            paths = db.sample_path_by_hash(resubmission_hash)
            if paths:
                paths = [_f for _f in [path if os.path.exists(path) else False for path in paths] if _f]
                if not paths and FULL_DB:
                    tasks = results_db.analysis.find({"dropped.sha256": resubmission_hash})
                    if tasks:
                        for task in tasks:
                            # grab task id and replace in path if needed aka distributed hack
                            path = os.path.join(settings.CUCKOO_PATH, "storage", "analyses",
                                                str(task["info"]["id"]), "files", resubmission_hash)
                            if os.path.exists(path):
                                paths = [path]
                                break

            if paths:
                content = False
                content = get_file_content(paths)
                if not content:
                    return render(request, "error.html",
                                  {"error": "Can't find {} on disk, {}".format(resubmission_hash, str(paths))})
                base_dir = tempfile.mkdtemp(prefix='resubmit_', dir=settings.TEMP_PATH)
                if opt_filename:
                    filename = base_dir + "/" + opt_filename
                else:
                    filename = base_dir + "/" + sanitize_filename(resubmission_hash)
                path = store_temp_file(content, filename)
                headers = {}
                url = 'local'
                params = {}

                status, task_ids = download_file(False, content, request, db, task_ids, url, params, headers, "Local",
                                                 path, package, timeout, options, priority, machine, clock, custom,
                                                 memory, enforce_timeout, referrer, tags, orig_options, "", static)
            else:
                return render(request, "error.html", {"error": "File not found on hdd for resubmission"})

        elif "sample" in request.FILES:
            samples = request.FILES.getlist("sample")
            for sample in samples:
                # Error if there was only one submitted sample and it's empty.
                # But if there are multiple and one was empty, just ignore it.
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html", {"error": "You uploaded an empty file."})
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request,
                                  "error.html",
                                  {"error": "You uploaded a file that exceeds the maximum allowed upload size "
                                            "specified in web/web/local_settings.py."})

                if opt_filename:
                    filename = opt_filename
                else:
                    filename = sample.name
                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                path = store_temp_file(sample.read(), filename)

                if unique and db.check_file_uniq(File(path).get_sha256()):
                    return render(request, "error.html",
                                  {"error": "Duplicated file, disable unique option to force submission"})

                magic_type = get_magic_type(path)
                if disable_x64 is True:
                    if magic_type and ("x86-64" in magic_type or "PE32+" in magic_type):
                        if len(samples) == 1:
                            return render(request, "error.html", {"error": "Sorry no x64 support yet"})
                        else:
                            continue

                    orig_options, timeout, enforce_timeout = recon(path, orig_options, timeout, enforce_timeout)

                platform = get_platform(magic_type)
                if machine.lower() == "all":
                    task_machines = [vm.name for vm in db.list_machines(platform=platform)]
                elif machine:
                    machine_details = db.view_machine(machine)
                    if not machine_details.platform == platform:
                        return render(request, "error.html",
                                      {"error": "Wrong platform, {} VM selected for {} sample".format(
                                          machine_details.platform, platform)})
                    else:
                        task_machines = [machine]

                else:
                    task_machines = ["first"]

                for entry in task_machines:
                    if entry == "first":
                        entry = None
                    try:
                        task_ids_new = db.demux_sample_and_add_to_db(file_path=path, package=package, timeout=timeout,
                                                                     options=options, priority=priority, machine=entry,
                                                                     custom=custom, memory=memory, platform=platform,
                                                                     enforce_timeout=enforce_timeout, tags=tags,
                                                                     clock=clock, static=static)
                        task_ids.extend(task_ids_new)
                    except CuckooDemuxError as err:
                        return render(request, "error.html", {"error": err})

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
                    return render(request, "error.html",
                                  {"error": "You uploaded a quarantine file that exceeds the maximum \
                                  allowed upload size specified in web/web/local_settings.py."})

                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                tmp_path = store_temp_file(sample.read(), sample.name)

                path = unquarantine(tmp_path)
                try:
                    os.remove(tmp_path)
                except Exception as e:
                    pass

                if not path:
                    return render(request, "error.html", {"error": "You uploaded an unsupported quarantine file."})

                if machine.lower() == "all":
                    task_machines = [vm.name for vm in db.list_machines(platform="windows")]
                elif machine:
                    machine_details = db.view_machine(machine)
                    if not machine_details.platform == "windows":
                        return render(request, "error.html",
                                      {"error": "Wrong platform, linux VM selected for {} sample".format(
                                          machine_details.platform)})
                    else:
                        task_machines = [machine]

                if not task_machines:
                    task_machines = ["first"]

                for entry in task_machines:
                    if entry == "first":
                        entry = None
                    task_ids_new = db.demux_sample_and_add_to_db(file_path=path, package=package, timeout=timeout,
                                                                 options=options, priority=priority, machine=entry,
                                                                 custom=custom, memory=memory, tags=tags,
                                                                 enforce_timeout=enforce_timeout, clock=clock)
                    if task_ids_new:
                        task_ids.extend(task_ids_new)

        elif "static" in request.FILES:
            samples = request.FILES.getlist("static")
            for sample in samples:
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html", {"error": "You uploaded an empty file."})
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request, "error.html", {"error": "You uploaded a file that exceeds the maximum \
                    allowed upload size specified in web/web/local_settings.py."})

                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                path = store_temp_file(sample.read(), sample.name)

                task_id = db.add_static(file_path=path, priority=priority)
                if not task_id:
                    return render(request, "error.html", {"error": "We don't have static extractor for this"})
                task_ids.append(task_id)

        elif "pcap" in request.FILES:
            samples = request.FILES.getlist("pcap")
            for sample in samples:
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html", {"error": "You uploaded an empty PCAP file."})
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request, "error.html", {"error": "You uploaded a PCAP file that exceeds the maximum \
                     allowed upload size specified in web/web/local_settings.py."})

                # Moving sample from django temporary file to Cuckoo temporary storage to
                # let it persist between reboot (if user like to configure it in that way).
                path = store_temp_file(sample.read(),
                                       sample.name)

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

                task_id = db.add_pcap(file_path=path, priority=priority)
                if task_id:
                    task_ids.append(task_id)

        elif "url" in request.POST and request.POST.get("url").strip():
            url = request.POST.get("url").strip()
            if not url:
                return render(request, "error.html", {"error": "You specified an invalid URL!"})

            url = url.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")

            if machine.lower() == "all":
                task_machines = [vm.name for vm in db.list_machines(platform="windows")]
            elif machine:
                machine_details = db.view_machine(machine)
                if not machine_details.platform == "windows":
                    return render(request, "error.html",
                                  {"error": "Wrong platform, linux VM selected for {} sample".format(
                                      machine_details.platform)})
                else:
                    task_machines = [machine]

            else:
                task_machines = ["first"]

            for entry in task_machines:
                if entry == "first":
                    entry = None
                task_ids_new = db.add_url(url=url, package=package, timeout=timeout, options=options, priority=priority,
                                          machine=entry, custom=custom, memory=memory, enforce_timeout=enforce_timeout,
                                          tags=tags, clock=clock)
                if task_ids_new:
                    task_ids.extend(task_ids_new)

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

            magic_type = get_magic_type(path)
            platform = get_platform(magic_type)

            if machine.lower() == "all":
                task_machines = [vm.name for vm in db.list_machines(platform=platform)]
            elif machine:
                machine_details = db.view_machine(machine[0])
                if not machine_details.platform == platform:
                    return render(request, "error.html",
                                  {"error": "Wrong platform, {} VM selected for {} sample".format(
                                       machine_details.platform, platform)})
                else:
                    task_machines = [machine]
            else:
                task_machines = ["first"]

            for entry in task_machines:
                if entry == "first":
                    entry = None
                task_ids_new = db.demux_sample_and_add_to_db(file_path=path, package=package, timeout=timeout,
                                                             options=options, priority=priority, machine=entry,
                                                             custom=custom, memory=memory,
                                                             enforce_timeout=enforce_timeout, tags=tags,
                                                             platform=platform, clock=clock)
                if task_ids_new:
                    task_ids.extend(task_ids_new)

        elif settings.VTDL_ENABLED and "vtdl" in request.POST and request.POST.get("vtdl", False) \
                and request.POST.get("vtdl")[0] != '':
            vtdl = request.POST.get("vtdl").strip()
            if (not settings.VTDL_PRIV_KEY and not settings.VTDL_INTEL_KEY) or not settings.VTDL_PATH:
                    return render(request, "error.html",
                                  {"error": "You specified VirusTotal but must edit the file and specify your "
                                            "VTDL_PRIV_KEY or VTDL_INTEL_KEY variable and VTDL_PATH base directory"})
            else:
                hashlist = []
                if "," in vtdl:
                    hashlist = [_f for _f in vtdl.replace(" ", "").strip().split(",") if _f]
                else:
                    hashlist.append(vtdl)

                for h in hashlist:
                    base_dir = tempfile.mkdtemp(prefix='cuckoovtdl', dir=settings.VTDL_PATH)
                    task_ids_tmp = list()
                    if opt_filename:
                        filename = base_dir + "/" + opt_filename
                    else:
                        filename = base_dir + "/" + sanitize_filename(h)
                    headers = {}
                    paths = db.sample_path_by_hash(h)
                    content = False
                    if paths:
                        content = get_file_content(paths)
                    if settings.VTDL_PRIV_KEY:
                        headers = {'x-apikey': settings.VTDL_PRIV_KEY}
                    elif settings.VTDL_INTEL_KEY:
                        headers = {'x-apikey': settings.VTDL_INTEL_KEY}
                    url = "https://www.virustotal.com/api/v3/files/{id}/download".format(id = h)
                    params = {}

                    if not content:
                        status, task_ids_tmp = download_file(False, content, request, db, task_ids, url, params,
                                                             headers, "VirusTotal", filename, package, timeout,
                                                             options, priority, machine, clock, custom, memory,
                                                             enforce_timeout, referrer, tags, orig_options, "",
                                                             static, h)
                    else:
                        status, task_ids_tmp = download_file(False, content, request, db, task_ids, url, params,
                                                             headers, "Local", filename, package, timeout, options,
                                                             priority, machine, clock, custom, memory, enforce_timeout,
                                                             referrer, tags, orig_options, "", static, h)
                    if status is "ok":
                        task_ids = task_ids_tmp
                    else:
                        failed_hashes.append(h)

        if not isinstance(task_ids, list) and status == "error":
            # is render msg
            return task_ids
        if not isinstance(task_ids_tmp, list) and status == "error":
            # is render msg
            return task_ids_tmp
        if isinstance(task_ids, list):
            tasks_count = len(task_ids)
        else:
            # ToDo improve error msg
            tasks_count = 0
        tasks_count = len(task_ids)
        if tasks_count > 0:
            data = {"tasks": task_ids, "tasks_count": tasks_count}
            if failed_hashes:
                data["failed_hashes"] = failed_hashes
            return render(request, "submission/complete.html", data)

        else:
            return render(request, "error.html", {"error": "Error adding task to Cuckoo's database."})
    else:
        enabledconf = dict()
        enabledconf["vt"] = settings.VTDL_ENABLED
        enabledconf["kernel"] = settings.OPT_ZER0M0N
        enabledconf["memory"] = processing.memory.get("enabled")
        enabledconf["procmemory"] = processing.procmemory.get("enabled")
        enabledconf["dlnexec"] = settings.DLNEXEC
        enabledconf["tags"] = False
        enabledconf["dist_master_storage_only"] = repconf.distributed.master_storage_only

        all_tags = load_vms_tags()
        if all_tags:
            enabledconf["tags"] = True

        if not enabledconf["tags"]:
            # load multi machinery tags:
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

        return render(request, "submission/index.html",
                      {"packages": sorted(packages),
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
                       "tags": sorted(list(set(all_tags)))})


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def status(request, task_id):
    task = db.view_task(task_id)
    if not task:
        return render(request, "error.html", {"error": "The specified task doesn't seem to exist."})

    completed = False
    if task.status == "reported":
        return redirect('report', task_id=task_id)

    status = task.status
    if status == "completed":
        status = "processing"

    return render(request, "submission/status.html", {"completed" : completed, "status" : status, "task_id" : task_id})
