# encoding: utf-8
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import ast
import logging
import os
import random
import sys
import tempfile
import textwrap
from base64 import urlsafe_b64encode
from contextlib import suppress

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

sys.path.append(settings.CUCKOO_PATH)
from uuid import NAMESPACE_DNS, uuid3

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_mkdir
from lib.cuckoo.common.saztopcap import saz_to_pcap
from lib.cuckoo.common.utils import get_options, get_user_filename, sanitize_filename, store_temp_file
from lib.cuckoo.common.web_utils import (
    download_file,
    download_from_bazaar,
    download_from_vt,
    get_file_content,
    load_vms_exits,
    load_vms_tags,
    parse_request_arguments,
    perform_search,
    process_new_dlnexec_task,
    process_new_task_files,
)
from lib.cuckoo.core.database import Database
from lib.cuckoo.core.rooter import _load_socks5_operational, vpns

# this required for hash searches
cfg = Config("cuckoo")
routing = Config("routing")
repconf = Config("reporting")
distconf = Config("distributed")
processing = Config("processing")
aux_conf = Config("auxiliary")
web_conf = Config("web")

db = Database()

from urllib3 import disable_warnings

disable_warnings()

logger = logging.getLogger(__name__)


def parse_expr(expr, context):
    """Return the value from a python AST expression.

    Recursive! the initial call is the right hand side of an assignment.
    Recursion is necessary because the expression is made up of a variable number
    of subexpressions, sub-subexpressions, etc.
    """
    if isinstance(expr, str):
        return expr
    if isinstance(expr, ast.Constant):
        return expr.value
    if isinstance(expr, ast.Name):
        # To get the value associated with the variable name, look up name (expr.id) in context.
        # If lookup fails (we do not know the value of the variable), return the name.
        return context.get(expr.id, str(expr.id))
    if isinstance(expr, ast.List):
        return [parse_expr(item, context) for item in expr.elts]
    if isinstance(expr, ast.Tuple):
        return tuple([parse_expr(item, context) for item in expr.elts])
    if isinstance(expr, ast.JoinedStr):
        # JoinedStr - coerce each item to string, and join them.
        return "".join([str(parse_expr(item, context)) for item in expr.values])
    if isinstance(expr, ast.FormattedValue):
        return parse_expr(expr.value, context)
    if isinstance(expr, ast.Attribute):
        # Join expr.value to expr.attr with a "." between. Example: os.path.join
        return parse_expr(expr.value, context) + "." + parse_expr(expr.attr, context)
    if isinstance(expr, ast.Call):
        # Figure out what function is being called, with what arguments.
        func = parse_expr(expr.func, context)
        args = tuple([parse_expr(item, context) for item in expr.args])
        # We deem these functions safe to use with "eval".
        allowed_functions = ("sorted", "set", "os.path.join")
        if func in allowed_functions:
            # Actually call the function, passing the args, and return the result.
            return eval(f"{func}{args}")
        # Don't execute the call, but instead, give back a string representation.
        return f"<{func}{args}>"
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        left = parse_expr(expr.left, context)
        right = parse_expr(expr.right, context)
        try:
            ans = left + right
        except TypeError:
            # Expected behavior during unit tests
            ans = str(left) + str(right)
        return ans
    # Not expected to reach this, but should aid in debugging if found.
    return f"?? Unexpected type({type(expr)}) in parse_expr()"


def parse_ast(items, context=None):
    """Look at each item in a list of ast elements.

    Item type ast.Assign signifies a statement of the form 'name = value'.
    Work out the value using parse_expr.
    Add an entry of the form 'name' = value to the context dictionary.
    """
    if not context:
        context = dict()
    for item in items:
        if isinstance(item, ast.Assign):
            key = item.targets[0].id
            context[key] = parse_expr(item.value, context)
    return context


def get_lib_common_constants(platform):
    """Extract constants from lib.common.constants into a dict"""
    constant_file = os.path.join(settings.CUCKOO_PATH, "analyzer", platform, "lib", "common", "constants.py")
    with open(constant_file, "r") as f:
        contents = f.read()
    tr = ast.parse(contents)
    the_dict = parse_ast(tr.body)
    return the_dict


def get_package_info(dir_name, filename, platform, common_context):
    """Find out everything we can about the package."""
    default_summary = f"Package {filename} has no summary"
    default_description = f"Package {filename} has no description"
    # Clear out previous package description etc.
    to_delete = ("summary", "description", "option_names")
    for item in to_delete:
        if item in common_context:
            del common_context[item]
    with open(os.path.join(dir_name, filename), "r") as f:
        contents = f.read()
    tr = ast.parse(contents)
    expanded_context = parse_ast(tr.body, common_context)
    classes = [item for item in tr.body if isinstance(item, ast.ClassDef) and item.bases and item.bases[0].id == "Package"]
    if classes:
        classname = classes[0].name
        assignments = parse_ast(classes[0].body, expanded_context)
    else:
        # No class inherited from 'Package'
        classname = "unknown classname"
        assignments = dict()
    summary = assignments.get("summary", default_summary)
    description = textwrap.dedent(assignments.get("description", default_description))
    option_names = assignments.get("option_names", ())
    if option_names:
        description = description + f"\nOPTIONS: {option_names}"
    result = {
        "name": os.path.splitext(filename)[0],
        "value": os.path.splitext(filename)[0],
        "classname": classname,
        "platform": platform,
        "summary": summary,
        "description": description,
        "option_names": option_names,
    }
    return result


def get_enabled_platforms():
    """Return a list of enabled platforms.

    We are going to assume that the windows platform is first in the list."""
    platforms = ["windows"]
    if web_conf.linux.enabled:
        platforms.append("linux")
    return platforms


def correlate_platform_packages(platform_package_dict):
    """Given a per-platform dictionary, return a single list of all packages"""
    package_names = set()
    result = []
    for platform in get_enabled_platforms():
        for package in platform_package_dict.get(platform, []):
            package_name = package["name"].lower()
            if package_name not in package_names:
                package_names.add(package_name)
                if platform != "windows":
                    # The windows analyzer package list did not contain this package name.
                    package["name"] = package["name"] + f" ({platform} only)"
                result.append(package)
    return result


def get_form_data():
    """Return data about packages and machines to help build the submission form."""
    platforms = get_enabled_platforms()

    platform_packages = dict()
    for platform in platforms:
        common_context = get_lib_common_constants(platform)
        package_root = os.path.join(settings.CUCKOO_PATH, "analyzer", platform, "modules", "packages")
        files = [item.name for item in os.scandir(package_root) if item.is_file() and not item.name.startswith(".")]
        exclusions = [package.strip() + ".py" for package in web_conf.package_exclusion.packages.split(",")]

        exclusions.append("__init__.py")

        platform_packages[platform] = [
            get_package_info(package_root, name, platform, common_context) for name in files if name not in exclusions
        ]
    packages = correlate_platform_packages(platform_packages)

    # Prepare a list of VM names, description label based on tags.
    machines = []
    for machine in db.list_machines():
        tags = [tag.name for tag in machine.tags]

        label = f"{machine.label}:{machine.arch}"
        if tags:
            label = f"{label}:{','.join(tags)}"

        if web_conf.linux.enabled:
            label = machine.platform + ":" + label

        machines.append((machine.label, label))

    # Prepend ALL/ANY options. Disable until a platform can be verified in scheduler
    machines.insert(0, ("", "First available"))
    if web_conf.all_vms.enabled:
        machines.insert(1, ("all", "All"))

    return packages, machines


# Conditional decorator for web authentication
class conditional_login_required:
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
    except Exception:
        value = 0
    finally:
        return value


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def index(request, task_id=None, resubmit_hash=None):
    remote_console = False
    if request.method == "POST":
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
        ) = parse_request_arguments(request)

        # This is done to remove spaces in options but not breaks custom paths
        options = ",".join(
            "=".join(value.strip() for value in option.split("=", 1)) for option in options.split(",") if option and "=" in option
        )
        opt_filename = get_user_filename(options, custom)

        if priority and web_conf.public.enabled and web_conf.public.priority and not request.user.is_staff:
            priority = web_conf.public.priority

        if timeout and web_conf.public.enabled and web_conf.public.timeout and not request.user.is_staff:
            timeout = web_conf.public.timeout

        if options:
            options += ","

        if referrer:
            options += "referrer=%s," % (referrer)

        if request.POST.get("free"):
            options += "free=yes,"

        if request.POST.get("nohuman"):
            options += "nohuman=yes,"

        if request.POST.get("mitmdump"):
            options += "mitmdump=yes,"

        if web_conf.guacamole.enabled and request.POST.get("interactive"):
            remote_console = True
            options += "interactive=1,"
            if "nohuman=yes," not in options:
                options += "nohuman=yes,"
            if request.POST.get("manual"):
                options += "manual=1,"

        if request.POST.get("tor"):
            options += "tor=yes,"

        if request.POST.get("process_dump"):
            options += "procdump=0,"

        if request.POST.get("process_memory"):
            options += "procmemdump=1,"

        if request.POST.get("import_reconstruction"):
            options += "import_reconstruction=1,"

        if request.POST.get("unpacker"):
            options += "unpacker=2,"

        if not request.POST.get("syscall"):
            options += "syscall=0,"

        if request.POST.get("kernel_analysis"):
            options += "kernel_analysis=yes,"

        if request.POST.get("norefer"):
            options += "norefer=1,"

        if request.POST.get("oldloader"):
            options += "no-iat=1,"

        if request.POST.get("unpack"):
            options += "unpack=yes,"

        job_category = False
        if request.POST.get("job_category"):
            job_category = request.POST.get("job_category")

        # amsidump is enabled by default in the monitor for Win10+
        if web_conf.amsidump.enabled and not request.POST.get("amsidump"):
            options += "amsidump=0,"

        options = options[:-1]

        opt_apikey = False
        opts = get_options(options)
        if opts:
            opt_apikey = opts.get("apikey", False)

        status = "ok"
        existent_tasks = {}
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
            "package": package,
        }
        task_category = False
        samples = []
        if "hash" in request.POST and request.POST.get("hash", False) and request.POST.get("hash")[0] != "":
            task_category = "resubmit"
            samples = request.POST.get("hash").strip().split(",")
        elif "sample" in request.FILES:
            task_category = "sample"
            samples = request.FILES.getlist("sample")
        elif "static" in request.FILES:
            task_category = "static"
            samples = request.FILES.getlist("static")
        elif "pcap" in request.FILES:
            task_category = "pcap"
            samples = request.FILES.getlist("pcap")
        elif "url" in request.POST and request.POST.get("url").strip():
            task_category = "url"
            samples = request.POST.get("url").strip()
        elif "dlnexec" in request.POST and request.POST.get("dlnexec").strip():
            task_category = "dlnexec"
            samples = request.POST.get("dlnexec").strip()
        elif (
            settings.VTDL_ENABLED
            and "vtdl" in request.POST
            and request.POST.get("vtdl", False)
            and request.POST.get("vtdl")[0] != ""
        ):
            task_category = "vtdl"
            samples = request.POST.get("vtdl").strip()
        elif "bazaar" in request.POST and request.POST.get("bazaar").strip():
            task_category = "bazaar"
            samples = request.POST.get("bazaar").strip()

        list_of_tasks = []
        if task_category in ("url", "dlnexec"):
            if not samples:
                return render(request, "error.html", {"error": "You specified an invalid URL!"})

            for url in samples.split(","):
                url = url.replace("hxxps://", "https://").replace("hxxp://", "http://").replace("[.]", ".")
                if task_category == "dlnexec":
                    path, content, sha256 = process_new_dlnexec_task(url, route, options, custom)
                    if path:
                        list_of_tasks.append((content, path, sha256))
                elif task_category == "url":
                    list_of_tasks.append(("", url, ""))

        elif task_category in ("sample", "static", "pcap"):
            list_of_tasks, details = process_new_task_files(request, samples, details, opt_filename, unique)

        elif task_category == "resubmit":
            for hash in samples:
                paths = []
                if len(hash) in (32, 40, 64):
                    paths = db.sample_path_by_hash(hash)
                else:
                    task_binary = os.path.join(settings.CUCKOO_PATH, "storage", "analyses", str(task_id), "binary")
                    if path_exists(task_binary):
                        paths.append(task_binary)
                    else:
                        tmp_paths = db.find_sample(task_id=task_id)
                        if not tmp_paths:
                            details["errors"].append({hash: "Task not found for resubmission"})
                            continue
                        for tmp_sample in tmp_paths:
                            path = False
                            tmp_dict = tmp_sample.to_dict()
                            if path_exists(tmp_dict.get("target", "")):
                                path = tmp_dict["target"]
                            else:
                                tmp_tasks = db.find_sample(sample_id=tmp_dict["sample_id"])
                                for tmp_task in tmp_tasks:
                                    tmp_path = os.path.join(
                                        settings.CUCKOO_PATH, "storage", "binaries", tmp_task.to_dict()["sha256"]
                                    )
                                    if path_exists(tmp_path):
                                        path = tmp_path
                                        break
                            if path:
                                paths.append(path)

                if not paths:
                    for folder_name in ("selfextracted", "files"):
                        # Self Extracted support folder
                        path = os.path.join(settings.CUCKOO_PATH, "storage", "analyses", str(task_id), folder_name, hash)
                        if path_exists(path):
                            paths.append(path)

                if not paths:
                    details["errors"].append({hash: "File not found on hdd for resubmission"})
                    continue

                content = get_file_content(paths)
                if not content:
                    details["errors"].append({hash: f"Can't find {hash} on disk"})
                    continue
                folder = os.path.join(settings.TEMP_PATH, "cape-resubmit")
                if not path_exists(folder):
                    path_mkdir(folder)
                base_dir = tempfile.mkdtemp(prefix="resubmit_", dir=folder)
                if opt_filename:
                    filename = base_dir + "/" + opt_filename
                else:
                    filename = base_dir + "/" + sanitize_filename(hash)
                path = store_temp_file(content, filename)
                list_of_tasks.append((content, path, hash))

        # Hack for resubmit first find all files and then put task as proper category
        if job_category and job_category in ("resubmit", "sample", "static", "pcap", "dlnexec", "vtdl", "bazaar"):
            task_category = job_category

        if task_category == "resubmit":
            for content, path, sha256 in list_of_tasks:
                if web_conf.pre_script.enabled and "pre_script" in request.FILES:
                    pre_script = request.FILES["pre_script"]
                    details["pre_script_name"] = request.FILES["pre_script"].name
                    details["pre_script_content"] = pre_script.read()

                if web_conf.during_script.enabled and "during_script" in request.FILES:
                    during_script = request.FILES["during_script"]
                    details["during_script_name"] = request.FILES["during_script"].name
                    details["during_script_content"] = during_script.read()

                details["path"] = path
                details["content"] = content
                status, tasks_details = download_file(**details)
                if status == "error":
                    details["errors"].append({os.path.basename(filename): tasks_details})
                else:
                    details["task_ids"] = tasks_details.get("task_ids")
                    if tasks_details.get("errors"):
                        details["errors"].extend(tasks_details["errors"])
                    if web_conf.web_reporting.get("enabled", False) and web_conf.general.get("existent_tasks", False):
                        records = perform_search("target_sha256", hash, search_limit=5)
                        if records:
                            for record in records or []:
                                existent_tasks.setdefault(record["target"]["file"]["sha256"], []).append(record)

        elif task_category == "sample":
            details["service"] = "WebGUI"
            for content, path, sha256 in list_of_tasks:
                if web_conf.pre_script.enabled and "pre_script" in request.FILES:
                    pre_script = request.FILES["pre_script"]
                    details["pre_script_name"] = request.FILES["pre_script"].name
                    details["pre_script_content"] = pre_script.read()

                if web_conf.during_script.enabled and "during_script" in request.FILES:
                    during_script = request.FILES["during_script"]
                    details["during_script_name"] = request.FILES["during_script"].name
                    details["during_script_content"] = during_script.read()

                if timeout and web_conf.public.enabled and web_conf.public.timeout and timeout > web_conf.public.timeout:
                    timeout = web_conf.public.timeout

                details["path"] = path
                details["content"] = content
                status, tasks_details = download_file(**details)
                if status == "error":
                    details["errors"].append({os.path.basename(path): tasks_details})
                else:
                    details["task_ids"] = tasks_details.get("task_ids")
                    if tasks_details.get("errors"):
                        details["errors"].extend(tasks_details["errors"])
                    if web_conf.general.get("existent_tasks", False):
                        records = perform_search("target_sha256", sha256, search_limit=5)
                        if records:
                            for record in records:
                                if record.get("target").get("file", {}).get("sha256"):
                                    existent_tasks.setdefault(record["target"]["file"]["sha256"], []).append(record)

        elif task_category == "static":
            for content, path, sha256 in list_of_tasks:
                task_id = db.add_static(file_path=path, priority=priority, tlp=tlp, options=options, user_id=request.user.id or 0)
                if not task_id:
                    return render(request, "error.html", {"error": "We don't have static extractor for this"})
                details["task_ids"] += task_id

        elif task_category == "pcap":
            for content, path, sha256 in list_of_tasks:
                if path.lower().endswith(b".saz"):
                    saz = saz_to_pcap(path)
                    if saz:
                        with suppress(Exception):
                            path_delete(path)
                        path = saz
                    else:
                        details["errors"].append({os.path.basename(path): "Conversion from SAZ to PCAP failed."})
                        continue

                task_id = db.add_pcap(file_path=path, priority=priority, tlp=tlp, user_id=request.user.id or 0)
                if task_id:
                    details["task_ids"].append(task_id)

        elif task_category == "url":
            for _, url, _ in list_of_tasks:
                if machine.lower() == "all":
                    machines = [vm.name for vm in db.list_machines(platform=platform)]
                elif machine:
                    machine_details = db.view_machine(machine)
                    if platform and hasattr(machine_details, "platform") and not machine_details.platform == platform:
                        details["errors"].append(
                            {os.path.basename(url): f"Wrong platform, {machine_details.platform} VM selected for {platform} sample"}
                        )
                        continue
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

        elif task_category == "dlnexec":
            for content, path, sha256 in list_of_tasks:
                details["path"] = path
                details["content"] = content
                details["service"] = "DLnExec"
                details["source_url"] = samples
                status, tasks_details = download_file(**details)
                if status == "error":
                    details["errors"].append({os.path.basename(path): tasks_details})
                else:
                    details["task_ids"] = tasks_details.get("task_ids")
                    if tasks_details.get("errors"):
                        details["errors"].extend(tasks_details["errors"])

        elif task_category == "vtdl":
            if not settings.VTDL_KEY:
                return render(
                    request,
                    "error.html",
                    {"error": "You specified VirusTotal but must edit the file and specify your VTDL_KEY variable"},
                )
            else:
                if opt_apikey:
                    details["apikey"] = opt_apikey
                details = download_from_vt(samples, details, opt_filename, settings)

        elif task_category == "bazaar":
            details = download_from_bazaar(samples, details, opt_filename, settings)

        if details.get("task_ids"):
            tasks_count = len(details["task_ids"])
        else:
            tasks_count = 0
        if tasks_count > 0:
            data = {
                "title": "Submission",
                "tasks": details["task_ids"],
                "tasks_count": tasks_count,
                "errors": details["errors"],
                "existent_tasks": existent_tasks,
                "remote_console": remote_console,
            }
            return render(request, "submission/complete.html", data)
        else:
            err_data = {
                "error": "Error adding task(s) to CAPE's database.",
                "errors": details["errors"],
                "title": "Submission Failure",
            }
            return render(request, "error.html", err_data)
    else:
        enabledconf = {}
        enabledconf["vt"] = settings.VTDL_ENABLED
        enabledconf["bazaar"] = settings.BAZAAR_ENABLED
        enabledconf["kernel"] = settings.OPT_ZER0M0N
        enabledconf["memory"] = processing.memory.get("enabled")
        enabledconf["procmemory"] = processing.procmemory.get("enabled")
        enabledconf["dlnexec"] = settings.DLNEXEC
        enabledconf["url_analysis"] = settings.URL_ANALYSIS
        enabledconf["tags"] = False
        enabledconf["dist_master_storage_only"] = distconf.distributed.master_storage_only
        enabledconf["linux_on_gui"] = web_conf.linux.enabled
        enabledconf["tlp"] = web_conf.tlp.enabled
        enabledconf["timeout"] = cfg.timeouts.default
        enabledconf["amsidump"] = web_conf.amsidump.enabled
        enabledconf["pre_script"] = web_conf.pre_script.enabled
        enabledconf["during_script"] = web_conf.during_script.enabled

        all_vms_tags = load_vms_tags()

        if all_vms_tags:
            enabledconf["tags"] = True

        if not enabledconf["tags"]:
            # load multi machinery tags:
            # Get enabled machinery
            machinery = cfg.cuckoo.get("machinery")
            machinery_tags = "scale_sets" if machinery == "az" else "machines"
            if machinery == "multi":
                for mmachinery in Config(machinery).multi.get("machinery").split(","):
                    vms = [x.strip() for x in getattr(Config(mmachinery), mmachinery).get(machinery_tags).split(",") if x.strip()]
                    if any(["tags" in list(getattr(Config(mmachinery), vmtag).keys()) for vmtag in vms]):
                        enabledconf["tags"] = True
                        break
            else:
                # Get VM names for machinery config elements
                vms = [x.strip() for x in str(getattr(Config(machinery), machinery).get(machinery_tags)).split(",") if x.strip()]
                # Check each VM config element for tags
                if any(["tags" in list(getattr(Config(machinery), vmtag).keys()) for vmtag in vms]):
                    enabledconf["tags"] = True

        packages, machines = get_form_data()

        socks5s = _load_socks5_operational()

        socks5s_random = ""
        vpn_random = ""

        if routing.socks5.random_socks5 and socks5s:
            socks5s_random = socks5s[random.choice(list(socks5s.keys()))]

        if routing.vpn.random_vpn and vpns:
            vpn_random = vpns[random.choice(list(vpns.keys()))]

        random_route = False
        if vpn_random and socks5s_random:
            random_route = random.choice((vpn_random, socks5s_random))
        elif vpn_random:
            random_route = vpn_random
        elif socks5s_random:
            random_route = socks5s_random

        # prepare data for the gui rendering
        if random_route:
            if random_route is vpn_random:
                random_route = {
                    "name": random_route["name"],
                    "description": random_route["description"],
                    "interface": random_route["interface"],
                    "type": "VPN",
                }
            else:
                random_route = {
                    "name": random_route["description"],
                    "host": random_route["host"],
                    "port": random_route["port"],
                    "type": "SOCKS5",
                }
        socks5s_data = [
            {"name": v["description"], "host": v["host"], "port": v["port"], "type": "socks5"} for k, v in socks5s.items()
        ]
        vpns_data = [
            {"name": v["name"], "description": v["description"], "interface": v["interface"], "type": "vpn"} for v in vpns.values()
        ]

        existent_tasks = {}
        if resubmit_hash:
            if web_conf.general.get("existent_tasks", False):
                records = perform_search("target_sha256", resubmit_hash, search_limit=5)
                if records:
                    for record in records:
                        existent_tasks.setdefault(record["target"]["file"]["sha256"], [])
                        existent_tasks[record["target"]["file"]["sha256"]].append(record)

        return render(
            request,
            "submission/index.html",
            {
                "title": "Submit",
                "packages": sorted(packages, key=lambda i: i["name"].lower()),
                "machines": machines,
                "vpns": vpns_data,
                "random_route": random_route,
                "socks5s": socks5s_data,
                "route": routing.routing.route,
                "internet": routing.routing.internet,
                "inetsim": routing.inetsim.enabled,
                "tor": routing.tor.enabled,
                "config": enabledconf,
                "resubmit": resubmit_hash,
                "tags": all_vms_tags,
                "existent_tasks": existent_tasks,
                "all_exitnodes": list(sorted(load_vms_exits())),
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

    response = {
        "title": "Task Status",
        "completed": completed,
        "status": status,
        "task_id": task_id,
        "session_data": "",
        "target": task.sample.sha256 if task.sample.sha256 else task.target,
    }
    if settings.REMOTE_SESSION:
        machine = db.view_machine_by_label(task.machine)
        if machine:
            guest_ip = machine.ip
            session_id = uuid3(NAMESPACE_DNS, task_id).hex[:16]
            session_data = urlsafe_b64encode(f"{session_id}|{task.machine}|{guest_ip}".encode("utf8")).decode("utf8")
            response["session_data"] = session_data

    return render(request, "submission/status.html", response)


@conditional_login_required(login_required, settings.WEB_AUTHENTICATION)
def remote_session(request, task_id):
    task = db.view_task(task_id)
    if not task:
        return render(request, "error.html", {"error": "The specified task doesn't seem to exist."})

    machine_status = False
    session_data = ""

    if task.status == "running":
        machine = db.view_machine(task.machine)
        if not machine:
            return render(request, "error.html", {"error": "Machine is not set for this task."})
        guest_ip = machine.ip
        machine_status = True
        session_id = uuid3(NAMESPACE_DNS, task_id).hex[:16]
        session_data = urlsafe_b64encode(f"{session_id}|{machine.label}|{guest_ip}".encode("utf8")).decode("utf8")

    return render(
        request,
        "submission/remote_status.html",
        {
            "running": machine_status,
            "task_id": task_id,
            "session_data": session_data,
        },
    )
