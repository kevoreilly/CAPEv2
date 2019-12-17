
from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import json
import magic
import logging
import hashlib
import requests

from random import choice

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))
sys.path.append(CUCKOO_ROOT)

from django.http import HttpResponse
from django.shortcuts import redirect, render
from lib.cuckoo.common.config import Config
from lib.cuckoo.core.rooter import _load_socks5_operational
from lib.cuckoo.common.utils import get_ip_address


cfg = Config("cuckoo")
socks5_conf = Config("socks5")
machinery = Config(cfg.cuckoo.machinery)
disable_x64 = cfg.cuckoo.get("disable_x64", False)

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

try:
   import pefile
   HAVE_PEFILE = True
except ImportError:
   HAVE_PEFILE = False

log = logging.getLogger(__name__)

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

# Same jsonize function from api.py except we can now return Django
# HttpResponse objects as well. (Shortcut to return errors)
def jsonize(data, response=False):
    """Converts data dict to JSON.
    @param data: data dict
    @return: JSON formatted data or HttpResponse object with json data
    """
    if response:
        jdata = json.dumps(data, sort_keys=False, indent=4)
        return HttpResponse(jdata,
                            content_type="application/json; charset=UTF-8")
    else:
        return json.dumps(data, sort_keys=False, indent=4)


def get_file_content(paths):
    content = False
    for path in paths:
        if os.path.exists(path):
            with open(path, "rb") as f:
                content = f.read()
            break
    return content


def fix_section_permission(path):
   if HAVE_PEFILE:
       try:
           pe = pefile.PE(path)
           for id in range(len(pe.sections)):
               if pe.sections[id].Name.rstrip("\0") == ".rdata" and hex(pe.sections[id].Characteristics)[:3] == "0x4":
                   log.info("section found")
                   pe.sections[id].Characteristics += pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]
                   log.info(pe.sections[id].Characteristics)
                   pe.write(filename=path)
           pe.close()
           log.info("close")
       except Exception as e:
           log.info(e)
   else:
       log.info("[-] Missed dependency pefile")


# Submission hooks to set options based on some naming patrons
def recon(filename, orig_options, timeout, enforce_timeout):
    filename = filename.lower()
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


# Func to download from services
def download_file(api, content, request, db, task_ids, url, params, headers, service, filename, package, timeout, options, priority, machine, clock, custom, memory, enforce_timeout, referrer, tags, orig_options, task_machines, static, fhash=False):
    onesuccess = False
    if not content:
        try:
            r = requests.get(url, params=params, headers=headers, verify=False)
        except requests.exceptions.RequestException as e:
            logging.error(e)
            if api:
                return "error", jsonize({"error": "Provided hash not found on {}".format(service)}, response=True)
            else:
                return "error", render(request, "error.html", {"error":  "Provided hash not found on {}".format(service)})

        if r.status_code == 200 and r.content != b"Hash Not Present" and b"The request requires higher privileges than provided by the access token" not in r.content:
            content = r.content
        elif r.status_code == 403:
            if api:
                return "error", jsonize({"error": "API key provided is not a valid {0} key or is not authorized for {0} downloads".format(service)}, response=True)
            else:
                return "error", render(request, "error.html", {"error": "API key provided is not a valid {0} key or is not authorized for {0} downloads".format(service)})
        else:
            if api:
                return "error", jsonize({"error": "Was impossible to download from {0}".format(service)}, response=True)
            else:
                return "error", render(request, "error.html", {"error": "Was impossible to download from {0}".format(service)})

    if not content:
        if api:
            return "error", jsonize({"error": "Error downloading file from {}".format(service)}, response=True)
        else:
            return "error", render(request, "error.html", {"error": "Error downloading file from {}".format(service)})

    try:
        if fhash:
            retrieved_hash = hashes[len(fhash)](content).hexdigest()
            if retrieved_hash != fhash.lower():
                if api:
                    return "error", jsonize({"error": "Hashes mismatch, original hash: {} - retrieved hash: {}".format(fhash, retrieved_hash)}, response=True)
                else:
                    return "error", render(request, "error.html", {"error": "Hashes mismatch, original hash: {} - retrieved hash: {}".format(fhash, retrieved_hash)})

        f = open(filename, 'wb')
        f.write(content)
        f. close()
    except:
        if api:
            return "error", jsonize({"error": "Error writing {} download file to temporary path".format(service)}, response=True)
        else:
            return "error", render(request, "error.html", {"error": "Error writing {} download file to temporary path".format(service)})

    onesuccess = True
    if filename:
        if disable_x64 is True:
            magic_type = get_magic_type(filename)
            if magic_type and ("x86-64" in magic_type or "PE32+" in magic_type):
                if len(request.FILES) == 1:
                    return "error", render(request, "error.html", {"error": "Sorry no x64 support yet"})

    orig_options, timeout, enforce_timeout = recon(filename, orig_options, timeout, enforce_timeout)
    for entry in task_machines:
        #ToDo find the root of the problem, vt vs resubmit as example
        if isinstance(filename, str):
            filename = filename.encode("utf-8")
        task_ids_new = db.demux_sample_and_add_to_db(file_path=filename, package=package, timeout=timeout, options=options, priority=priority,
                                                        machine=entry, custom=custom, memory=memory, enforce_timeout=enforce_timeout, tags=tags, clock=clock, static=static)
        if isinstance(task_ids, list):
            task_ids.extend(task_ids_new)

    if not onesuccess:
        if api:
            return "error", jsonize({"error": "Provided hash not found on {}".format(service)}, response=True)
        else:
            return "error", render(request, "error.html", {"error": "Provided hash not found on {}".format(service)})
    return "ok", task_ids


def _download_file(route, url, options):
    socks5s = _load_socks5_operational()
    proxies = dict()
    response = False
    headers = {
        "User-Agent": choice(user_agents)
    }

    print(socks5s)
    if route:
        if route == "tor":
            proxies = {
                "http": "socks5://127.0.0.1:9050",
                "https": "socks5://127.0.0.1:9050",
            }

        elif route in socks5s:
            proxies={
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
