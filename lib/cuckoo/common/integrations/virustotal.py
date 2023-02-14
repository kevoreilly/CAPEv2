# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import logging
import operator
from collections import defaultdict

import requests

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.utils import add_family_detection

try:
    import re2 as re
except ImportError:
    import re

log = logging.getLogger(__name__)

VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/api/v3/files/{id}"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/api/v3/urls/{id}"

processing_conf = Config("processing")

key = processing_conf.virustotal.key
do_file_lookup = processing_conf.virustotal.get("do_file_lookup", False)
do_url_lookup = processing_conf.virustotal.get("do_url_lookup", False)
urlscrub = processing_conf.virustotal.urlscrub
timeout = int(processing_conf.virustotal.timeout)
remove_empty = processing_conf.virustotal.remove_empty

headers = {"x-apikey": key}

"""
from modules.processing.virustotal import vt_lookup
res = vt_lookup("file", "d17f3c491d68d8cb37c37752689bdca8c2664a2bc305530e2e2beb3704fcca4b", on_demand=True)
"""

banlist = (
    "other",
    "troj",
    "trojan",
    "win32",
    "trojandownloader",
    "trojandropper",
    "dropper",
    "tsgeneric",
    "malware",
    "dldr",
    "downloader",
    "injector",
    "agent",
    "nsis",
    "genetic",
    "generik",
    "generic",
    "generickd",
    "genericgb",
    "generickdz",
    "behaveslike",
    "heur",
    "inject2",
    "trojanspy",
    "trojanpws",
    "reputation",
    "script",
    "score",
    "w97m",
    "pp97m",
    "lookslike",
    "macro",
    "dloadr",
    "kryptik",
    "graftor",
    "artemis",
    "zbot",
    "w2km",
    "docdl",
    "variant",
    "packed",
    "trojware",
    "worm",
    "backdoor",
    "email",
    "obfuscated",
    "cryptor",
    "obfus",
    "virus",
    "xpack",
    "crypt",
    "rootkit",
    "malwares",
    "malicious",
    "suspicious",
    "riskware",
    "risk",
    "win64",
    "troj64",
    "drop",
    "hacktool",
    "exploit",
    "msil",
    "inject",
    "dropped",
    "program",
    "unwanted",
    "heuristic",
    "patcher",
    "tool",
    "potentially",
    "rogue",
    "keygen",
    "unsafe",
    "application",
    "risktool",
    "multi",
    "msoffice",
    "ransom",
    "autoit",
    "yakes",
    "java",
    "ckrf",
    "html",
    "bngv",
    "bnaq",
    "o97m",
    "blqi",
    "bmbg",
    "mikey",
    "kazy",
    "x97m",
    "msword",
    "cozm",
    "eldorado",
    "fakems",
    "cloud",
    "stealer",
    "dangerousobject",
    "symmi",
    "zusy",
    "dynamer",
    "obfsstrm",
    "krypt",
    "lazy",
    "linux",
    "unix",
    "ftmn",
)


def get_vt_consensus(namelist: list):

    finaltoks = defaultdict(int)
    for name in namelist:
        toks = re.findall(r"[A-Za-z0-9]+", name)
        for tok in toks:
            finaltoks[tok.title()] += 1
    for tok in list(finaltoks):
        lowertok = tok.lower()
        accepted = True
        numlist = [x for x in tok if x.isdigit()]
        if len(numlist) > 2 or len(tok) < 4:
            accepted = False
        if accepted:
            for black in banlist:
                if black == lowertok:
                    accepted = False
                    break
        if not accepted:
            del finaltoks[tok]

    sorted_finaltoks = sorted(list(finaltoks.items()), key=operator.itemgetter(1), reverse=True)
    if len(sorted_finaltoks) == 1 and sorted_finaltoks[0][1] >= 2:
        return sorted_finaltoks[0][0]
    elif len(sorted_finaltoks) > 1 and (sorted_finaltoks[0][1] >= sorted_finaltoks[1][1] * 2 or sorted_finaltoks[0][1] > 8):
        return sorted_finaltoks[0][0]
    elif len(sorted_finaltoks) > 1 and sorted_finaltoks[0][1] == sorted_finaltoks[1][1] and sorted_finaltoks[0][1] > 2:
        return sorted_finaltoks[0][0]
    return ""


# https://developers.virustotal.com/v3.0/reference#file-info
def vt_lookup(category: str, target: str, results: dict = {}, on_demand: bool = False):
    if not processing_conf.virustotal.enabled or processing_conf.virustotal.get("on_demand", False) and not on_demand:
        return {}
    if category not in ("file", "url"):
        return {"error": True, "msg": "VT category isn't supported"}

    if category == "file":
        if not do_file_lookup:
            return {"error": True, "msg": "VT File lookup disabled in processing.conf"}
        if not path_exists(target) and len(target) != 64:
            return {"error": True, "msg": "File doesn't exist"}

        sha256 = target if len(target) == 64 else File(target).get_sha256()
        url = VIRUSTOTAL_FILE_URL.format(id=sha256)

    elif category == "url":
        if not do_url_lookup:
            return {"error": True, "msg": "VT URL lookup disabled in processing.conf"}
        if urlscrub:
            urlscrub_compiled_re = None
            try:
                urlscrub_compiled_re = re.compile(urlscrub)
            except Exception as e:
                log.error(f"Failed to compile urlscrub regex: {e}")
                return {}
            try:
                target = re.sub(urlscrub_compiled_re, "", target)
            except Exception as e:
                return {"error": True, "msg": f"Failed to scrub url: {e}"}

        # normalize the URL the way VT appears to
        if not target.lower().startswith(("http://", "https://")):
            target = f"http://{target}"
        slashsplit = target.split("/")
        slashsplit[0] = slashsplit[0].lower()
        slashsplit[2] = slashsplit[2].lower()
        if len(slashsplit) == 3:
            slashsplit.append("")
        target = "/".join(slashsplit)

        sha256 = hashlib.sha256(target.encode()).hexdigest()
        url = VIRUSTOTAL_URL_URL.format(id=target)

    try:
        r = requests.get(url, headers=headers, verify=True, timeout=timeout)
        if not r.ok:
            return {"error": True, "msg": f"Unable to complete connection to VirusTotal. Status code: {r.status_code}"}
        vt_response = r.json()
        engines = vt_response.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
        if not engines:
            return {}
        virustotal = {
            "names": vt_response.get("data", {}).get("attributes", {}).get("names"),
            "scan_id": vt_response.get("data", {}).get("id"),
            "md5": vt_response.get("data", {}).get("attributes", {}).get("md5"),
            "sha1": vt_response.get("data", {}).get("attributes", {}).get("sha1"),
            "sha256": vt_response.get("data", {}).get("attributes", {}).get("sha256"),
            "tlsh": vt_response.get("data", {}).get("attributes", {}).get("tlsh"),
            "positives": vt_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious"),
            "total": len(engines.keys()),
            "permalink": vt_response.get("data", {}).get("links", {}).get("self"),
        }
        if remove_empty:
            virustotal["scans"] = {engine.replace(".", "_"): block for engine, block in engines.items() if block["result"]}
        else:
            virustotal["scans"] = {engine.replace(".", "_"): block for engine, block in engines.items()}

        virustotal["resource"] = sha256
        virustotal["results"] = []
        detectnames = []
        for engine, block in engines.items():
            virustotal["results"] += [{"vendor": engine.replace(".", "_"), "sig": block["result"]}]
            if block["result"] and "Trojan.Heur." not in block["result"]:
                # weight Microsoft's detection, they seem to be more accurate than the rest
                if engine == "Microsoft":
                    detectnames.append(block["result"])
                detectnames.append(block["result"])

        virustotal["detection"] = get_vt_consensus(detectnames)
        if virustotal.get("detection", False) and results:
            add_family_detection(results, virustotal["detection"], "VirusTotal", virustotal["sha256"])
        if virustotal.get("positives", False) and virustotal.get("total", False):
            virustotal["summary"] = f"{virustotal['positives']}/{virustotal['total']}"

        return virustotal
    except requests.exceptions.RequestException as e:
        return {
            "error": True,
            "msg": f"Unable to complete connection to VirusTotal: {e}",
        }

    return {}
