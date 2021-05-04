# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import requests
import hashlib

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.utils import get_vt_consensus
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.config import Config

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

# https://developers.virustotal.com/v3.0/reference#file-info
def vt_lookup(category, target, on_demand=False):
    if processing_conf.virustotal.enabled and (processing_conf.virustotal.get("on_demand", False) is False or on_demand is True):

        if category not in ("file", "url"):
            return {"error": True, "msg": "VT category isn't supported"}

        if category == "file":
            if not do_file_lookup:
                return {"error": True, "msg": "VT File lookup disabled in processing.conf"}
            if not os.path.exists(target):
                return {"error": True, "msg": "File doesn't exist"}

            sha256 = File(target).get_sha256()
            url = VIRUSTOTAL_FILE_URL.format(id=sha256)

        elif category == "url":
            if not do_url_lookup:
                return {"error": True, "msg": "VT URL lookup disabled in processing.conf"}
            if urlscrub:
                urlscrub_compiled_re = None
                try:
                    urlscrub_compiled_re = re.compile(urlscrub)
                except Exception as e:
                    raise CuckooProcessingError("Failed to compile urlscrub regex" % (e))
                try:
                    target = re.sub(urlscrub_compiled_re, "", target)
                except Exception as e:
                    return {"error": True, "msg": "Failed to scrub url" % (e)}

            # normalize the URL the way VT appears to
            if not target.lower().startswith("http://") and not target.lower().startswith("https://"):
                target = "http://" + target
            slashsplit = target.split("/")
            slashsplit[0] = slashsplit[0].lower()
            slashsplit[2] = slashsplit[2].lower()
            if len(slashsplit) == 3:
                slashsplit.append("")
            target = "/".join(slashsplit)

            sha256 = hashlib.sha256(target.encode("utf-8")).hexdigest()
            url = VIRUSTOTAL_URL_URL.format(id=target)

        try:
            r = requests.get(url, headers=headers, verify=True, timeout=timeout)
            if r.ok:
                vt_response = r.json()
                engines = vt_response.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
                if engines:
                    virustotal = {}
                    virustotal["names"] = vt_response.get("data", {}).get("attributes", {}).get("names")
                    virustotal["scan_id"] = vt_response.get("data", {}).get("id")
                    virustotal["md5"] = vt_response.get("data", {}).get("attributes", {}).get("md5")
                    virustotal["sha1"] = vt_response.get("data", {}).get("attributes", {}).get("sha1")
                    virustotal["sha256"] = vt_response.get("data", {}).get("attributes", {}).get("sha256")
                    virustotal["tlsh"] = vt_response.get("data", {}).get("attributes", {}).get("tlsh")
                    virustotal["possitive"] = (
                        vt_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious")
                    )
                    virustotal["total"] = len(engines.keys())
                    virustotal["permalink"] = vt_response.get("data", {}).get("links", {}).get("self")
                    virustotal["scans"] = dict((engine.replace(".", "_"), block) for engine, block in engines.items() if remove_empty and block["result"])
                    virustotal["resource"] = sha256

                    virustotal["results"] = list()
                    detectnames = list()
                    for engine, block in engines.items():
                        virustotal["results"] += [{"vendor": engine.replace(".", "_"), "sig": block["result"]}]
                        if block["result"] and "Trojan.Heur." not in block["result"]:
                            # weight Microsoft's detection, they seem to be more accurate than the rest
                            if engine == "Microsoft":
                                detectnames.append(block["result"])
                            detectnames.append(block["result"])

                    virustotal["detection"] = get_vt_consensus(detectnames)
                    return virustotal
                else:
                    return dict()
            else:
                return {"error": True, "msg": "Unable to complete connection to VirusTotal. Status code: {}".format(r.status_code)}
        except requests.exceptions.RequestException as e:
            return {"error": True, "msg": "Unable to complete connection to VirusTotal: {0}".format(e)}
    else:
        return dict()


class VirusTotal(Processing):
    """Gets antivirus signatures from VirusTotal.com"""

    def run(self):
        """Runs VirusTotal processing
        @return: full VirusTotal report.
        """
        self.key = "virustotal"

        if not key:
            raise CuckooProcessingError("VirusTotal API key not configured, skip")

        if processing_conf.virustotal.get("on_demand", False):
            log.debug("VT on_demand enabled, returning")
            return dict()

        target = False
        if self.task["category"] == "file" and do_file_lookup:
            target = self.file_path
        elif self.task["category"] == "url" and do_url_lookup:
            target = self.task["target"]
        else:
            # Not supported type, exit.
            return dict()

        vt_response = vt_lookup(self.task["category"], target)
        if "error" in vt_response:
            raise CuckooProcessingError(vt_response["msg"])

        return vt_response
