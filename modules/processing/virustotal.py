# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import json
import logging
import requests
import hashlib

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.objects import File

VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/vtapi/v2/file/report"
VIRUSTOTAL_URL_URL = "https://www.virustotal.com/vtapi/v2/url/report"


class VirusTotal(Processing):
    """Gets antivirus signatures from VirusTotal.com"""

    def getbool(self, s):
        if isinstance(s, bool):
            rtn = s
        else:
            try:
                rtn = s.lower() in ("yes", "true", "1")
            except:
                rtn = False
        return rtn

    def run(self):
        """Runs VirusTotal processing
        @return: full VirusTotal report.
        """
        self.key = "virustotal"
        virustotal = []

        key = self.options.get("key", None)
        timeout = self.options.get("timeout", 60)
        urlscrub = self.options.get("urlscrub", None)
        do_file_lookup = self.getbool(self.options.get("do_file_lookup", False))
        do_url_lookup = self.getbool(self.options.get("do_url_lookup", False))

        if not key:
            raise CuckooProcessingError("VirusTotal API key not configured, skip")

        if self.task["category"] == "file" and do_file_lookup:
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("File {0} not found, skipping it".format(self.file_path))

            resource = File(self.file_path).get_sha256()
            url = VIRUSTOTAL_FILE_URL

        elif self.task["category"] == "url" and do_url_lookup:
            resource = self.task["target"]
            if urlscrub:
                urlscrub_compiled_re = None
                try:
                    urlscrub_compiled_re = re.compile(urlscrub)
                except Exception as e:
                    raise CuckooProcessingError("Failed to compile urlscrub regex" % (e))
                try:
                    resource = re.sub(urlscrub_compiled_re, "", resource)
                except Exception as e:
                    raise CuckooProcessingError("Failed to scrub url" % (e))

            # normalize the URL the way VT appears to
            if not resource.lower().startswith("http://") and not resource.lower().startswith("https://"):
                resource = "http://" + resource
            slashsplit = resource.split("/")
            slashsplit[0] = slashsplit[0].lower()
            slashsplit[2] = slashsplit[2].lower()
            if len(slashsplit) == 3:
                slashsplit.append("")
            resource = "/".join(slashsplit)
            try:
                resource = hashlib.sha256(resource.encode("utf-8")).hexdigest()
            except TypeError as e:
                logging.error(e, exc_info=True)
                return virustotal
            url = VIRUSTOTAL_URL_URL
        else:
            # Not supported type, exit.
            return virustotal

        data = {"resource": resource, "apikey": key}

        try:
            r = requests.get(url, params=data, verify=True, timeout=int(timeout))
            response_data = r.content
        except requests.exceptions.RequestException as e:
            raise CuckooProcessingError("Unable to complete connection to VirusTotal: {0}".format(e))

        if not response_data:
            return virustotal

        try:
            virustotal = json.loads(response_data)
        except ValueError as e:
            raise CuckooProcessingError("Unable to convert response to JSON: {0}".format(e))

        # Work around VT brain-damage
        if isinstance(virustotal, list) and len(virustotal):
            virustotal = virustotal[0]

        if "scans" in virustotal:
            items = list(virustotal["scans"].items())
            virustotal["scans"] = dict((engine.replace(".", "_"), signature) for engine, signature in items)
            virustotal["resource"] = resource
            virustotal["results"] = list(({"vendor": engine.replace(".", "_"), "sig": signature["result"]}) for engine, signature in items)
        return virustotal
