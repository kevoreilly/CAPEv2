# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com), Cuckoo Foundation
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import json
import os
import urllib.error
import urllib.parse
import urllib.request

import requests
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.objects import File


class CIF(Processing):
    """Queries IP/domain results from CIF server"""

    order = 100

    def getbool(self, s) -> bool:
        if isinstance(s, bool):
            return s
        elif isinstance(s, str):
            return s.lower() in {"yes", "true", "1"}
        else:
            return False

    def normalize_url(self, url: str) -> str:
        # normalize URL according to CIF specification
        uri = url.partition(":")[-1] if ":" in url else url
        uri = uri.strip("/")
        return urllib.parse.quote(uri.encode("utf8")).lower()

    def run(self):
        """Runs CIF processing
        @return: full CIF report.
        """
        self.key = "cif"
        cif = []
        resources = []

        key = self.options.get("key")
        timeout = self.options.get("timeout", 60)
        url = self.options.get("url")
        confidence = self.options.get("confidence", 85)
        nolog = self.getbool(self.options.get("nolog", True))
        per_lookup_limit = self.options.get("per_lookup_limit", 20)
        per_analysis_limit = self.options.get("per_analysis_limit", 200)

        if not url:
            raise CuckooProcessingError("CIF URL not configured, skip")

        if not key:
            raise CuckooProcessingError("CIF API key not configured, skip")

        # add IOC from submission
        if self.task["category"] in {"file", "static"}:
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError(f"File {self.file_path} not found, skipping it")

            resources.append(File(self.file_path).get_md5())
        elif self.task["category"] == "url":
            query = self.normalize_url(self.task["target"])
            resources.append(hashlib.sha1(query).hexdigest())
        else:
            # Not supported type, exiting
            return cif

        # add IOCs from previous network processing
        if "network" in self.results:
            hosts = self.results["network"].get("hosts")
            if hosts:
                resources.extend(host["ip"] for host in hosts)
            domains = self.results["network"].get("domains")
            if domains:
                resources.extend(domain["domain"] for domain in domains)
            httpreqs = self.results["network"].get("http")
            if httpreqs:
                for req in httpreqs:
                    uri = self.normalize_url(req["uri"])
                    resources.append(hashlib.sha1(uri).hexdigest())

        # add IOCs from dropped files
        if "dropped" in self.results:
            resources.extend(
                File(dropped["path"]).get_md5()
                for dropped in self.results["dropped"]
                if os.path.isfile(dropped["path"]) and ("PE32" in dropped["type"] or "MS-DOS" in dropped["type"])
            )

        headers = {"User-Agent": "Mozilla Cuckoo"}

        for res in resources[:per_analysis_limit]:
            data = {
                "query": res,
                "apikey": key,
                "nolog": nolog,
                "confidence": confidence,
                "limit": per_lookup_limit,
                "fmt": "json",
            }

            try:
                r = requests.get(url, headers=headers, params=data, verify=True, timeout=int(timeout))
                response_data = r.content
            except requests.exceptions.RequestException as e:
                raise CuckooProcessingError(f"Unable to complete connection to CIF server: {e}") from e

            try:
                resplines = [i.strip() for i in response_data.splitlines()]
                ciftmp = [json.loads(i) for i in resplines]
                cif.extend(ciftmp)
            except ValueError as e:
                raise CuckooProcessingError(f"Unable to convert response to JSON: {e}") from e

        return cif
