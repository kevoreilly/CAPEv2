# Copyright (C) 2024 fdiaz@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os

from lib.cuckoo.common.abstracts import Report

log = logging.getLogger(__name__)


class BrowserExt(Report):
    """Include browser extension logs in final report."""

    def run(self, results):
        browser_log_path = os.path.join(self.analysis_path, "browser", "requests.log")
        if not os.path.isfile(browser_log_path):
            return
        if not results.get("browser"):
            results["browser"] = {}
        with open(browser_log_path, "r") as blp_fd:
            try:
                results["browser"]["requests"] = json.load(blp_fd)
            except Exception as ex:
                log.debug(f"error parsing browser requests json: {ex}")
