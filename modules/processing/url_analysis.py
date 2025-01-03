# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.parse_url import HAVE_WHOIS, URL

HAVE_VIRUSTOTAL = False
processing_conf = Config("processing")

if processing_conf.virustotal.enabled and not processing_conf.virustotal.on_demand:
    from lib.cuckoo.common.integrations.virustotal import vt_lookup

    HAVE_VIRUSTOTAL = True


class UrlAnalysis(Processing):
    """General information about a URL."""

    def run(self):
        """Run URL information gathering.
        @return: information dict.
        """
        self.key = "url_analysis"
        self.order = 1
        target_info = {}
        if self.task["category"] == "url":
            target_info["url"] = self.task["target"]
            if HAVE_WHOIS and self.options.whois:
                self.results["url"] = URL(self.task["target"]).run()

            if HAVE_VIRUSTOTAL and processing_conf.virustotal.enabled:
                vt_details = vt_lookup("url", self.task["target"], self.results)
                if vt_details:
                    self.results["url"].setdefault("virustotal", vt_details)

            self.results["target"] = {"category": "url"}
        return target_info
