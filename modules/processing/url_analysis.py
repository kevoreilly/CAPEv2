# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.parse_url import HAVE_WHOIS, URL

processing_conf = Config("processing")


class UrlAnalysis(Processing):
    """General information about a file."""

    def run(self):
        """Run file information gathering.
        @return: information dict.
        """
        self.key = "url_analysis"
        self.order = 1
        target_info = {}
        if self.task["category"] == "url":
            target_info["url"] = self.task["target"]
            if HAVE_WHOIS and processing_conf.url_analysis.whois:
                self.results["url"] = URL(self.task["target"]).run()
        return target_info
