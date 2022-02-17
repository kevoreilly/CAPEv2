# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import, print_function
import logging
import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.cape_utils import generic_file_extractors
from lib.cuckoo.common.integrations.parse_url import HAVE_WHOIS, URL
from lib.cuckoo.common.objects import File

log = logging.getLogger(__name__)


class Static(Processing):
    """Static analysis."""

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        self.key = "static"
        static = {}

        if self.task["category"] in ("file", "static"):
            package = self.results.get("info", {}).get("package", "")
            thetype = File(self.file_path).get_type()

            # Allows to put execute file extractors/unpackers
            generic_file_extractors(self.file_path, self.dropped_path, thetype, static)
        elif self.task["category"] == "url":
            enabled_whois = self.options.get("whois", True)
            if HAVE_WHOIS and enabled_whois:
                static = URL(self.task["target"]).run()

        return static
