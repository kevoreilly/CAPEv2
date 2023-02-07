# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.integrations.mitre import mitre_generate_attck

log = logging.getLogger(__name__)


class MITRE_TTPS(Report):
    def run(self, results):
        if not results.get("ttps") or not hasattr(self, "mitre"):
            return

        attck = mitre_generate_attck(results, self.mitre)
        if attck:
            results["mitre_attck"] = attck
