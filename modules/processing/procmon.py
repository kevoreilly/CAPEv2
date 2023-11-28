# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import xml.etree.ElementTree

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.path_utils import path_exists


class ProcmonLog(list):
    """Yield each API call event to the parent handler."""

    def __init__(self, filepath):
        list.__init__(self)
        self.filepath = filepath

    def __next__(self):
        iterator = xml.etree.ElementTree.iterparse(open(self.filepath, "rb"), events=["end"])
        for _, element in iterator:
            if element.tag != "event":
                continue

            yield {child.tag: child.text for child in element.getchildren()}

    def __nonzero__(self):
        # For documentation on this please refer to MonitorProcessLog.
        return True


class Procmon(Processing):
    """Extract events from procmon.exe output."""

    def run(self):
        self.key = "procmon"
        procmon_xml = os.path.join(self.analysis_path, "aux/procmon.xml")
        if not path_exists(procmon_xml):
            return

        return ProcmonLog(procmon_xml)
