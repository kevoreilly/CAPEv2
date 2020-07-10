# Copyright (C) 2016-2017 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import xml.etree.ElementTree

from lib.cuckoo.common.abstracts import Processing


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

            entry = {}
            for child in element.getchildren():
                entry[child.tag] = child.text
            yield entry

    def __nonzero__(self):
        # For documentation on this please refer to MonitorProcessLog.
        return True


class Procmon(Processing):
    """Extract events from procmon.exe output."""

    def run(self):
        self.key = "procmon"
        procmon_xml = os.path.join(self.analysis_path, "procmon.xml")
        if not os.path.exists(procmon_xml):
            return

        return ProcmonLog(procmon_xml)
