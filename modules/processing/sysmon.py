from __future__ import absolute_import
import logging
import os
import re
import xml.etree.ElementTree as ET

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

__author__ = "@FernandoDoming"
__version__ = "1.0.0"


def parseXmlToJson(xml):
    response = {}
    for child in list(xml):
        if len(list(child)) > 0:
            response[child.tag] = parseXmlToJson(child)
        else:
            response[child.tag] = child.text or ""
    return response


class Sysmon(Processing):
    def remove_noise(self, data):
        filtered_proc_creations_re = [
            r"C:\\Windows\\System32\\wevtutil\.exe\s+clear-log\s+microsoft-windows-(sysmon|powershell)\/operational",
            r"bin\\is32bit.exe",
            r"bin\\inject-(?:x86|x64).exe",
            r"C:\\Windows\\System32\\wevtutil.exe\s+query-events microsoft-windows-powershell\/operational\s+\/rd:true\s+\/e:root\s+\/format:xml\s+\/uni:true",
            r"C:\\Windows\\System32\\wevtutil.exe\s+query-events\s+microsoft-windows-sysmon\/operational\s+\/format:xml",
        ]

        filtered = []
        for event in data:
            is_filtered = False
            if event["System"]["EventID"] == "1":
                for p in filtered_proc_creations_re:
                    cmdline = event["EventData"]["Data"][9]["#text"]
                    if re.search(p, cmdline):
                        log.info("Supressed %s because it is noisy", cmdline)
                        is_filtered = True

            if not is_filtered:
                filtered.append(event)

        return filtered

    def run(self):
        self.key = "sysmon"

        # Determine oldest sysmon log and remove the rest
        lastlog = os.listdir(f"{self.analysis_path}/sysmon/")
        lastlog.sort()
        if not lastlog:
            return
        lastlog = lastlog[-1]
        # Leave only the most recent file
        for f in os.listdir(f"{self.analysis_path}/sysmon/"):
            if f != lastlog:
                try:
                    os.remove(f"{self.analysis_path}/sysmon/{f}")
                except Exception:
                    log.error("Failed to remove sysmon file log %s", f)

        os.rename(f"{self.analysis_path}/sysmon/{lastlog}", f"{self.analysis_path}/sysmon/sysmon.xml")

        sysmon_path = f"{self.analysis_path}/sysmon/sysmon.xml"

        if not os.path.exists(sysmon_path) or os.path.getsize(sysmon_path) < 100:
            return

        data = None
        try:
            tree = ET.parse(sysmon_path)
            root = tree.getroot()
            data = parseXmlToJson(root.attrib)
        except Exception as e:
            raise CuckooProcessingError(f"Failed parsing sysmon.xml with ET: {e}")

        if not root:
            return

        data = self.remove_noise(data)
        return data
