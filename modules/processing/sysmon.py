import logging
import os
import re
import xmltodict

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

__author__ = "@FernandoDoming"
__version__ = "1.0.0"


def parseXmlToJson(xml):
    return {child.tag: parseXmlToJson(child) if list(child) else child.text or "" for child in list(xml)}


class Sysmon(Processing):
    def remove_noise(self, data):
        filtered_proc_creations_re = (
            r"C:\\Windows\\System32\\wevtutil\.exe\s+clear-log\s+microsoft-windows-(sysmon|powershell)\/operational",
            r"bin\\is32bit.exe",
            r"bin\\inject-(?:x86|x64).exe",
            r"C:\\Windows\\System32\\wevtutil.exe\s+query-events microsoft-windows-powershell\/operational\s+\/rd:true\s+\/e:root\s+\/format:xml\s+\/uni:true",
            r"C:\\Windows\\System32\\wevtutil.exe\s+query-events\s+microsoft-windows-sysmon\/operational\s+\/format:xml",
        )

        filtered = []
        for event in data:
            is_filtered = False
            if event["System"]["EventID"] == "1":
                for p in filtered_proc_creations_re:
                    cmdline = event["EventData"]["Data"][9].get("#text")
                    if cmdline and re.search(p, cmdline):
                        log.info("Supressed %s because it is noisy", cmdline)
                        is_filtered = True

            if not is_filtered:
                filtered.append(event)

        return filtered

    def run(self):
        self.key = "sysmon"
        sysmon_path = f"{self.analysis_path}/sysmon/sysmon.xml"

        if not os.path.exists(sysmon_path) or os.path.getsize(sysmon_path) < 100:
            return

        data = None
        try:
            xml = open(sysmon_path, "rb").read()
            xml = xml.decode("latin1").encode("utf8")
            data = xmltodict.parse(xml)["Events"]["Event"]
        except Exception as e:
            raise CuckooProcessingError("Failed parsing sysmon.xml: %s" % e.message)

        return self.remove_noise(data)
