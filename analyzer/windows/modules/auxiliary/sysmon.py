import logging
import os
import platform
import subprocess
import threading
from itertools import product
from zipfile import ZIP_DEFLATED, ZipFile

from lib.common.abstracts import Auxiliary
from lib.common.exceptions import CuckooPackageError
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

__author__ = "@FernandoDoming"
__version__ = "1.0.1"


class Sysmon(threading.Thread, Auxiliary):
    evtx_dump = "evtx.zip"
    windows_logs = [
        "Microsoft-Windows-Sysmon/Operational",
    ]

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.sysmon
        self.extract_evtx = config.sysmon and not config.evtx
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    def clear_log(self):
        try:
            subprocess.call(
                ("C:\\Windows\\System32\\wevtutil.exe", "clear-log", "microsoft-windows-sysmon/operational"),
                startupinfo=self.startupinfo,
            )
        except Exception as e:
            log.error("Error clearing Sysmon events - %s", e)

    def collect_logs(self):
        sysmon_xml_path = "C:\\sysmon.xml"
        try:
            subprocess.call(
                (
                    "C:\\Windows\\System32\\wevtutil.exe",
                    "query-events",
                    "microsoft-windows-sysmon/operational",
                    "/rd:true",
                    "/e:Events",
                    "/format:xml",
                ),
                startupinfo=self.startupinfo,
                stdout=open(sysmon_xml_path, "w"),
            )
        except Exception as e:
            log.error("Could not create sysmon log file - %s", e)

        if os.path.exists(sysmon_xml_path):
            upload_to_host(sysmon_xml_path, "sysmon/sysmon.xml")
        else:
            log.error("Sysmon log file not found in guest machine")

        if self.extract_evtx:
            logs_folder = None
            try:
                logs_folder = "C:/windows/Sysnative/winevt/Logs"
                os.listdir(logs_folder)
            except Exception:
                logs_folder = "C:/Windows/System32/winevt/Logs"

            with ZipFile(self.evtx_dump, "w", ZIP_DEFLATED) as zip_obj:
                for evtx_file_name, selected_evtx in product(os.listdir(logs_folder), self.windows_logs):
                    _selected_evtx = f"{selected_evtx}.evtx"
                    _selected_evtx = _selected_evtx.replace("/", "%4")
                    if _selected_evtx == evtx_file_name:
                        full_path = os.path.join(logs_folder, evtx_file_name)
                        if os.path.exists(full_path):
                            log.debug("Adding %s to zip dump", full_path)
                            zip_obj.write(full_path, evtx_file_name)

            log.debug("Uploading %s to host", self.evtx_dump)
            upload_to_host(self.evtx_dump, f"evtx/{self.evtx_dump}")

    def start(self):
        if not self.enabled:
            return False

        self.clear_log()

        # First figure out what architecture the system in running (x64 or x86)
        bin_path = os.path.join(os.getcwd(), "bin")

        if "Windows" in platform.uname():
            if "AMD64" in platform.uname():
                sysmon = os.path.join(bin_path, "SMaster64.exe")
            else:
                sysmon = os.path.join(bin_path, "SMaster32.exe")
        # TODO: Platform is Linux, add support for https://github.com/Sysinternals/SysmonForLinux
        else:
            self.enabled = False
            return False

        config_file = os.path.join(bin_path, "sysmonconfig-export.xml")
        if not os.path.exists(sysmon) or not os.path.exists(config_file):
            raise CuckooPackageError(
                "In order to use the Sysmon functionality, it "
                "is required to have the SMaster(64|32).exe file and "
                "sysmonconfig-export.xml file in the bin path. Note that the SMaster(64|32).exe files are "
                "just the standard Sysmon binaries renamed to avoid anti-analysis detection techniques."
            )

        # Start Sysmon in the background
        subprocess.call([sysmon, "-accepteula", "-n", "-i", config_file], startupinfo=self.startupinfo)

    def stop(self) -> bool:
        if self.enabled:
            self.collect_logs()
            return True
        return False
