import logging
import os
import subprocess
import time
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

__author__ = "Jeff White [karttoon] @noottrak"
__email__ = "jwhite@paloaltonetworks.com"
__version__ = "1.0.4"
__date__ = "11OCT2019"


class Curtain(Thread, Auxiliary):
    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        Thread.__init__(self)
        Auxiliary.__init__(self, options, config)
        self.enabled = config.curtain
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

    def collectLogs(self):
        try:
            subprocess.call(
                [
                    "C:\\Windows\\System32\\wevtutil.exe",
                    "query-events",
                    "microsoft-windows-powershell/operational",
                    "/rd:true",
                    "/e:root",
                    "/format:xml",
                    "/uni:true",
                ],
                startupinfo=self.startupinfo,
                stdout=open("C:\\curtain.log", "w"),
            )
        except Exception as e:
            log.error("Curtain - Error collecting PowerShell events - %s", e)

        # time.sleep(5)

        if os.path.exists("C:\\curtain.log"):
            now = time.time()
            upload_to_host("C:\\curtain.log", f"curtain/{now}.curtain.log")
        else:
            log.error("Curtain log file not found!")

    def clearLogs(self):
        try:
            subprocess.call(
                ["C:\\Windows\\System32\\wevtutil.exe", "clear-log", "microsoft-windows-powershell/operational"],
                startupinfo=self.startupinfo,
            )
        except Exception as e:
            log.error("Curtain - Error clearing PowerShell events - %s", e)

    def run(self):
        if self.enabled:
            self.clearLogs()
            return True
        return False

    def stop(self):
        self.collectLogs()
        return True
