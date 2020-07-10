from __future__ import absolute_import
import os
import time
import logging
import subprocess
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host
from lib.core.config import Config

log = logging.getLogger(__name__)

__author__ = "Jeff White [karttoon] @noottrak"
__email__ = "jwhite@paloaltonetworks.com"
__version__ = "1.0.4"
__date__ = "11OCT2019"


class Curtain(Thread, Auxiliary):
    def __init__(self, options={}, config=None):
        Thread.__init__(self)
        Auxiliary.__init__(self, options, config)
        self.config = Config(cfg="analysis.conf")
        self.enabled = self.config.curtain
        self.do_run = self.enabled
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
            log.error("Curtain - Error collecting PowerShell events - %s " % e)

        # time.sleep(5)

        if os.path.exists("C:\\curtain.log"):
            now = time.time()
            upload_to_host("C:\\curtain.log", f"curtain/{now}.curtain.log", False)
        else:
            log.error("Curtain log file not found!")

    def clearLogs(self):
        try:
            subprocess.call(
                ["C:\\Windows\\System32\\wevtutil.exe", "clear-log", "microsoft-windows-powershell/operational"], startupinfo=self.startupinfo
            )
        except Exception as e:
            log.error("Curtain - Error clearing PowerShell events - %s" % e)

    def run(self):
        if self.enabled:
            self.clearLogs()
            return True
        return False

    def stop(self):
        if self.enabled:
            self.collectLogs()
            return True
        return False
