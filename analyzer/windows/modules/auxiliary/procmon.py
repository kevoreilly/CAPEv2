# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path
import subprocess
import time
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.constants import ROOT
from lib.common.exceptions import CuckooPackageError
from lib.common.results import upload_to_host


class Procmon(Auxiliary, Thread):
    """Allow procmon to be run on the side."""

    def __init__(self, options, config):
        Thread.__init__(self)
        Auxiliary.__init__(self, options, config)
        self.enabled = config.procmon
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

        bin_path = os.path.join(ROOT, "bin")
        self.procmon_exe = os.path.join(bin_path, "procmon.exe")
        self.procmon_pmc = os.path.join(bin_path, "procmon.pmc")
        self.procmon_pml = os.path.join(bin_path, "procmon")
        self.procmon_xml = os.path.join(bin_path, "procmon.xml")

    def run(self) -> bool:
        if not self.enabled:
            return False

        if not os.path.exists(self.procmon_exe) or not os.path.exists(self.procmon_pmc):
            raise CuckooPackageError(
                "In order to use the Process Monitor functionality it is "
                "required to have Procmon setup with CAPE. Please run the "
                "CAPE Community script which will automatically fetch all "
                "related files to get you up-and-running."
            )

        # Start process monitor in the background.
        subprocess.Popen(
            (
                self.procmon_exe,
                "/AcceptEula",
                "/Quiet",
                "/Minimized",
                "/BackingFile",
                self.procmon_pml,
            ),
            startupinfo=self.startupinfo,
            shell=True,
        )

        # Try to avoid race conditions by waiting until at least something
        # has been written to the log file.
        while not os.path.exists(self.procmon_pml) or not os.path.getsize(self.procmon_pml):
            time.sleep(0.1)

        return True

    def stop(self) -> bool:
        if not self.enabled:
            return False
        try:
            # Terminate process monitor.
            subprocess.call((self.procmon_exe, "/Terminate"), startupinfo=self.startupinfo, shell=True)

            # Convert the process monitor log into a readable XML file.
            subprocess.call(
                (
                    self.procmon_exe,
                    "/OpenLog",
                    f"{self.procmon_pml}.PML",
                    "/LoadConfig",
                    self.procmon_pmc,
                    "/SaveAs",
                    self.procmon_xml,
                    "/SaveApplyFilter",
                ),
                startupinfo=self.startupinfo,
                shell=True,
            )

            # Upload the XML file to the host.
            upload_to_host(self.procmon_xml, "procmon.xml")
            return True
        except Exception as e:
            logging.error(e, exc_info=True)
            return False
