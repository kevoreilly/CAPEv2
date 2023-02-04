# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os.path

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.exceptions import CuckooDisableModule
from lib.cuckoo.common.misc import cwd

log = logging.getLogger(__name__)

class Reboot(Auxiliary):
    def start(self):
        if self.task.package != "reboot":
            return

    def _push_dropped_files(self, analysis_path):
        files_json = os.path.join(analysis_path, "files.json")
        if not os.path.exists(files_json):
            return

        # Push dropped files through.
        for line in open(files_json, "rb"):
            entry = json.loads(line)
            # Screenshots etc.
            if not entry["filepath"]:
                continue
            filepath = os.path.join(analysis_path, entry["path"])
            data = {
                "filepath": entry["filepath"],
            }
            files = {
                "file": open(filepath, "rb"),
            }
            self.guest_manager.post("/store", files=files, data=data)

    def cb_prepare_guest(self):
        log.info("Preparing task #%d for a reboot analysis..", self.task.id)
        analysis_path = cwd("storage", "analyses", str(self.task.id))
        self._push_dropped_files(analysis_path)
        # Push the reboot.json file to the Analyzer.
        files = {
            "file": open(os.path.join(analysis_path, "reboot.json"), "rb"),
        }
        reboot_path = os.path.join(
            self.guest.analyzer_path, "reboot.json"
        )
        data = {
            "filepath": reboot_path,
        }
        self.guest.post("/store", files=files, data=data)
