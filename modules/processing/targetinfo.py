# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os.path

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File


class TargetInfo(Processing):
    """General information about a file."""

    def run(self):
        """Run file information gathering.
        @return: information dict.
        """
        self.key = "target"

        target_info = {"category": self.task["category"]}
        # We have to deal with file or URL targets.
        if self.task["category"] in ("file", "static"):
            target_info["file"] = {}

            # Let's try to get as much information as possible, i.e., the
            # filename if the file is not available anymore.
            if os.path.exists(self.file_path):
                target_info["file"], pefile_object = File(self.file_path).get_all()
                if pefile_object:
                    self.results.setdefault("pefiles", {})
                    self.results["pefiles"].setdefault(target_info["file"]["sha256"], pefile_object)

            target_info["file"]["name"] = File(self.task["target"]).get_name()
        elif self.task["category"] == "url":
            target_info["url"] = self.task["target"]

        return target_info
