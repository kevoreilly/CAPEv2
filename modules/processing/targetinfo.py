# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.file_extra_info import static_file_info
from lib.cuckoo.common.integrations.parse_url import HAVE_WHOIS, URL
from lib.cuckoo.common.objects import File

processing_conf = Config("processing")


class TargetInfo(Processing):
    """General information about a file."""

    def run(self):
        """Run file information gathering.
        @return: information dict.
        """
        self.key = "target"
        self.order = 1
        target_info = {"category": self.task["category"]}
        # We have to deal with file or URL targets.
        if self.task["category"] in ("file", "static"):
            target_info["file"] = {}
            # Let's try to get as much information as possible, i.e., the filename if the file is not available anymore.
            if os.path.exists(self.file_path):
                target_info["file"], pefile_object = File(self.file_path).get_all()
                if pefile_object:
                    self.results.setdefault("pefiles", {}).setdefault(target_info["file"]["sha256"], pefile_object)

                static_file_info(
                    target_info["file"],
                    self.file_path,
                    str(self.task["id"]),
                    self.task.get("package", ""),
                    self.task.get("options", ""),
                    self.self_extracted,
                    self.results,
                )

            target_info["file"]["name"] = File(self.task["target"]).get_name()
        elif self.task["category"] == "url":
            target_info["url"] = self.task["target"]
            if HAVE_WHOIS and processing_conf.static.whois:
                self.results["url"] = URL(self.task["target"]).run()
        return target_info
