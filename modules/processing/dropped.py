# Copyright (C) 2010-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import json
import os

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.integrations.file_extra_info import static_file_info
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import convert_to_printable_and_truncate, wide2str


class Dropped(Processing):
    """Dropped files analysis."""

    def run(self):
        """Run analysis.
        @return: list of dropped files with related information.
        """
        self.key = "dropped"
        dropped_files, meta = [], {}
        buf = self.options.get("buffer", 8192)

        if self.task["category"] in ("pcap", "static"):
            return dropped_files

        if not os.path.exists(self.dropped_path):
            return dropped_files

        if os.path.exists(self.files_metadata):
            with open(self.files_metadata, "rb") as f:
                for line in f:
                    entry = json.loads(line)
                    filepath = os.path.join(self.analysis_path, entry["path"])
                    meta.setdefault(filepath, []).append(
                        {
                            "pids": entry["pids"],
                            "filepath": entry["filepath"],
                        }
                    )

        for dir_name, _, file_names in os.walk(self.dropped_path):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                file_info, pefile_object = File(file_path=file_path).get_all()
                if pefile_object:
                    self.results.setdefault("pefiles", {})
                    self.results["pefiles"].setdefault(file_info["sha256"], pefile_object)
                # ToDo should we pass PE object?
                static_file_info(
                    file_info,
                    file_path,
                    self.task["id"],
                    self.task.get("package", ""),
                    self.task.get("options", ""),
                    self.dropped_path,
                )

                file_info.update(meta.get(file_info["path"][0], {}))
                file_info["guest_paths"] = list({path.get("filepath") for path in meta.get(file_path, [])})
                file_info["name"] = list({path.get("filepath", "").rsplit("\\", 1)[-1] for path in meta.get(file_path, [])})

                try:
                    with open(file_info["path"], "r") as drop_open:
                        filedata = drop_open.read(buf + 1)

                    filedata = wide2str(filedata)
                    file_info["data"] = convert_to_printable_and_truncate(filedata, buf)
                except UnicodeDecodeError:
                    pass
                dropped_files.append(file_info)

        for dir_name, _, file_names in os.walk(self.package_files):
            for file_name in file_names:
                file_path = os.path.join(dir_name, file_name)
                file_info, pefile_object = File(file_path=file_path).get_all()
                if pefile_object:
                    self.results.setdefault("pefiles", {})
                    self.results["pefiles"].setdefault(file_info["sha256"], pefile_object)

                static_file_info(
                    file_info,
                    file_path,
                    self.task["id"],
                    self.task.get("package", ""),
                    self.task.get("options", ""),
                    self.dropped_path,
                )

                dropped_files.append(file_info)

        return dropped_files
