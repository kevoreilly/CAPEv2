# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import json
from datetime import datetime
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.utils import convert_to_printable
from lib.cuckoo.common.cape_utils import flare_capa_details

processing_conf = Config("processing")

class ProcDump(Processing):
    """ProcDump files analysis."""

    def run(self):
        """Run analysis.
        @return: list of process dumps with related information.
        """
        self.key = "procdump"
        procdump_files = []
        buf = self.options.get("buffer", 8192)
        if not os.path.exists(self.procdump_path):
            return None

        meta = dict()
        if os.path.exists(self.files_metadata):
            for line in open(self.files_metadata, "rb"):
                entry = json.loads(line)
                filepath = os.path.join(self.analysis_path, entry["path"])
                meta[filepath] = {
                    "pids": entry["pids"],
                    "filepath": entry["filepath"],
                    "metadata": entry["metadata"],
                }

        file_names = os.listdir(self.procdump_path)
        for file_name in file_names:
            file_path = os.path.join(self.procdump_path, file_name)
            if not meta.get(file_path):
                continue
            file_info, pefile_object = File(file_path=file_path, guest_paths=meta[file_path]["metadata"], file_name=file_name).get_all()
            if pefile_object:
                self.results.setdefault("pefiles", {})
                self.results["pefiles"].setdefault(file_info["sha256"], pefile_object)
            metastrings = meta[file_path].get("metadata", "").split(";?")
            if len(metastrings) < 3:
                continue
            file_info["process_path"] = metastrings[1]
            file_info["module_path"] = metastrings[2]
            file_info["process_name"] = file_info["process_path"].split("\\")[-1]
            file_info["pid"] = meta[file_path]["pids"][0]
            type_strings = file_info["type"].split()
            if len(type_strings) < 3:
                continue
            if type_strings[0] == "MS-DOS":
                file_info["cape_type"] = "DOS MZ image: executable"
            else:
                file_info["cape_type"] = "PE image"
                if type_strings[0] == ("PE32+"):
                    file_info["cape_type"] += ": 64-bit "
                elif type_strings[0] == ("PE32"):
                    file_info["cape_type"] += ": 32-bit "
                if type_strings[2] == ("(DLL)"):
                    file_info["cape_type"] += "DLL"
                else:
                    file_info["cape_type"] += "executable"
            texttypes = [
                "ASCII",
                "Windows Registry text",
                "XML document text",
                "Unicode text",
            ]
            readit = False
            for texttype in texttypes:
                if texttype in file_info["type"]:
                    readit = True
                    break
            if readit:
                with open(file_info["path"], "r") as drop_open:
                    filedata = drop_open.read(buf + 1)
                if len(filedata) > buf:
                    file_info["data"] = convert_to_printable(filedata[:buf] + " <truncated>")
                else:
                    file_info["data"] = convert_to_printable(filedata)

            pretime = datetime.now()
            capa_details = flare_capa_details(file_path, "procdump")
            if capa_details:
                file_info["flare_capa"] = capa_details
            self.add_statistic_tmp("flare_capa", "time", pretime)

            procdump_files.append(file_info)

        return procdump_files
