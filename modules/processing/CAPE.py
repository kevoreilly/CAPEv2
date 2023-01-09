# Copyright (C) 2015 Kevin O'Reilly kevin.oreilly@contextis.co.uk
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import collections
import json
import logging
import os
import timeit
from pathlib import Path
from contextlib import suppress

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.cape_utils import pe_map, static_config_parsers, cape_name_from_yara
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.file_extra_info import static_file_info
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import (
    add_family_detection,
    get_clamav_consensus,
    make_bytes,
    convert_to_printable_and_truncate,
    wide2str,
    texttypes,
)

try:
    import pydeep

    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

processing_conf = Config("processing")

HAVE_FLARE_CAPA = False
# required to not load not enabled dependencies
if processing_conf.flare_capa.enabled and not processing_conf.flare_capa.on_demand:
    from lib.cuckoo.common.integrations.capa import HAVE_FLARE_CAPA, flare_capa_details

ssdeep_threshold = 95

# CAPE output types. To correlate with cape\cape.h in monitor
COMPRESSION = 2
TYPE_STRING = 0x100

log = logging.getLogger(__name__)

code_mapping = {
    # UPX
    0x1000: "Unpacked PE Image",
    0x6A: "AMSI Buffer",
    0x6B: "AMSI Stream",
}

inject_map = {
    3: "Injected PE Image",
    4: "Injected Shellcode/Data",
}

unpack_map = {
    8: "Unpacked PE Image",
    9: "Unpacked Shellcode",
}


class CAPE(Processing):
    """CAPE output file processing."""

    def add_family_detections(self, file_info, cape_names):
        for cape_name in cape_names:
            if cape_name != "UPX" and cape_name:
                if processing_conf.detections.yara:
                    add_family_detection(self.results, cape_name, "Yara", file_info["sha256"])
            if file_info.get("pid"):
                self.detect2pid(str(file_info["pid"]), cape_name)

    def detect2pid(self, pid: str, cape_name: str):
        self.results.setdefault("detections2pid", {}).setdefault(pid, [])
        if cape_name not in self.results["detections2pid"][pid]:
            self.results["detections2pid"][pid].append(cape_name)

    @staticmethod
    def ensure_config_key(cape_name, config):
        """Make sure that the cape_name is the top-level key of the config.
        Return the resulting config.
        """
        if cape_name not in config:
            config = {cape_name: config}
        return config

    def _cape_type_string(self, type_strings, file_info, append_file):
        if file_info["cape_type_code"] in code_mapping:
            file_info["cape_type"] = code_mapping[file_info["cape_type_code"]]
            append_file = True
        if any(i in type_strings for i in ("PE32+", "PE32")):
            if not file_info["cape_type"]:
                return append_file
            pe_type = "PE32+" if "PE32+" in type_strings else "PE32"
            file_info["cape_type"] += pe_map[pe_type]
            file_info["cape_type"] += "DLL" if type_strings[2] == ("(DLL)") else "executable"
        elif type_strings[0] == "MS-DOS":
            file_info["cape_type"] = "DOS MZ image: executable"
        else:
            file_info["cape_type"] = file_info["cape_type"] or "PE image"
        return append_file

    def _metadata_processing(self, metadata, file_info, append_file):
        type_string = ""
        file_info["cape_type_code"] = 0
        file_info["cape_type"] = ""

        metastrings = metadata.get("metadata", "").split(";?")
        if len(metastrings) > 2:
            file_info["process_path"] = metastrings[1]
            file_info["process_name"] = metastrings[1].rsplit("\\", 1)[-1]
        if len(metastrings) > 3:
            file_info["module_path"] = metastrings[2]

        if "pids" in metadata:
            file_info["pid"] = metadata["pids"][0] if len(metadata["pids"]) == 1 else ",".join(metadata["pids"])

        if metastrings and metastrings[0] and metastrings[0].isdigit():
            file_info["cape_type_code"] = int(metastrings[0])
            if file_info["cape_type_code"] == TYPE_STRING:
                if len(metastrings) > 4:
                    type_string = metastrings[3]

            elif file_info["cape_type_code"] == COMPRESSION:
                file_info["cape_type"] = "Decompressed PE Image"

            elif file_info["cape_type_code"] in inject_map:
                file_info["cape_type"] = inject_map[file_info["cape_type_code"]]
                if len(metastrings) > 4:
                    file_info["target_path"] = metastrings[3]
                    file_info["target_process"] = metastrings[3].rsplit("\\", 1)[-1]
                    file_info["target_pid"] = metastrings[4]

            elif file_info["cape_type_code"] in unpack_map:
                file_info["cape_type"] = unpack_map[file_info["cape_type_code"]]
                if len(metastrings) > 4:
                    file_info["virtual_address"] = metastrings[3]

            type_strings = file_info["type"].split()
            append_file = self._cape_type_string(type_strings, file_info, append_file)

        return type_string, append_file

    def process_file(self, file_path, append_file, metadata: dict = {}, category: str = False, duplicated: dict = {}) -> dict:
        """Process file.
        @return: file_info
        """

        if not Path(file_path).exists():
            return

        cape_names = set()
        buf_size = self.options.get("buffer", 8192)
        # ToDo filename argument for procdump

        # Optimize to not load all if duplicated, it stores sha256 in file object
        f = File(file_path, metadata.get("metadata", ""))
        sha256 = f.get_sha256()

        if sha256 in duplicated["sha256"]:
            return
        else:
            duplicated["sha256"].append(sha256)

        file_info, pefile_object = f.get_all()

        if pefile_object:
            self.results.setdefault("pefiles", {}).setdefault(file_info["sha256"], pefile_object)

        if file_info.get("clamav") and processing_conf.detections.clamav:
            clamav_detection = get_clamav_consensus(file_info["clamav"])
            if clamav_detection:
                add_family_detection(self.results, clamav_detection, "ClamAV", file_info["sha256"])

        # should we use dropped path here?
        static_file_info(
            file_info,
            file_path,
            str(self.task["id"]),
            self.task.get("package", ""),
            self.task.get("options", ""),
            self.self_extracted,
            self.results,
            duplicated,
        )

        type_string, append_file = self._metadata_processing(metadata, file_info, append_file)

        if processing_conf.CAPE.targetinfo and category in ("static", "file"):
            file_info["name"] = File(self.task["target"]).get_name()
            self.results["target"] = {
                "category": category,
                "file": file_info,
            }
        elif processing_conf.CAPE.dropped and category in ("dropped", "package"):
            if category == "dropped":
                file_info.update(metadata.get(file_info["path"][0], {}))
                file_info["guest_paths"] = list({path.get("filepath") for path in metadata.get(file_path, [])})
                file_info["name"] = list(
                    {path.get("filepath", "").rsplit("\\", 1)[-1] for path in metadata.get(file_path, [])}
                ) or [metadata.get("filepath").rsplit("\\", 1)[-1]]
                if category == "dropped":
                    with suppress(UnicodeDecodeError):
                        with open(file_info["path"], "r") as drop_open:
                            filedata = drop_open.read(buf_size + 1)
                        filedata = wide2str(filedata)
                        file_info["data"] = convert_to_printable_and_truncate(filedata, buf_size)

            self.results.setdefault("dropped", []).append(file_info)
        elif processing_conf.CAPE.procdump and category == "procdump":
            if any(texttype in file_info["type"] for texttype in texttypes):
                with open(file_info["path"], "r") as drop_open:
                    filedata = drop_open.read(buf_size + 1)
                file_info["data"] = convert_to_printable_and_truncate(filedata, buf_size)
            if file_info.get("pid"):
                _ = cape_name_from_yara(file_info, file_info["pid"], self.results)

            if HAVE_FLARE_CAPA:
                pretime = timeit.default_timer()
                capa_details = flare_capa_details(file_path, "procdump")
                if capa_details:
                    file_info["flare_capa"] = capa_details
                self.add_statistic_tmp("flare_capa", "time", pretime)

            self.results.setdefault(category, []).append(file_info)

        # Get the file data
        file_data = Path(file_info["path"]).read_bytes()

        # Process CAPE Yara hits
        # Prefilter extracted data + beauty is better than oneliner:
        all_files = []
        for extracted_file in file_info.get("extracted_files", []):
            if not extracted_file["cape_yara"]:
                continue
            if extracted_file.get("data", b""):
                extracted_file_data = make_bytes(extracted_file["data"])
            else:
                extracted_file_data = Path(extracted_file["path"]).read_bytes()
            for yara in extracted_file["cape_yara"]:
                all_files.append(
                    (
                        f"[{extracted_file.get('sha256', '')}]{file_info['path']}",
                        extracted_file_data,
                        yara,
                    )
                )

        for yara in file_info["cape_yara"]:
            all_files.append((file_info["path"], file_data, yara))

        executed_config_parsers = collections.defaultdict(set)
        for tmp_path, tmp_data, hit in all_files:
            # Check for a payload or config hit
            cape_name = None
            try:
                if File.yara_hit_provides_detection(hit):
                    file_info["cape_type"] = hit["meta"]["cape_type"]
                    cape_name = File.get_cape_name_from_yara_hit(hit)
                    cape_names.add(cape_name)
            except Exception as e:
                log.error("Cape type error: %s", str(e))
            type_strings = file_info["type"].split()
            if "-bit" not in file_info["cape_type"]:
                append_file = self._cape_type_string(type_strings, file_info, append_file)

            if cape_name and cape_name not in executed_config_parsers[tmp_path]:
                tmp_config = static_config_parsers(cape_name, tmp_path, tmp_data)
                self.update_cape_configs(tmp_config)
                executed_config_parsers[tmp_path].add(cape_name)

        if type_string:
            file_info["cape_type"] = type_string
            if "config" in type_string.lower():
                append_file = False
            cape_name = File.get_cape_name_from_cape_type(type_string)
            if cape_name and cape_name not in executed_config_parsers:
                tmp_config = static_config_parsers(cape_name, file_info["path"], file_data)
                if tmp_config:
                    cape_names.add(cape_name)
                    log.info("CAPE: config returned for: %s", cape_name)
                    self.update_cape_configs(tmp_config)

        self.add_family_detections(file_info, cape_names)

        # Remove duplicate payloads from web ui
        for cape_file in self.cape["payloads"] or []:
            if file_info["size"] == cape_file["size"]:
                if HAVE_PYDEEP:
                    ssdeep_grade = pydeep.compare(file_info["ssdeep"].encode(), cape_file["ssdeep"].encode())
                    if ssdeep_grade >= ssdeep_threshold:
                        log.debug(
                            "CAPE duplicate output file skipped: ssdeep grade %d, threshold %d", ssdeep_grade, ssdeep_threshold
                        )
                        append_file = False
                if file_info.get("entrypoint") and file_info.get("ep_bytes") and cape_file.get("entrypoint"):
                    if file_info["entrypoint"] == cape_file["entrypoint"] and file_info["cape_type_code"] == cape_file["cape_type_code"] and file_info["ep_bytes"] == cape_file["ep_bytes"]:
                        log.debug("CAPE duplicate output file skipped: matching entrypoint")
                        append_file = False

        if append_file:
            if HAVE_FLARE_CAPA and category == "CAPE":
                pretime = timeit.default_timer()
                capa_details = flare_capa_details(file_path, "cape")
                if capa_details:
                    file_info["flare_capa"] = capa_details
                self.add_statistic_tmp("flare_capa", "time", pretime=pretime)
            self.cape["payloads"].append(file_info)

    def run(self):
        """Run analysis.
        @return: list of CAPE output files with related information.
        """
        self.key = "CAPE"

        self.cape = {}
        self.cape["payloads"] = []
        self.cape["configs"] = []

        meta = {}
        # Required to control files extracted by selfextract.conf as we store them in dropped
        duplicated = {"sha256": []}
        if Path(self.files_metadata).exists():
            for line in open(self.files_metadata, "rb"):
                entry = json.loads(line)

                # ignore ransom files
                if entry["filepath"] in self.results.get("ransom_exclude_files", []):
                    continue

                filepath = os.path.join(self.analysis_path, entry["path"])
                meta[filepath] = {
                    "pids": entry.get("pids"),
                    "ppids": entry.get("ppids"),
                    "filepath": entry.get("filepath", ""),
                    "metadata": entry.get("metadata", {}),
                }

        # Finally static processing of submitted file
        if self.task["category"] in ("file", "static"):
            self.process_file(
                self.file_path, False, meta.get(self.file_path, {}), category=self.task["category"], duplicated=duplicated
            )

        for folder in ("CAPE_path", "procdump_path", "dropped_path", "package_files"):
            category = folder.replace("_path", "").replace("_files", "")
            if hasattr(self, folder):
                # Process dynamically dumped CAPE/procdumps files/dropped might
                # be detected as payloads and trigger config parsing
                for dir_name, _, file_names in os.walk(getattr(self, folder)):
                    for file_name in file_names:
                        filepath = os.path.join(dir_name, file_name)
                        # We want to exclude duplicate files from display in ui
                        if folder not in ("procdump_path", "dropped_path") and len(file_name) <= 64:
                            self.process_file(filepath, True, meta.get(filepath, {}), category=category, duplicated=duplicated)
                        else:
                            # We set append_file to False as we don't wan't to include
                            # the files by default in the CAPE tab
                            self.process_file(filepath, False, meta.get(filepath, {}), category=category, duplicated=duplicated)
        return self.cape

    def update_cape_configs(self, config):
        """Add the given config to self.cape["configs"]."""
        if not config:
            return

        updated = False

        for name, data in config.items():
            break

        # Some families may have multiple configs. Squash them all together.
        if name not in self.cape["configs"]:
            for current in self.cape["configs"]:
                if name == list(current.keys())[0]:
                    current[name].update(data)
                    updated = True
                    break

        if updated is False:
            self.cape["configs"].append(config)
