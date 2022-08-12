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
import hashlib
import imp
import json
import logging
import os
import timeit

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.cape_utils import pe_map, plugx_parser, static_config_parsers
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.integrations.file_extra_info import static_file_info
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import add_family_detection, get_clamav_consensus, make_bytes

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

# CAPE output types
# To correlate with cape\cape.h in monitor

PROCDUMP = 0
COMPRESSION = 1
INJECTION_PE = 3
INJECTION_SHELLCODE = 4
UNPACKED_PE = 8
UNPACKED_SHELLCODE = 9
PLUGX_PAYLOAD = 0x10
PLUGX_CONFIG = 0x11
SCRIPT_DUMP = 0x65
DATADUMP = 0x66
REGDUMP = 0x67
MOREEGGSJS_PAYLOAD = 0x68
MOREEGGSBIN_PAYLOAD = 0x69
AMSIBUFFER = 0x6A
AMSISTREAM = 0x6B
TYPE_STRING = 0x100
UPX = 0x1000

log = logging.getLogger(__name__)

code_mapping = {
    PLUGX_PAYLOAD: "PlugX Payload",
    UPX: "Unpacked PE Image",
    MOREEGGSBIN_PAYLOAD: "More_Eggs Binary Payload",
    AMSIBUFFER: "AMSI Buffer",
    AMSISTREAM: "AMSI Stream",
}

name_mapping = {
    MOREEGGSBIN_PAYLOAD: "MoreEggs",
}

inject_map = {
    INJECTION_PE: "Injected PE Image",
    INJECTION_SHELLCODE: "Injected Shellcode/Data",
}

unpack_map = {
    UNPACKED_PE: "Unpacked PE Image",
    UNPACKED_SHELLCODE: "Unpacked Shellcode",
}

multi_block_config = ("SquirrelWaffle",)


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

    def process_file(self, file_path, append_file, metadata=None):
        """Process file.
        @return: file_info
        """

        if metadata is None:
            metadata = {}
        cape_name = ""
        type_string = ""

        if not os.path.exists(file_path):
            return

        file_info, pefile_object = File(file_path, metadata.get("metadata", "")).get_all()
        cape_names = set()

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
        )

        # Get the file data
        with open(file_info["path"], "rb") as file_open:
            file_data = file_open.read()

        if metadata.get("pids", False):
            file_info["pid"] = metadata["pids"][0] if len(metadata["pids"]) == 1 else ",".join(metadata["pids"])

        metastrings = metadata.get("metadata", "").split(";?")
        if len(metastrings) > 2:
            file_info["process_path"] = metastrings[1]
            file_info["process_name"] = metastrings[1].rsplit("\\", 1)[-1]
        if len(metastrings) > 3:
            file_info["module_path"] = metastrings[2]

        file_info["cape_type_code"] = 0
        file_info["cape_type"] = ""
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

            if type_strings[0] in ("PE32+", "PE32"):
                file_info["cape_type"] += pe_map[type_strings[0]]
                if type_strings[2] == ("(DLL)"):
                    file_info["cape_type"] += "DLL"
                else:
                    file_info["cape_type"] += "executable"

            if file_info["cape_type_code"] in code_mapping:
                file_info["cape_type"] = code_mapping[file_info["cape_type_code"]]
                type_strings = file_info["type"].split()
                if type_strings[0] in ("PE32+", "PE32"):
                    file_info["cape_type"] += pe_map[type_strings[0]]
                    if type_strings[2] == ("(DLL)"):
                        file_info["cape_type"] += "DLL"
                    else:
                        file_info["cape_type"] += "executable"
                if file_info["cape_type_code"] in name_mapping:
                    cape_name = name_mapping[file_info["cape_type_code"]]
                append_file = True

            # PlugX
            elif file_info["cape_type_code"] == PLUGX_CONFIG:
                file_info["cape_type"] = "PlugX Config"
                if plugx_parser:
                    plugx_config = plugx_parser.parse_config(file_data, len(file_data))
                    if plugx_config:
                        cape_name = "PlugX"
                        self.update_cape_configs(cape_name, plugx_config)
                        cape_names.add(cape_name)
                    else:
                        log.error("CAPE: PlugX config parsing failure - size many not be handled")
                    append_file = False

            # Attempt to decrypt script dump
            elif file_info["cape_type_code"] == SCRIPT_DUMP:
                data = file_data.decode("utf-16").replace("\x00", "")
                cape_name = "ScriptDump"
                malwareconfig_loaded = False
                try:
                    malwareconfig_parsers = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "CAPE")
                    file, pathname, description = imp.find_module(cape_name, [malwareconfig_parsers])
                    module = imp.load_module(cape_name, file, pathname, description)
                    malwareconfig_loaded = True
                    log.debug("CAPE: Imported parser %s", cape_name)
                except ImportError:
                    log.debug("CAPE: parser: No module named %s", cape_name)
                if malwareconfig_loaded:
                    try:
                        script_data = module.config(self, data)
                        if script_data and "more_eggs" in script_data["type"]:
                            bindata = script_data["data"]
                            sha256 = hashlib.sha256(bindata).hexdigest()
                            filepath = os.path.join(self.CAPE_path, sha256)
                            if "text" in script_data["datatype"]:
                                file_info["cape_type"] = "MoreEggsJS"
                            elif "binary" in script_data["datatype"]:
                                file_info["cape_type"] = "MoreEggsBin"
                            with open(filepath, "w") as cfile:
                                cfile.write(bindata)
                                self.script_dump_files.append(filepath)
                        else:
                            file_info["cape_type"] = "Script Dump"
                            log.info("CAPE: Script Dump does not contain known encrypted payload")
                    except Exception as e:
                        log.error("CAPE: malwareconfig parsing error with %s: %s", cape_name, e)
                append_file = True

            # More_Eggs
            elif file_info["cape_type_code"] == MOREEGGSJS_PAYLOAD:
                file_info["cape_type"] = "More Eggs JS Payload"
                cape_name = "MoreEggs"
                append_file = True

        # Process CAPE Yara hits

        # Prefilter extracted data + beauty is better than oneliner:
        all_files = []
        for extracted_file in file_info.get("extracted_files", []):
            yara_hits = extracted_file["cape_yara"]
            if not yara_hits:
                continue
            if extracted_file.get("data", b""):
                extracted_file_data = make_bytes(extracted_file["data"])
            else:
                with open(extracted_file["path"], "rb") as fil:
                    extracted_file_data = fil.read()
            for yara in yara_hits:
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
            try:
                if File.yara_hit_provides_detection(hit):
                    file_info["cape_type"] = hit["meta"]["cape_type"]
                    cape_name = File.get_cape_name_from_yara_hit(hit)
                    cape_names.add(cape_name)
            except Exception as e:
                print(f"Cape type error: {e}")
            type_strings = file_info["type"].split()
            if "-bit" not in file_info["cape_type"]:
                if type_strings[0] in ("PE32+", "PE32"):
                    file_info["cape_type"] += pe_map[type_strings[0]]
                    file_info["cape_type"] += "DLL" if type_strings[2] == ("(DLL)") else "executable"

            if cape_name and cape_name not in executed_config_parsers[tmp_path]:
                tmp_config = static_config_parsers(cape_name, tmp_path, tmp_data)
                self.update_cape_configs(cape_name, tmp_config)
                executed_config_parsers[tmp_path].add(cape_name)

        if type_string:
            log.info("CAPE: type_string: %s", type_string)
            tmp_cape_name = File.get_cape_name_from_cape_type(type_string)
            if tmp_cape_name and tmp_cape_name not in executed_config_parsers:
                tmp_config = static_config_parsers(tmp_cape_name, file_info["path"], file_data)
                if tmp_config:
                    cape_name = tmp_cape_name
                    cape_names.add(cape_name)
                    log.info("CAPE: config returned for: %s", cape_name)
                    self.update_cape_configs(cape_name, tmp_config)

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
                    if (
                        file_info["entrypoint"] == cape_file["entrypoint"]
                        and file_info["cape_type_code"] == cape_file["cape_type_code"]
                        and file_info["ep_bytes"] == cape_file["ep_bytes"]
                    ):
                        log.debug("CAPE duplicate output file skipped: matching entrypoint")
                        append_file = False

        if append_file:
            if HAVE_FLARE_CAPA:
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
        self.script_dump_files = []

        self.cape = {}
        self.cape["payloads"] = []
        self.cape["configs"] = []

        meta = {}
        if os.path.exists(self.files_metadata):
            for line in open(self.files_metadata, "rb"):
                entry = json.loads(line)

                # ignore ransom files
                if entry["filepath"] in self.results.get("ransom_exclude_files", []):
                    continue

                filepath = os.path.join(self.analysis_path, entry["path"])
                meta[filepath] = {
                    "pids": entry["pids"],
                    "ppids": entry["ppids"],
                    "filepath": entry["filepath"],
                    "metadata": entry["metadata"],
                }

        for folder in ("CAPE_path", "procdump_path", "dropped_path"):
            if hasattr(self, folder):
                # Process dynamically dumped CAPE/procdumps files/dropped might
                # be detected as payloads and trigger config parsing
                for dir_name, _, file_names in os.walk(getattr(self, folder)):
                    for file_name in file_names:
                        file_path = os.path.join(dir_name, file_name)
                        # We want to exclude duplicate files from display in ui
                        if folder not in ("procdump_path", "dropped_path") and len(file_name) <= 64:
                            self.process_file(file_path, True, meta.get(file_path, {}))
                        else:
                            # We set append_file to False as we don't wan't to include
                            # the files by default in the CAPE tab
                            self.process_file(file_path, False)

                # Process files that may have been decrypted from ScriptDump
                for file_path in self.script_dump_files:
                    self.process_file(file_path, False, meta.get(file_path, {}))

        # Finally static processing of submitted file
        if self.task["category"] in ("file", "static"):
            if not os.path.exists(self.file_path):
                log.error('Sample file doesn\'t exist: "%s"', self.file_path)

        self.process_file(self.file_path, False, meta.get(self.file_path, {}))

        return self.cape

    def update_cape_configs(self, cape_name, config):
        """Add the given config to self.cape["configs"]."""
        if not config:
            return

        config = self.ensure_config_key(cape_name, config)

        if config not in self.cape["configs"]:
            if cape_name in multi_block_config and self.cape["configs"]:
                # Some families may have multiple configs extracted. Squash them all
                # together.
                for conf in self.cape["configs"]:
                    if cape_name in conf:
                        conf[cape_name].update(config)
            else:
                self.cape["configs"].append(config)
