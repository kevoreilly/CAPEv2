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

from __future__ import absolute_import
import os
import shutil
import json
import logging
from datetime import datetime

try:
    import re2 as re
except ImportError:
    import re
import hashlib
import imp

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.cape_utils import pe_map, upx_harness, BUFSIZE, static_config_parsers, plugx_parser

try:
    import pydeep

    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

processing_conf = Config("processing")

HAVE_FLARE_CAPA = False
# required to not load not enabled dependencies
if processing_conf.flare_capa.enabled and processing_conf.flare_capa.on_demand is False:
    from lib.cuckoo.common.integrations.capa import flare_capa_details, HAVE_FLARE_CAPA

ssdeep_threshold = 90

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
TYPE_STRING = 0x100
UPX = 0x1000

log = logging.getLogger(__name__)

code_mapping = {
    PLUGX_PAYLOAD: "PlugX Payload",
    UPX: "Unpacked PE Image",
    MOREEGGSBIN_PAYLOAD: "More_Eggs Binary Payload",
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

multi_block_config = (
    "SquirrelWaffle",
)

class CAPE(Processing):
    """CAPE output file processing."""

    def detect2pid(self, pid, cape_name):
        self.results.setdefault("detections2pid", {})
        self.results["detections2pid"].setdefault(str(pid), list())
        if cape_name not in self.results["detections2pid"][str(pid)]:
            self.results["detections2pid"][str(pid)].append(cape_name)

    def upx_unpack(self, file_data):
        unpacked_file = upx_harness(file_data)
        if unpacked_file and os.path.exists(unpacked_file):
            for unpacked_hit in File(unpacked_file).get_yara(category="CAPE"):
                if unpacked_hit["name"] == "UPX":
                    # Failed to unpack
                    log.info("CAPE: Failed to unpack UPX")
                    break
            if not os.path.exists(self.CAPE_path):
                os.makedirs(self.CAPE_path)
            newname = os.path.join(self.CAPE_path, os.path.basename(unpacked_file))
            if os.path.exists(unpacked_file):
                shutil.move(unpacked_file, newname)
                # Recursive process of unpacked file
                upx_extract = self.process_file(newname, True, {})
                if upx_extract and upx_extract["type"]:
                    upx_extract["cape_type"] = "UPX-extracted "
                    type_strings = upx_extract["type"].split()
                    if type_strings[0] in ("PE32+", "PE32"):
                        upx_extract["cape_type"] += pe_map[type_strings[0]]
                        if type_strings[2][0] == "(DLL)":
                            upx_extract["cape_type"] += "DLL"
                        else:
                            upx_extract["cape_type"] += "executable"

    def process_file(self, file_path, append_file, metadata={}):
        """Process file.
        @return: file_info
        """

        config = {}
        cape_name = ""
        type_string = ""

        if not os.path.exists(file_path):
            return

        buf = self.options.get("buffer", BUFSIZE)
        file_info, pefile_object = File(file_path, metadata.get("metadata", "")).get_all()
        if pefile_object:
            self.results.setdefault("pefiles", {})
            self.results["pefiles"].setdefault(file_info["sha256"], pefile_object)

        # Get the file data
        with open(file_info["path"], "rb") as file_open:
            file_data = file_open.read()

        if metadata.get("pids", False):
            if len(metadata["pids"]) == 1:
                file_info["pid"] = metadata["pids"][0]
            else:
                file_info["pid"] = ",".join(metadata["pids"])

        metastrings = metadata.get("metadata", "").split(";?")
        if len(metastrings) > 2:
            file_info["process_path"] = metastrings[1]
            file_info["process_name"] = metastrings[1].split("\\")[-1]
        if len(metastrings) > 3:
            file_info["module_path"] = metastrings[2]

        file_info["cape_type_code"] = 0
        file_info["cape_type"] = ""
        if metastrings and metastrings[0] and metastrings[0].isdigit():
            file_info["cape_type_code"] = int(metastrings[0])

            if file_info["cape_type_code"] == TYPE_STRING:
                if len(metastrings) > 4:
                    type_string = metastrings[3]

            if file_info["cape_type_code"] == COMPRESSION:
                file_info["cape_type"] = "Decompressed PE Image"

            if file_info["cape_type_code"] in inject_map:
                file_info["cape_type"] = inject_map[file_info["cape_type_code"]]
                if len(metastrings) > 4:
                    file_info["target_path"] = metastrings[3]
                    file_info["target_process"] = metastrings[3].split("\\")[-1]
                    file_info["target_pid"] = metastrings[4]

            if file_info["cape_type_code"] in unpack_map:
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

                """
                ConfigData = format(file_data)
                if ConfigData:
                    config[cape_name].update({ConfigItem: [ConfigData]})
                """
                append_file = False

            # PlugX
            if file_info["cape_type_code"] == PLUGX_CONFIG:
                file_info["cape_type"] = "PlugX Config"
                if plugx_parser:
                    plugx_config = plugx_parser.parse_config(file_data, len(file_data))
                    if plugx_config:
                        cape_name = "PlugX"
                        config[cape_name] = dict()
                        for key, value in plugx_config.items():
                            config[cape_name].update({key: [value]})
                    else:
                        log.error("CAPE: PlugX config parsing failure - size many not be handled.")
                    append_file = False

            # Attempt to decrypt script dump
            if file_info["cape_type_code"] == SCRIPT_DUMP:
                data = file_data.decode("utf-16").replace("\x00", "")
                cape_name = "ScriptDump"
                malwareconfig_loaded = False
                try:
                    malwareconfig_parsers = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "CAPE")
                    file, pathname, description = imp.find_module(cape_name, [malwareconfig_parsers])
                    module = imp.load_module(cape_name, file, pathname, description)
                    malwareconfig_loaded = True
                    log.debug("CAPE: Imported malwareconfig.com parser %s", cape_name)
                except ImportError:
                    log.debug("CAPE: malwareconfig.com parser: No module named %s", cape_name)
                if malwareconfig_loaded:
                    try:
                        script_data = module.config(self, data)
                        if script_data and "more_eggs" in script_data["type"]:
                            bindata = script_data["data"]
                            sha256 = hashlib.sha256(bindata).hexdigest()
                            filepath = os.path.join(self.CAPE_path, sha256)
                            tmpstr = file_info["pid"]
                            tmpstr += "," + file_info["process_path"]
                            tmpstr += "," + file_info["module_path"]
                            if "text" in script_data["datatype"]:
                                file_info["cape_type"] = "MoreEggsJS"
                                outstr = str(MOREEGGSJS_PAYLOAD) + "," + tmpstr + "\n"
                                with open(filepath + "_info.txt", "w") as infofd:
                                    infofd.write(outstr)
                                with open(filepath, "w") as cfile:
                                    cfile.write(bindata)
                            elif "binary" in script_data["datatype"]:
                                file_info["cape_type"] = "MoreEggsBin"
                                outstr = str(MOREEGGSBIN_PAYLOAD) + "," + tmpstr + "\n"
                                with open(filepath + "_info.txt", "w") as infofd:
                                    infofd.write(outstr)
                                with open(filepath, "wb") as cfile:
                                    cfile.write(bindata)
                            if os.path.exists(filepath):
                                self.script_dump_files.append(filepath)
                        else:
                            file_info["cape_type"] = "Script Dump"
                            log.info("CAPE: Script Dump does not contain known encrypted payload.")
                    except Exception as e:
                        log.error("CAPE: malwareconfig parsing error with %s: %s", cape_name, e)
                append_file = True

            # More_Eggs
            if file_info["cape_type_code"] == MOREEGGSJS_PAYLOAD:
                file_info["cape_type"] = "More Eggs JS Payload"
                cape_name = "MoreEggs"
                append_file = True

        # Process CAPE Yara hits
        for hit in file_info["cape_yara"]:
            # Check to see if file is packed with UPX
            if hit["name"] == "UPX":
                log.info("CAPE: Found UPX Packed sample - attempting to unpack")
                self.upx_unpack(file_data)

            # Check for a payload or config hit
            extraction_types = ("payload", "config", "loader")

            try:
                if any([file_type in hit["meta"].get("cape_type", "").lower() for file_type in extraction_types]):
                    file_info["cape_type"] = hit["meta"]["cape_type"]
                    cape_name = hit["name"].replace("_", " ")
            except Exception as e:
                print("Cape type error: {}".format(e))
            type_strings = file_info["type"].split()
            if "-bit" not in file_info["cape_type"]:
                if type_strings[0] in ("PE32+", "PE32"):
                    file_info["cape_type"] += pe_map[type_strings[0]]
                    if type_strings[2] == ("(DLL)"):
                        file_info["cape_type"] += "DLL"
                    else:
                        file_info["cape_type"] += "executable"

            if hit["name"] == "GuLoader":
                self.detect2pid(file_info["pid"], "GuLoader")

            cape_name = hit["name"].replace("_", " ")
            tmp_config = static_config_parsers(hit["name"], file_data)
            if tmp_config and tmp_config.get(cape_name):
                config.update(tmp_config[cape_name])

        if type_string :
            log.info("CAPE: type_string: %s", type_string)
            tmp_config = static_config_parsers(type_string.split(" ")[0], file_data)
            if tmp_config:
                cape_name = type_string.split(" ")[0]
                log.info("CAPE: config returned for: %s", cape_name)
                config.update(tmp_config)

        if cape_name:
            if "detections" not in self.results:
                if cape_name != "UPX":
                    # ToDo list of keys
                    self.results["detections"] = cape_name
            if file_info.get("pid"):
                self.detect2pid(file_info["pid"], cape_name)

        # Remove duplicate payloads from web ui
        for cape_file in self.cape["payloads"] or []:
            if file_info["size"] == cape_file["size"]:
                if HAVE_PYDEEP:
                    ssdeep_grade = pydeep.compare(file_info["ssdeep"].encode("utf-8"), cape_file["ssdeep"].encode("utf-8"))
                    if ssdeep_grade >= ssdeep_threshold:
                        append_file = False
                if file_info.get("entrypoint") and file_info.get("ep_bytes") and cape_file.get("entrypoint"):
                    if (
                        file_info.get("entrypoint")
                        and file_info["entrypoint"] == cape_file["entrypoint"]
                        and file_info["cape_type_code"] == cape_file["cape_type_code"]
                        and file_info["ep_bytes"] == cape_file["ep_bytes"]
                    ):
                        log.debug("CAPE duplicate output file skipped")
                        append_file = False

        if append_file is True:
            if HAVE_FLARE_CAPA:
                pretime = datetime.now()
                capa_details = flare_capa_details(file_path, "cape")
                if capa_details:
                    file_info["flare_capa"] = capa_details
                self.add_statistic_tmp("flare_capa", "time", pretime=pretime)
            self.cape["payloads"].append(file_info)

        if config and config not in self.cape["configs"]:
            if cape_name in multi_block_config and self.cape["configs"]:
                for conf in self.cape["configs"]:
                    if cape_name in conf:
                        conf[cape_name].update(config[cape_name])
            else:
                # in case if malware name is missed it will break conf visualization
                if cape_name not in config:
                    config = {cape_name: config}
                if config not in self.cape["configs"]:
                    self.cape["configs"].append(config)

    def run(self):
        """Run analysis.
        @return: list of CAPE output files with related information.
        """
        self.key = "CAPE"
        self.script_dump_files = []

        self.cape = dict()
        self.cape["payloads"] = list()
        self.cape["configs"] = list()

        meta = dict()
        if os.path.exists(self.files_metadata):
            for line in open(self.files_metadata, "rb"):
                entry = json.loads(line)

                # ignore ransom files
                if entry["filepath"] in self.results.get("ransom_exclude_files", []):
                    continue

                filepath = os.path.join(self.analysis_path, entry["path"])
                meta[filepath] = {
                    "pids": entry["pids"],
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
                log.error('Sample file doesn\'t exist: "%s"' % self.file_path)

        self.process_file(self.file_path, False, meta.get(self.file_path, {}))

        return self.cape
