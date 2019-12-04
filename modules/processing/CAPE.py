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
try:
    import re2 as re
except ImportError:
    import re
import hashlib
import imp
import datetime

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.utils import convert_to_printable
from lib.cuckoo.common.cape_utils import pe_map, convert, upx_harness, BUFSIZE, static_config_parsers#, plugx

try:
    import pydeep
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

ssdeep_threshold = 90

# CAPE output types
# To correlate with cape\cape.h in monitor

PROCDUMP             = 0
COMPRESSION          = 1
INJECTION_PE         = 3
INJECTION_SHELLCODE  = 4
INJECTION_SECTION    = 5
EXTRACTION_PE        = 8
EXTRACTION_SHELLCODE = 9
PLUGX_PAYLOAD        = 0x10
PLUGX_CONFIG         = 0x11
EVILGRAB_PAYLOAD     = 0x14
EVILGRAB_DATA        = 0x15
SEDRECO_DATA         = 0x20
URSNIF_CONFIG        = 0x24
URSNIF_PAYLOAD       = 0x25
CERBER_CONFIG        = 0x30
CERBER_PAYLOAD       = 0x31
HANCITOR_CONFIG      = 0x34
HANCITOR_PAYLOAD     = 0x35
QAKBOT_CONFIG        = 0x38
QAKBOT_PAYLOAD       = 0x39
ICEDID_LOADER        = 0x40
ICEDID_BOT           = 0x41
SCRIPT_DUMP          = 0x65
DATADUMP             = 0x66
MOREEGGSJS_PAYLOAD   = 0x68
MOREEGGSBIN_PAYLOAD  = 0x69
UPX                  = 0x1000

log = logging.getLogger(__name__)

code_mapping = {
    PLUGX_PAYLOAD: "PlugX Payload",
    EVILGRAB_PAYLOAD: "EvilGrab Payload",
    CERBER_PAYLOAD: "Cerber Payload",
    QAKBOT_PAYLOAD: "QakBot Payload",
    UPX: "Unpacked PE Image",
    MOREEGGSBIN_PAYLOAD: "More_Eggs Binary Payload",
}

name_mapping = {
    QAKBOT_PAYLOAD: "QakBot",
    MOREEGGSBIN_PAYLOAD: "MoreEggs",
}

config_mapping = {
    QAKBOT_PAYLOAD: "QakBot",
}

inject_map = {
    INJECTION_PE: "Injected PE Image",
    INJECTION_SHELLCODE: "Injected Shellcode/Data",
}

sedreco_map = {
    "0x0": "Timer1",
    "0x1": "Timer2",
    "0x2": "Computer Name",
    "0x3": "C&C1",
    "0x4": "C&C2",
    "0x5": "Operation Name",
    "0x6": "Keylogger MaxBuffer",
    "0x7": "Keylogger MaxTimeout",
    "0x8": "Keylogger Flag",
    "0x9": "C&C3",
}

qakbot_map = {
    "10": "Botnet name",
    "11": "Number of C2 servers",
    "47": "Bot ID"
}

qakbot_id_map = {
    b"22": "#1",
    b"23": "#2",
    b"24": "#3",
    b"25": "#4",
    b"26": "#5",
}

class CAPE(Processing):
    """CAPE output file processing."""

    cape_config = {}

    def upx_unpack(self, file_data, CAPE_output):
        unpacked_file = upx_harness(file_data)
        if unpacked_file and os.path.exists(unpacked_file):
            for unpacked_hit in File(unpacked_file).get_yara("CAPE"):
                if unpacked_hit["name"] == 'UPX':
                    # Failed to unpack
                    log.info("CAPE: Failed to unpack UPX")
                    os.unlink(unpacked_file)
                    break
            if not os.path.exists(self.CAPE_path):
                os.makedirs(self.CAPE_path)
            newname = os.path.join(self.CAPE_path, os.path.basename(unpacked_file))
            shutil.move(unpacked_file, newname)
            #infofd = open(newname + "_info.txt", "a")
            #infofd.write(os.path.basename(unpacked_file) + "\n")
            #infofd.close()

            # Recursive process of unpacked file
            upx_extract = self.process_file(newname, CAPE_output, True, {})
            if upx_extract["type"]:
                upx_extract["cape_type"] = "UPX-extracted "
                type_strings = upx_extract["type"].split()
                if type_strings[0] in ("PE32+", "PE32"):
                    upx_extract["cape_type"] += pe_map[type_strings[0]]
                    if type_strings[2][0] == "(DLL)":
                        upx_extract["cape_type"] += "DLL"
                    else:
                        upx_extract["cape_type"] += "executable"

    def process_file(self, file_path, CAPE_output, append_file, metadata={}):
        """Process file.
        @return: file_info
        """
        global cape_config
        cape_name = ""
        strings = []

        buf = self.options.get("buffer", BUFSIZE)
        if file_path.endswith("_info.txt"):
            return

        texttypes = [
            "ASCII",
            "Windows Registry text",
            "XML document text",
            "Unicode text",
        ]

        textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
        is_binary_file = lambda bytes: bool(bytes.translate(None, textchars))

        file_info = File(file_path, metadata.get("metadata", "")).get_all()

        # Get the file data
        with open(file_info["path"], "rb") as file_open:
            file_data = file_open.read(buf + 1)

        if is_binary_file(file_data[:8192]):
            file_info["data"] = None
        else:
            if len(file_data) > buf:
                file_info["data"] = convert_to_printable(file_data[:buf] + " <truncated>")
            else:
                file_info["data"] = convert_to_printable(file_data)

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

        if metastrings != "":
            try:
                file_info["cape_type_code"] = int(metastrings[0])
            except Exception as e:
                pass
            if file_info["cape_type_code"] == COMPRESSION:
                file_info["cape_type"] = "Decompressed PE Image"

            if file_info["cape_type_code"] in inject_map:
                file_info["cape_type"] = inject_map[file_info["cape_type_code"]]
                if len(metastrings) > 4:
                    file_info["target_path"] = metastrings[4]
                    file_info["target_process"] = metastrings[4].split("\\")[-1]
                    file_info["target_pid"] = metastrings[5]

            if file_info["cape_type_code"] == INJECTION_SECTION:
                file_info["cape_type"] = "Injected Section"
                if len(metastrings) > 4:
                    file_info["section_handle"] = metastrings[4]

            simple_cape_type_map = {
                EXTRACTION_PE: "Extracted PE Image",
                EXTRACTION_SHELLCODE: "Extracted Shellcode",
            }
            if file_info["cape_type_code"] in simple_cape_type_map:
                file_info["cape_type"] = simple_cape_type_map[file_info["cape_type_code"]]
                if len(metastrings) > 4:
                    file_info["virtual_address"] = metastrings[4]

            type_strings = file_info["type"].split()
            if type_strings[0] in ("PE32+", "PE32"):
                file_info["cape_type"] += pe_map[type_strings[0]]
                if type_strings[2] == ("(DLL)"):
                    file_info["cape_type"] += "DLL"
                else:
                    file_info["cape_type"] += "executable"
            """
            # PlugX
            if file_info["cape_type_code"] == PLUGX_CONFIG:
                file_info["cape_type"] = "PlugX Config"
                plugx_parser = plugx.PlugXConfig()
                plugx_config = plugx_parser.parse_config(file_data, len(file_data))
                if not "cape_config" in cape_config and plugx_config:
                    cape_config["cape_config"] = {}
                    for key, value in plugx_config.items():
                        cape_config["cape_config"].update({key: [value]})
                    cape_name = "PlugX"
                else:
                    log.error("CAPE: PlugX config parsing failure - size many not be handled.")
                append_file = False
            """
            if file_info["cape_type_code"] in code_mapping:
                file_info["cape_type"] = code_mapping[file_info["cape_type_code"]]
                if file_info["cape_type_code"] in config_mapping:
                    cape_config["cape_type"] = code_mapping[file_info["cape_type_code"]]

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

            if file_info["cape_type_code"] == EVILGRAB_DATA:
                cape_name = "EvilGrab"
                file_info["cape_type"] = "EvilGrab Data"
                if not "cape_config" in cape_config:
                    cape_config["cape_config"] = {}
                if file_info["size"] == 256 or file_info["size"] == 260:
                    cape_config["cape_config"].update({"filepath": [format(file_data)]})
                if file_info["size"] > 0x1000:
                    append_file = True
                else:
                    append_file = False
            # Sedreco
            if file_info["cape_type_code"] == SEDRECO_DATA:
                cape_name = "Sedreco"
                cape_config["cape_type"] = "Sedreco Config"
                if not "cape_config" in cape_config:
                    cape_config["cape_config"] = {}
                if len(metastrings) > 4:
                    SedrecoConfigIndex = metastrings[4]
                    if SedrecoConfigIndex in sedreco_map:
                        ConfigItem = sedreco_map[SedrecoConfigIndex]
                    else:
                        ConfigItem = "Unknown"

                ConfigData = format(file_data)
                if ConfigData:
                    cape_config["cape_config"].update({ConfigItem: [ConfigData]})
                append_file = False
            # Cerber
            if file_info["cape_type_code"] == CERBER_CONFIG:
                file_info["cape_type"] = "Cerber Config"
                cape_config["cape_type"] = "Cerber Config"
                cape_name = "Cerber"
                if not "cape_config" in cape_config:
                    cape_config["cape_config"] = {}
                parsed = json.loads(file_data.rstrip(b'\0'))
                cape_config["cape_config"].update({"JSON Data": [json.dumps(parsed, indent=4, sort_keys=True)]})
                append_file = True
            # Ursnif
            if file_info["cape_type_code"] == URSNIF_PAYLOAD:
                cape_name = "Ursnif"
                cape_config["cape_type"] = "Ursnif Payload"
                file_info["cape_type"] = "Ursnif Payload"
            if file_info["cape_type_code"] == URSNIF_CONFIG:
                file_info["cape_type"] = "Ursnif Config"
                cape_config["cape_type"] = "Ursnif Config"
                cape_name = "Ursnif"
                malwareconfig_loaded = False
                try:
                    malwareconfig_parsers = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers","malwareconfig")
                    file, pathname, description = imp.find_module(cape_name,[malwareconfig_parsers])
                    module = imp.load_module(cape_name, file, pathname, description)
                    malwareconfig_loaded = True
                    log.info("CAPE: Imported malwareconfig.com parser %s", cape_name)
                except ImportError:
                    log.info("CAPE: malwareconfig.com parser: No module named %s", cape_name)
                if malwareconfig_loaded:
                    try:
                        if not "cape_config" in cape_config:
                            cape_config["cape_config"] = {}
                        malwareconfig_config = module.config(file_data)
                        if isinstance(malwareconfig_config, list):
                            for (key, value) in malwareconfig_config[0].items():
                                cape_config["cape_config"].update({key: [value]})
                        elif isinstance(malwareconfig_config, dict):
                            for (key, value) in malwareconfig_config.items():
                                cape_config["cape_config"].update({key: [value]})
                    except Exception as e:
                        log.error("CAPE: malwareconfig parsing error with %s: %s", cape_name, e)
                append_file = False
            # Hancitor
            if file_info["cape_type_code"] == HANCITOR_PAYLOAD:
                cape_name = "Hancitor"
                cape_config["cape_type"] = "Hancitor Payload"
                file_info["cape_type"] = "Hancitor Payload"
            if file_info["cape_type_code"] == HANCITOR_CONFIG:
                cape_name = "Hancitor"
                cape_config["cape_type"] = "Hancitor Config"
                file_info["cape_type"] = "Hancitor Config"
                if not "cape_config" in cape_config:
                    cape_config["cape_config"] = {}
                ConfigStrings = file_data.split(b'\0')
                ConfigStrings = [_f for _f in ConfigStrings if _f]
                ConfigItem = "Campaign Code"
                cape_config["cape_config"].update({ConfigItem: [ConfigStrings[0]]})
                GateURLs = ConfigStrings[1].split(b'|')
                for index, value in enumerate(GateURLs):
                    ConfigItem = "Gate URL " + str(index+1)
                    cape_config["cape_config"].update({ConfigItem: [value]})
                append_file = False
            # QakBot
            if file_info["cape_type_code"] == QAKBOT_CONFIG:
                file_info["cape_type"] = "QakBot Config"
                cape_config["cape_type"] = "QakBot Config"
                cape_name = "QakBot"
                if "cape_config" not in cape_config:
                    cape_config["cape_config"] = {}
                for line in file_data.splitlines():
                    if b'=' in line:
                        index = line.split('=')[0]
                        data = line.split('=')[1]
                        if index in qakbot_map:
                            ConfigItem = qakbot_map[index]
                            ConfigData = data
                            if ConfigData:
                                self.reporter.add_metadata('other', {ConfigItem: ConfigData})
                        if index == b'3':
                            cape_config["cape_config"].update({
                                "Config timestamp": datetime.datetime.fromtimestamp(int(data)).strftime('%H:%M:%S %d-%m-%Y')}
                            )
                        if index in (b'22', b'23', b'24', b'24', b'25', b'26'):
                            values = data.split(b':')
                            try:
                                cape_config["cape_config"].update({"Password {}".format(qakbot_id_map[index]): values[2]})
                                cape_config["cape_config"].update({ "Username {}".format(qakbot_id_map[index]): values[1]})
                                cape_config["cape_config"].update({"C2 {}".format(qakbot_id_map[index]): values[0]})
                            except:
                                pass
                append_file = False
            # Attempt to decrypt script dump
            if file_info["cape_type_code"] == SCRIPT_DUMP:
                data = file_data.decode("utf-16").replace("\x00", "")
                file_info["data"] = data
                cape_name = "ScriptDump"
                malwareconfig_loaded = False
                try:
                    malwareconfig_parsers = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "malwareconfig")
                    file, pathname, description = imp.find_module(cape_name, [malwareconfig_parsers])
                    module = imp.load_module(cape_name, file, pathname, description)
                    malwareconfig_loaded = True
                    log.info("CAPE: Imported malwareconfig.com parser %s", cape_name)
                except ImportError:
                    log.info("CAPE: malwareconfig.com parser: No module named %s", cape_name)
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
                                with open(filepath, 'w') as cfile:
                                    cfile.write(bindata)
                            elif "binary" in script_data["datatype"]:
                                file_info["cape_type"] = "MoreEggsBin"
                                outstr = str(MOREEGGSBIN_PAYLOAD) + "," + tmpstr + "\n"
                                with open(filepath + "_info.txt", "w") as infofd:
                                    infofd.write(outstr)
                                with open(filepath, 'wb') as cfile:
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
                self.upx_unpack(file_data, CAPE_output)

            # Check for a payload or config hit
            extraction_types = [
                "payload",
                "config",
                "loader"
                ]
            try:
                for type in extraction_types:
                    if type in hit["meta"]["cape_type"].lower():
                        file_info["cape_type"] = hit["meta"]["cape_type"]
                        cape_name = hit["name"].replace('_', ' ')
            except:
                pass
            type_strings = file_info["type"].split()
            if "-bit" not in file_info["cape_type"]:
                if type_strings[0] in ("PE32+", "PE32"):
                    file_info["cape_type"] += pe_map[type_strings[0]]
                    if type_strings[2] == ("(DLL)"):
                        file_info["cape_type"] += "DLL"
                    else:
                        file_info["cape_type"] += "executable"

            suppress_parsing_list = ["Cerber", "Emotet_Payload", "Ursnif", "QakBot"]

            if hit["name"] in suppress_parsing_list:
                continue

            cape_config = static_config_parsers(hit["name"], file_data, cape_config)

        if cape_name:
            if "cape_config" in cape_config and "cape_name" not in cape_config:
                cape_config["cape_name"] = format(cape_name)
            if not "cape" in self.results:
                if cape_name != "UPX":
                    self.results["cape"] = cape_name

        # Remove duplicate payloads from web ui
        for cape_file in CAPE_output:
            if file_info["size"] == cape_file["size"]:
                if HAVE_PYDEEP:
                    ssdeep_grade = pydeep.compare(file_info["ssdeep"].encode("utf-8"), cape_file["ssdeep"].encode("utf-8"))
                    if ssdeep_grade >= ssdeep_threshold:
                        append_file = False
                if file_info.get("entrypoint", False) and file_info.get("ep_bytes", False):
                    if file_info["entrypoint"] and file_info["entrypoint"] == cape_file["entrypoint"] \
                        and file_info["ep_bytes"] == cape_file["ep_bytes"]:
                        append_file = False

        if append_file is True:
            CAPE_output.append(file_info)
        return file_info

    def run(self):
        """Run analysis.
        @return: list of CAPE output files with related information.
        """
        global cape_config
        cape_config = {}
        self.key = "CAPE"
        CAPE_output = []
        self.script_dump_files = []
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

        for folder in ("CAPE_path", "procdump_path", "dropped_path"):
            if hasattr(self, folder):
                # Process dynamically dumped CAPE/procdumps files/dropped might
                # be detected as payloads and trigger config parsing
                for dir_name, dir_names, file_names in os.walk(getattr(self, folder)):
                    for file_name in file_names:
                        file_path = os.path.join(dir_name, file_name)
                        # We want to exclude duplicate files from display in ui
                        if folder not in ("procdump_path", "dropped_path") and len(file_name) <= 64:
                            self.process_file(file_path, CAPE_output, True, meta[file_path])
                        #else:
                            # We set append_file to False as we don't wan't to include
                            # the files by default in the CAPE tab
                            #self.process_file(file_path, CAPE_output, False)

                # Process files that may have been decrypted from ScriptDump
                for file_path in self.script_dump_files:
                    self.process_file(file_path, CAPE_output, False, meta[file_path])

        # Finally static processing of submitted file
        if self.task["category"] in ("file", "static"):
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError("Sample file doesn't exist: \"%s\"" % self.file_path)

        self.process_file(self.file_path, CAPE_output, False, meta.get(self.file_path, {}))
        if "cape_config" in cape_config:
            CAPE_output.append(cape_config)

        return CAPE_output
