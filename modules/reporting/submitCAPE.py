# encoding: utf-8
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
import logging
import requests

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import to_unicode
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)

reporting_conf = Config("reporting")
distributed = reporting_conf.submitCAPE.distributed
report_key = reporting_conf.submitCAPE.keyword

NUMBER_OF_DEBUG_REGISTERS = 4
bp = 0

cape_package_list = [
    "Emotet",
    "Emotet_doc",
    "Unpacker",
    "Unpacker_dll",
    "Unpacker_regsvr",
    "Unpacker_zip",
    "Unpacker_ps1",
    "Unpacker_js",
    "Hancitor",
    "Hancitor_dll",
    "Hancitor_doc",
    "PlugX",
    "PlugXPayload",
    "PlugX_dll",
    "PlugX_doc",
    "PlugX_zip",
    "RegBinary",
    "Shellcode-Extraction",
    "TrickBot",
    "TrickBot_doc",
    "UPX",
    "UPX_dll",
]

unpackers = {
    "ps1": "Unpacker_ps1",
    "dll": "Unpacker_dll",
    "regsvr": "Unpacker_regsvr",
    "zip": "Unpacker_zip",
    "js": "Unpacker_js",
    "exe": "Unpacker",
}

plugx = {
    "PlugXPayload": "PlugXPayload",
    "zip": "PlugX_zip",
    "doc": "PlugX_doc",
    "dll": "PlugX_dll",
    "exe": "PlugX",
}


class SubmitCAPE(Report):
    def process_cape_yara(self, cape_yara, results, detections):
        global bp

        if "cape_options" in cape_yara["meta"]:
            cape_options = cape_yara["meta"]["cape_options"].split(",")

            address = 0
            new_options = ""
            suffix = ""
            for option in cape_options:
                name, value = option.split("=")
                if name in ("bp0", "br0", 0):
                    bp = 1
                elif name in ("bp1", "br1", 1):
                    bp = 2
                elif name in ("bp2", "br2", 2):
                    bp = 3
                elif name in ("bp3", "br3", 3):
                    bp = 4
                elif bp == NUMBER_OF_DEBUG_REGISTERS:
                    break
                elif name in ("bp", "br") and value.startswith("$"):
                    for hit in cape_yara["addresses"]:
                        pattern = False
                        if "-" in value:
                            pattern = "-"
                        elif "+" in value:
                            pattern = "+"

                        if pattern:
                            suffix = pattern + value.split(pattern)[1]
                            value = value.split(pattern)[0]

                        if value.strip("$") in hit and str(cape_yara["addresses"][hit]) not in self.task_options:
                            address = cape_yara["addresses"][hit]
                            option = "{0}{1}={2}{3}".format(name, bp, address, suffix)
                            bp = bp + 1
                if option not in self.task_options:
                    if new_options == "":
                        new_options = option
                    else:
                        new_options = new_options + "," + option

            if not address:
                return

            if "procdump=1" in self.task_options:
                self.task_options = self.task_options.replace(u"procdump=1", u"procdump=0", 1)

            if "extraction=1" in self.task_options:
                self.task_options = self.task_options.replace(u"extraction=1", u"extraction=0", 1)

            if "combo=1" in self.task_options:
                self.task_options = self.task_options.replace(u"combo=1", u"combo=0", 1)

            if "file-offsets" in self.task_options:
                self.task_options = self.task_options.replace(u"file-offsets=0", u"file-offsets=0", 1)
            else:
                self.task_options = self.task_options + ",file-offsets=1"

            log.info("options = %s", new_options)
            self.task_options = self.task_options + "," + new_options
            if "auto=" not in self.task_options:
                self.task_options = self.task_options + ",auto=1"

            return

        if "disable_cape=1" in self.task_options:
            return

        if cape_yara["name"] == "TrickBot":
            detections.add("TrickBot")

        if cape_yara["name"] == "Hancitor":
            detections.add("Hancitor")

    def submit_task(
        self, target, package, timeout, task_options, priority, machine, platform, memory, enforce_timeout, clock, tags, parent_id, tlp
    ):

        db = Database()

        if os.path.exists(target):
            task_id = False
            if distributed:
                options = {
                    "package": package,
                    "timeout": timeout,
                    "options": task_options,
                    "priority": priority,
                    # "machine": machine,
                    "platform": platform,
                    "memory": memory,
                    "enforce_timeout": enforce_timeout,
                    "clock": clock,
                    "tags": tags,
                    "parent_id": parent_id,
                }
                multipart_file = [("file", (os.path.basename(target), open(target, "rb")))]
                try:
                    res = requests.post(reporting_conf.submitCAPE.url, files=multipart_file, data=options)
                    if res and res.ok:
                        task_id = res.json()["data"]["task_ids"][0]
                except Exception as e:
                    log.error(e)
            else:
                task_id = db.add_path(
                    file_path=target,
                    package=package,
                    timeout=timeout,
                    options=task_options,
                    priority=priority,  # increase priority to expedite related submission
                    machine=machine,
                    platform=platform,
                    memory=memory,
                    enforce_timeout=enforce_timeout,
                    clock=None,
                    tags=None,
                    parent_id=parent_id,
                    tlp=tlp,
                )
            if task_id:
                log.info(u'CAPE detection on file "{0}": {1} - added as CAPE task with ID {2}'.format(target, package, task_id))
                return task_id
            else:
                log.warn("Error adding CAPE task to database: {0}".format(package))
        else:
            log.info("File doesn't exists")

    def run(self, results):
        self.task_options_stack = []
        self.task_options = None
        self.task_custom = None
        detections = set()
        children = []
        bp = 0

        # allow ban unittests
        filename = results.get("target", {}).get("file", {}).get("name", "")
        filenames = ("_test_00", "danabot")
        if any(fn in filename for fn in filenames):
            return
        # We only want to submit a single job if we have a
        # malware detection. A given package should do
        # everything we need for its respective family.
        package = None

        # allow custom extractors
        if report_key in results:
            return

        self.task_options = self.task["options"]
        if not self.task_options:
            return

        if "auto" in self.task_options:
            return

        # We want to suppress spawned jobs if a config
        # has already been extracted
        for entry in results.get("CAPE", []):
            if isinstance(entry, dict) and entry.get("cape_config"):
                return

        parent_package = results["info"].get("package")

        # Initial static hits from CAPE's yara signatures
        for entry in results.get("target", {}).get("file", {}).get("cape_yara", []):
            self.process_cape_yara(entry, results, detections)

        for pattern in ("procdump", "CAPE", "dropped"):
            for file in results.get(pattern, []) or []:
                if "cape_yara" in file:
                    for entry in file["cape_yara"]:
                        self.process_cape_yara(entry, results, detections)

        if "auto=1" in self.task_options:
            if parent_package and parent_package in unpackers.values():
                return

            parent_id = int(results["info"]["id"])
            if results.get("info", {}).get("options", {}).get("main_task_id", ""):
                parent_id = int(results.get("info", {}).get("options", {}).get("main_task_id", ""))

            self.task_custom = "Parent_Task_ID:%s" % results["info"]["id"]
            if results.get("info", {}).get("custom"):
                self.task_custom = "%s Parent_Custom:%s" % (self.task_custom, results["info"]["custom"])

            log.debug("submit_task options: %s", self.task_options)
            task_id = self.submit_task(
                self.task["target"],
                self.task["package"],
                self.task["timeout"],
                self.task_options,
                self.task["priority"] + 1,  # increase priority to expedite related submission
                self.task["machine"],
                self.task["platform"],
                self.task["memory"],
                self.task["enforce_timeout"],
                None,
                None,
                parent_id,
                self.task["tlp"],
            )
            if task_id:
                children = []
                children.append([task_id, self.task["package"]])
                results["CAPE_children"] = children

            return

        if "disable_cape=1" in self.task_options:
            return

        # Dynamic CAPE hits from packers
        if "signatures" in results:
            for entry in results["signatures"]:
                if parent_package:
                    if entry["name"] == "Unpacker":
                        if parent_package == "doc":
                            continue

                        if parent_package in unpackers:
                            detections.add(unpackers[parent_package])
                            continue

                    # Specific malware family packages
                    elif entry["name"] == "PlugX" and parent_package in plugx:
                        detections.add(plugx[parent_package])
                        package = plugx[parent_package]
                        continue

        elif "TrickBot" in detections:
            if parent_package == "doc":
                package = "TrickBot_doc"
            elif parent_package == "exe":
                package = "TrickBot"

        elif "Hancitor" in detections:
            if parent_package in ("doc"):
                package = "Hancitor_doc"
            elif parent_package in ("exe"):
                package = "Hancitor"
            elif parent_package in ("dll"):
                package = "Hancitor_dll"

        # if 'RegBinary' in detections or 'CreatesLargeKey' in detections:
        elif "RegBinary" in detections:
            package = "RegBinary"

        # we want to switch off automatic process dumps in CAPE submissions
        if self.task_options and "procdump=1" in self.task_options:
            self.task_options = self.task_options.replace(u"procdump=1", u"procdump=0", 1)
        if self.task_options_stack:
            self.task_options = ",".join(self.task_options_stack)

        parent_id = int(results["info"]["id"])
        if results.get("info", {}).get("options", {}).get("main_task_id", ""):
            parent_id = int(results.get("info", {}).get("options", {}).get("main_task_id", ""))

        if package and package != parent_package:
            self.task_custom = "Parent_Task_ID:%s" % results["info"]["id"]
            if results.get("info", {}).get("custom"):
                self.task_custom = "%s Parent_Custom:%s" % (self.task_custom, results["info"]["custom"])
            task_id = self.submit_task(
                self.task["target"],
                package,
                self.task["timeout"],
                self.task_options,
                # increase priority to expedite related submission
                self.task["priority"] + 1,
                self.task["machine"],
                self.task["platform"],
                self.task["memory"],
                self.task["enforce_timeout"],
                None,
                None,
                parent_id,
                self.task["tlp"],
            )
            if task_id:
                children.append([task_id, package])

        else:  # nothing submitted, only 'dumpers' left
            if parent_package in cape_package_list:
                return

            self.task_custom = "Parent_Task_ID:%s" % results["info"]["id"]
            if results.get("info", {}).get("custom"):
                self.task_custom = "%s Parent_Custom:%s" % (self.task_custom, results["info"]["custom"])

            for dumper in detections:
                task_id = self.submit_task(
                    self.task["target"],
                    dumper,
                    self.task["timeout"],
                    self.task_options,
                    # increase priority to expedite related submission
                    self.task["priority"] + 1,
                    self.task["machine"],
                    self.task["platform"],
                    self.task["memory"],
                    self.task["enforce_timeout"],
                    None,
                    None,
                    parent_id,
                    self.task["tlp"],
                )
                if task_id:
                    children.append([task_id, dumper])

        if children:
            results["CAPE_children"] = children

        return
