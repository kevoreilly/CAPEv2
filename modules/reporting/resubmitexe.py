# Copyright (C) 2014-2015 Will Metcalf william.metcalf@gmail.com
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
import json
import logging

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import to_unicode
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)

db = Database()


class ReSubmitExtractedEXE(Report):
    def run(self, results):
        self.noinject = self.options.get("noinject", False)
        self.resublimit = int(self.options.get("resublimit", 5))
        filesdict = {}
        self.task_options_stack = []
        self.task_options = None
        self.task_custom = None
        self.machine = None
        self.resubcnt = 0
        self.tlp = None
        meta = dict()
        report = dict(results)

        if "options" in report["info"] and "resubmitjob" in report["info"]["options"] and report["info"]["options"]["resubmitjob"]:
            return

        # copy all the options from current
        if report["info"].get("options", False):
            for key, val in report["info"]["options"].items():
                self.task_options_stack.append(key + "=" + str(val))

        # copy machine label from current
        if report["info"].get("machine", False):
            self.machine = report["info"]["machine"]["label"]

        # copy TLP from current
        if report["info"].get("tlp", False):
            self.tlp = report["info"]["tlp"]

        self.task_options_stack.append("resubmitjob=true")
        if self.noinject:
            self.task_options_stack.append("free=true")

        if self.task_options_stack:
            self.task_options = ",".join(self.task_options_stack)

        report = dict(results)
        if report.get("dropped"):
            if os.path.exists(self.files_metadata):
                for line in open(self.files_metadata, "rb"):
                    entry = json.loads(line)
                    filepath = os.path.join(self.analysis_path, entry["path"])
                    meta[filepath] = {
                        "pids": entry["pids"],
                        "filepath": entry["filepath"],
                        "metadata": entry["metadata"],
                    }
        for dropped in report.get("dropped", []):
            if self.resubcnt >= self.resublimit:
                break
            if os.path.isfile(dropped["path"]):
                if (
                    ("PE32" in dropped["type"] or "MS-DOS" in dropped["type"])
                    and "DLL" not in dropped["type"]
                    and "native" not in dropped["type"]
                ):
                    if dropped["sha256"] not in filesdict:
                        srcpath = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(report["info"]["id"]), "files", dropped["sha256"])
                        linkdir = os.path.join(
                            CUCKOO_ROOT, "storage", "analyses", str(report["info"]["id"]), "files", dropped["sha256"] + "_link"
                        )

                        metastrings = meta[dropped["path"]].get("metadata", "").split(";?")
                        if len(metastrings) < 2:
                            continue

                        guest_name = metastrings[1].split("\\")[-1]
                        linkpath = os.path.join(linkdir, guest_name)
                        if not os.path.exists(linkdir):
                            os.makedirs(linkdir, mode=0o755)
                        try:
                            if not os.path.exists(linkpath):
                                os.symlink(srcpath, linkpath)
                            filesdict[dropped["sha256"]] = linkpath
                            self.resubcnt += 1
                        except:
                            filesdict[dropped["sha256"]] = dropped["path"]
                            self.resubcnt += 1

        # ToDo i think this is outdated
        if "suricata" in report and report["suricata"]:
            if "files" in report["suricata"] and report["suricata"]["files"]:
                for suricata_file_e in results["suricata"]["files"]:
                    # don't resubmit truncated files or files with invalid fileinfo metadata
                    if suricata_file_e.get("file_info", {}).get("size", 1) != suricata_file_e.get("size", 0):
                        continue
                    if self.resubcnt >= self.resublimit:
                        break
                    if "file_info" in suricata_file_e:
                        tmp_suricata_file_d = dict(suricata_file_e)
                        if os.path.isfile(suricata_file_e["file_info"]["path"]):
                            ftype = suricata_file_e["file_info"]["type"]
                            if ("PE32" in ftype or "MS-DOS" in ftype) and "DLL" not in ftype and "native" not in ftype:
                                if suricata_file_e["file_info"]["sha256"] not in filesdict:
                                    filesdict[suricata_file_e["file_info"]["sha256"]] = suricata_file_e["file_info"]["path"]
                                    self.resubcnt = self.resubcnt + 1

        for e in filesdict:
            if not File(filesdict[e]).get_size():
                continue
            if not db.find_sample(sha256=e) is None:
                continue

            self.task_custom = "Parent_Task_ID:%s" % report["info"]["id"]
            if "custom" in report["info"] and report["info"]["custom"]:
                self.task_custom = "%s Parent_Custom:%s" % (self.task_custom, report["info"]["custom"])
            task_id = db.add_path(
                file_path=filesdict[e],
                package="exe",
                timeout=200,
                options=self.task_options,
                priority=1,
                machine=self.machine or "",
                platform=None,
                custom=self.task_custom,
                memory=False,
                enforce_timeout=False,
                clock=None,
                tags=None,
                parent_id=int(report["info"]["id"]),
                tlp=self.tlp,
            )

            if task_id:
                log.info(u'Resubmitexe file "{0}" added as task with ID {1}'.format(filesdict[e], task_id))
            else:
                log.warn("Error adding resubmitexe task to database")
