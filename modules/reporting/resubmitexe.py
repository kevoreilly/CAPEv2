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
import logging
import requests
import ntpath
import datetime

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import to_unicode, sanitize_filename
from lib.cuckoo.core.database import Database

log = logging.getLogger(__name__)

interesting_file_types = [
    "UDF filesystem data",
    "PDF",
    "Rich Text Format",
    "Microsoft Word",
    "Microsoft Office Word",
    "OpenDocument Text",
    "Microsoft Office Excel",
    "OpenDocument Spreadsheet",
    "Microsoft PowerPoint",
    "OpenDocument Presentation",
    "ACE archive",
    "PowerISO Direct-Access-Archive",
    "RAR archive",
    "POSIX tar archive",
    "7-zip archive",
    "ISO 9660",
    "gzip compressed data, was",
    "Microsoft Disk Image, Virtual Server or Virtual PC",
    "Outlook",
    "Message",
    "DOS batch file, ASCII text",
]

interesting_file_extensions = [
    ".doc",
    ".dot",
    ".docx",
    ".dotx",
    ".docm",
    ".dotm",
    ".docb",
    ".rtf",
    ".mht",
    ".mso",
    ".odt",
    ".cpl",
    ".pdf",
    ".xls",
    ".xlt",
    ".xlm",
    ".xlsx",
    ".xltx",
    ".xlsm",
    ".xltm",
    ".xlsb",
    ".xla",
    ".xlam",
    ".xll",
    ".xlw",
    ".csv",
    ".slk",
    ".ods",
    ".ppt",
    ".pot",
    ".pps",
    ".pptx",
    ".pptm",
    ".potx",
    ".potm",
    ".ppam",
    ".ppsx",
    ".ppsm",
    ".sldx",
    ".sldm",
    ".odp",
    ".vbs",
    ".jse",
    ".vbe",
    ".msi",
    ".ps1",
    ".exe",
    ".z",
    ".ace",
    ".iso",
    ".bin",
    ".tar.bz2",
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".rar",
    ".zip",
    ".7z",
    ".bup",
    ".cab",
    ".daa",
    ".eml",
    ".gzip",
    ".msg",
    ".mso",
    ".lzh",
    ".img",
    ".vhd",
    ".scr",
    ".wsf",
    ".bat",
    ".lnk",
    ".sct",
    ".chm",
    ".hta",
    ".cmd",
    ".wbk",
]


whitelisted_names = [
    "outlook.pst",
    "readerdcmanifest3.msi",
    "normal.dotm",
    "equations.dotx",
    "word15.customui",
    ".rels",
    "~wrd0000.tmp",
]


class ReSubmitExtractedEXE(Report):
    def run(self, results):
        self.noinject = self.options.get("noinject", False)
        self.resublimit = int(self.options.get("resublimit", 5))
        self.distributed = self.options.get("distributed", False)
        self.resuburl = self.options.get("url", "http://127.0.0.1:8000/apiv2/tasks/create/file/")
        self.job_cache_timeout_minutes = self.options.get("job_cache_timeout_minutes", 180)
        filesdict = {}
        self.task_options_stack = []
        self.task_options = None
        self.task_custom = None
        self.machine = None
        self.resubcnt = 0
        self.sigfile_list = []
        report = dict(results)
        self.results = results

        if (
            "options" in report["info"] and "resubmitjob" in report["info"]["options"] and report["info"]["options"]["resubmitjob"]
        ) or ("Parent_Task_ID" in results.get("info", {}).get("custom", "")):
            log.warning("Bailing out of resubexe this is a child task")
            return
        if "signatures" in results and results["signatures"]:
            for entry in results.get("signatures", []):
                if entry.get("name", "") == "zwhitelistedcerts":
                    if entry.get("data", []):
                        log.info("Skipping resub our top listed object was signed by a whitelisted cert")
                        return
        try:
            if "signatures" in results and results["signatures"]:
                for entry in results.get("signatures", []):
                    if entry.get("name", "") == "office_write_exe":
                        exe_writes = entry.get("data", [])
                        for entry in exe_writes:
                            mfile = entry.get("office_write_exe_magic", "")
                            if mfile:
                                mfile2 = re.sub(r"_[A-Za-z0-9]+\.[Ee][Xx][Ee]$", "", mfile)
                                if mfile2 not in self.sigfile_list:
                                    self.sigfile_list.append(mfile2)
        except Exception as e:
            log.info("Problem hunting for office exe magic files {0}".format(e))

        if "options" in report["info"] and report["info"]["options"]:
            for key, val in list(report["info"]["options"].items()):
                self.task_options_stack.append(key + "=" + str(val))

        if "machine" in report["info"] and report["info"]["machine"]:
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
        for dropped in report.get("dropped", []):
            if results["target"]["category"] == "file" and self.results["target"]["file"]["sha256"] == dropped["sha256"]:
                continue
            skip_it = False
            for gpath in dropped["guest_paths"]:
                if "." in gpath and skip_it == False:
                    lfile = ntpath.basename(gpath).lower()
                    if lfile in whitelisted_names:
                        skip_it = True
            if skip_it == True:
                continue

            if (
                os.path.isfile(dropped["path"])
                and dropped["size"] > 0xA2
                and (all(x not in whitelisted_names for x in dropped["name"]))
                and ("Security: 1" not in dropped["type"])
            ):
                if (
                    (
                        ("PE32" in dropped["type"] or "MS-DOS" in dropped["type"])
                        and "DLL" not in dropped["type"]
                        and "native" not in dropped["type"]
                    )
                    or any(x in dropped["type"] for x in interesting_file_types)
                    and dropped["name"]
                ):
                    if dropped["sha256"] not in filesdict:
                        srcpath = os.path.join(
                            CUCKOO_ROOT, "storage", "analyses", str(report["info"]["id"]), "files", dropped["sha256"]
                        )
                        linkdir = os.path.join(
                            CUCKOO_ROOT, "storage", "analyses", str(report["info"]["id"]), "files", dropped["sha256"] + "_link"
                        )
                        guest_name = ntpath.basename(dropped["name"][0])
                        linkpath = os.path.join(linkdir, guest_name)
                        if not os.path.exists(linkdir):
                            os.makedirs(linkdir, mode=0o755)
                        try:
                            if not os.path.exists(linkpath):
                                os.symlink(srcpath, linkpath)
                            filesdict[dropped["sha256"]] = linkpath
                        except:
                            filesdict[dropped["sha256"]] = dropped["path"]
                else:
                    for gpath in dropped["guest_paths"]:
                        if "." in gpath:
                            lfile = ntpath.basename(gpath).lower()
                            base, ext = ntpath.splitext(lfile)
                            if ext in interesting_file_extensions or gpath in self.sigfile_list:
                                if dropped["sha256"] not in filesdict:
                                    srcpath = os.path.join(
                                        CUCKOO_ROOT, "storage", "analyses", str(report["info"]["id"]), "files", dropped["sha256"]
                                    )
                                    linkdir = os.path.join(
                                        CUCKOO_ROOT,
                                        "storage",
                                        "analyses",
                                        str(report["info"]["id"]),
                                        "files",
                                        dropped["sha256"] + "_link",
                                    )
                                    linkpath = os.path.join(linkdir, ntpath.basename(gpath))
                                    if not os.path.exists(linkdir):
                                        os.makedirs(linkdir, mode=0o755)
                                    try:
                                        if not os.path.exists(linkpath):
                                            os.symlink(srcpath, linkpath)
                                        filesdict[dropped["sha256"]] = linkpath
                                    except:
                                        filesdict[dropped["sha256"]] = dropped["path"]

        if "suricata" in report and report["suricata"]:
            if "files" in report["suricata"] and report["suricata"]["files"]:
                for suricata_file_e in results["suricata"]["files"]:
                    if not suricata_file_e.get("file_info", {}):
                        continue
                    # don't resubmit truncated files
                    if suricata_file_e.get("file_info", {}).get("size", -1) != suricata_file_e.get("size", -2):
                        continue
                    if (
                        results["target"]["category"] == "file"
                        and results["target"]["file"]["sha256"] == suricata_file_e["file_info"]["sha256"]
                    ):
                        continue

                    if "file_info" in suricata_file_e:
                        tmp_suricata_file_d = dict(suricata_file_e)
                        if os.path.isfile(suricata_file_e["file_info"]["path"]):
                            ftype = suricata_file_e["file_info"]["type"]
                            if ("PE32" in ftype or "MS-DOS" in ftype) and "DLL" not in ftype and "native" not in ftype:
                                if suricata_file_e["file_info"]["sha256"] not in filesdict:
                                    filesdict[suricata_file_e["file_info"]["sha256"]] = suricata_file_e["file_info"]["path"]

        db = Database()

        for e in filesdict:
            if not File(filesdict[e]).get_size():
                continue
            if self.resubcnt >= self.resublimit:
                log.info("Hit resub limit of {0}. Stopping Iteration".format(self.resublimit))
                break
            find_sample = db.find_sample(sha256=e)
            if find_sample:
                stasks = db.list_tasks(sample_id=find_sample.id)
                subbed_hash = False
                added_previous = False
                for entry in stasks:
                    if subbed_hash:
                        continue

                    tid = entry.id
                    tstart = entry.started_on
                    cat = entry.category
                    target = entry.target
                    if cat == "file":
                        if (
                            ((tstart + datetime.timedelta(minutes=self.job_cache_timeout_minutes)) > datetime.datetime.utcnow())
                            and target
                            and os.path.basename(target) == sanitize_filename(os.path.basename(filesdict[e]))
                        ) and tid not in self.results.get("resubs", []):
                            log.info(
                                "Adding previous task run to our resub list {0} for hash {1} and filename {2}".format(
                                    tid, e, filesdict[e]
                                )
                            )
                            self.results.setdefault("resubs", list()).append(tid)
                            added_previous = True
                            continue
                        else:
                            if not added_previous and not subbed_hash:
                                self.task_custom = "Parent_Task_ID:%s" % report["info"]["id"]
                                if "custom" in report["info"] and report["info"]["custom"]:
                                    self.task_custom = "%s Parent_Custom:%s" % (self.task_custom, report["info"]["custom"])
                                task_ids_new = None
                                if self.distributed and self.resuburl:
                                    options = {
                                        "priority": 1,
                                        "options": self.task_options,
                                        "custom": self.task_custom,
                                        "parent_id": int(report["info"]["id"]),
                                        "timeout": 90,
                                    }
                                    multipart_file = [("file", (os.path.basename(filesdict[e]), open(filesdict[e], "rb")))]
                                    try:
                                        log.info("Going to try to resub {0} via the api".format(filesdict[e]))
                                        res = requests.post(self.resuburl, files=multipart_file, data=options)
                                        if res and res.ok:
                                            task_ids_new = res.json()["data"]["task_ids"]
                                    except Exception as e:
                                        log.error(e)

                                else:
                                    task_ids_new = db.demux_sample_and_add_to_db(
                                        file_path=filesdict[e],
                                        package="",
                                        timeout=0,
                                        priority=1,
                                        options=self.task_options,
                                        machine="",
                                        platform=None,
                                        tags=None,
                                        custom=self.task_custom,
                                        memory=False,
                                        enforce_timeout=False,
                                        clock=None,
                                        shrike_url=None,
                                        shrike_msg=None,
                                        shrike_sid=None,
                                        shrike_refer=None,
                                    )

                                if task_ids_new:
                                    for task_id in task_ids_new:
                                        log.info(
                                            'Resubmitexe file "{0}" added as task with ID {1} resub count {2}'.format(
                                                filesdict[e], task_id, self.resubcnt
                                            )
                                        )
                                        self.results.setdefault("resubs", list()).append(task_id)
                                        self.resubcnt = self.resubcnt + 1
                                        subbed_hash = True

            else:
                self.task_custom = "Parent_Task_ID:%s" % report["info"]["id"]
                if "custom" in report["info"] and report["info"]["custom"]:
                    self.task_custom = "%s Parent_Custom:%s" % (self.task_custom, report["info"]["custom"])
                task_ids_new = None
                if self.distributed and self.resuburl:
                    options = {
                        "priority": 1,
                        "options": self.task_options,
                        "custom": self.task_custom,
                        "parent_id": int(report["info"]["id"]),
                        "timeout": 90,
                    }
                    multipart_file = [("file", (os.path.basename(filesdict[e]), open(filesdict[e], "rb")))]
                    try:
                        log.info("Going to try to resub {0} via the api".format(filesdict[e]))
                        res = requests.post(self.resuburl, files=multipart_file, data=options)
                        if res and res.ok:
                            task_ids_new = res.json()["data"]["task_ids"]
                    except Exception as e:
                        log.error(e)
                else:
                    task_ids_new = db.demux_sample_and_add_to_db(
                        file_path=filesdict[e],
                        package="",
                        timeout=0,
                        priority=1,
                        options=self.task_options,
                        machine="",
                        platform=None,
                        tags=None,
                        custom=self.task_custom,
                        memory=False,
                        enforce_timeout=False,
                        clock=None,
                        shrike_url=None,
                        shrike_msg=None,
                        shrike_sid=None,
                        shrike_refer=None,
                    )

                if task_ids_new:
                    for task_id in task_ids_new:
                        log.info(
                            'Resubmitexe file "{0}" added as task with ID {1} resub count {2}'.format(
                                filesdict[e], task_id, self.resubcnt
                            )
                        )
                        self.results.setdefault("resubs", list()).append(task_id)
                        self.resubcnt = self.resubcnt + 1
                else:
                    log.warn("Error adding resubmitexe task to database")
