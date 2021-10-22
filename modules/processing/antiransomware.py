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
import json
import logging
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger()
# ToDo store list of exclude files if conf enable to store them
proc_cfg = Config("processing")
skip_number = proc_cfg["antiransomware"]["skip_number"]
do_not_skip = ('txt', 'dll', 'msi', 'msp', 'appx', 'pub', 'doc', 'dot', 'docx', 'dotx', 'docm', 'dotm', 'docb', 'rtf', 'mht', 'mso', 'wbk', 'wiz', 'xls', 'xlt', 'xlm', 'xlsx', 'xltx', 'xlsm', 'xltm', 'xlsb', 'xla', 'xlam', 'xll', 'xlw', 'slk', 'xll', 'csv', 'ppt', 'ppa', 'pot', 'pps', 'pptx', 'pptm', 'potx', 'potm', 'ppam', 'ppsx', 'ppsm', 'sldx', 'sldm', 'jar', 'reg', 'swf', 'fws', 'py', 'pyc', 'pyw', 'ps1', 'js', 'jse', 'html', 'url', 'xps', 'hta', 'mht', 'lnk', 'chm', 'hwp', 'hwpx', 'hwt', 'hml', 'inp', 'int', 'xsl', 'xslt', 'wsf', 'pdf', 'vbs', 'vbe', 'csproj', 'vbproj', 'vcxproj', 'dbproj', 'fsproj', 'zip', 'cpl', 'jtd', 'jtdc', 'jttc', 'jtt')

class AntiRansomware(Processing):
    """Disable processing encrypted files."""

    def run(self):
        """Run analysis."""

        extensions = dict()
        tmp_ext_list = dict()
        self.report["ransom_exclude_files"] = list()
        with open(self.files_metadata, "rb") as f:
            for line in f.readlines():
                filename = json.loads(line).get("filepath", "")
                print(filename)
                if filename and not "." in filename:
                    continue
                ext = filename.rsplit(".")
                # do not count interesting extensions
                if ext and ext[-1] not in do_not_skip:
                    extensions.setdefault(ext[-1], 0)
                    extensions[ext[-1]] += 1
                    tmp_ext_list.setdefault(ext[-1], list())
                    tmp_ext_list[ext[-1]].append(filename)


        for ext, count in extensions.iteritems():
            if count > skip_number:
                log.debug(f"Skipping all files with extension: {ext}")
                self.report["ransom_exclude_files"] += tmp_ext_list.get(ext, [])

