# Copyright (C) 2022 Kevin Ross
#
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

from lib.cuckoo.common.abstracts import Signature


class CAPEExtractedContent(Signature):
    name = "cape_extracted_content"
    description = "CAPE detected injection into a browser process, likely for Man-In-Browser (MITB) infostealing"
    severity = 3
    categories = ["banker", "injection"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1185"]

    def run(self):
        browsertargets = [
            "chrome.exe",
            "firefox.exe",
            "iexplore.exe",
            "microsoftedge.exe",
            "microsoftedgecp.exe",
            "runtimebroker.exe",  # https://www.sentinelone.com/labs/how-trickbot-malware-hooking-engine-targets-windows-10-browsers/
        ]

        ret = False
        for cape in self.results.get("CAPE", {}).get("payloads", []) or []:
            targetproc = cape.get("target_process") or cape.get("cape_type")
            if targetproc and targetproc.lower() in browsertargets:
                targetpid = cape.get("target_pid") or cape.get("cape_type")
                targetpath = cape.get("target_path") or cape.get("cape_type")
                injectingproc = cape.get("process_path") or cape.get("cape_type")
                injectingpid = cape.get("pid") or cape.get("cape_type")
                if targetpid and targetpath and injectingproc and injectingpid:
                    self.data.append(
                        {
                            "browser_inject": "%s pid %s injected into %s with path %s and pid %s"
                            % (injectingproc, injectingpid, targetproc, targetpath, targetpid)
                        }
                    )
                    ret = True

        return ret
