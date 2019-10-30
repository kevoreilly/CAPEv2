# Copyright (C) 2015 KillerInstinct
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class Upatre_APIs(Signature):
    name = "upatre_behavior"
    description = "Exhibits behavior characteristic of Upatre downloader"
    weight = 3
    severity = 3
    categories = ["dropper"]
    families = ["Upatre"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.created_procs = list()
        self.requestcount = 0
        self.url_buffer = ""
        self.current_handle = ""
        self.network_data = set()
        self.campaign = ""
        self.deletes_parentfile = False
        self.hostname = ""
        self.bad_pid = 0
        self.first_pid = 0
        self.first_path = ""
        if "behavior" in self.results.keys():
            if "processtree" in self.results["behavior"].keys() and self.results["behavior"]["processtree"]:
                first_process = self.results["behavior"]["processtree"][0]
                self.first_pid = first_process["pid"]
                self.first_path = str(first_process["module_path"])
                if first_process["children"]:
                    self.bad_pid = first_process["children"][0]["pid"]

    filter_apinames = set(["DeleteFileA", "GetComputerNameW",
                           "InternetConnectW", "HttpOpenRequestW",
                           "CreateProcessInternalW"])

    def on_call(self, call, process):
        # We only care about top-most parent and first child processes
        if process["process_id"] == self.first_pid or process["process_id"] == self.bad_pid:
            if call["api"] == "CreateProcessInternalW":
                cli = self.get_argument(call, "CommandLine")
                if cli == "svchost.exe":
                    flags = int(self.get_argument(call, "CreationFlags"), 16)
                    # Only add if it's created with CREATE_SUSPENDED
                    if flags & 0x4:
                        self.created_procs.append(cli)
                else:
                    self.created_procs.append(cli)

        # We only care about the first child of the top-most parent process
        if process["parent_id"] == self.first_pid and process["process_id"] == self.bad_pid:
            if call["api"] == "DeleteFileA":
                buf = self.get_argument(call, "FileName")
                if buf and buf == self.first_path:
                    self.deletes_parentfile = True

            elif call["api"] == "GetComputerNameW":
                if not self.hostname:
                    self.hostname = self.get_argument(call, "ComputerName")

            elif call["api"] == "InternetConnectW":
                self.current_handle = call["return"]
                servername = self.get_argument(call, "ServerName")
                serverport = self.get_argument(call, "ServerPort")
                self.url_buffer = "{0}:{1}".format(servername, serverport)

            elif call["api"] == "HttpOpenRequestW":
                handle = self.get_argument(call, "InternetHandle")
                url = self.get_argument(call, "Path")
                if handle == self.current_handle:
                    self.requestcount += 1
                    # Ignore Recon IP Checking Request
                    if self.requestcount > 1:
                        rex = "/([^/]+)/" + self.hostname + "/[^/]+/\d{1,3}-"
                        tmp = re.match(rex, url)
                        if tmp:
                            # Upatre structured URI
                            if not self.campaign:
                                self.campaign = tmp.group(1)
                        else:
                            # Potential payload
                            self.network_data.add(self.url_buffer + url)

        return None

    def on_complete(self):
        ret = False
        badscore = 0
        if len(self.created_procs) == 2:
            if self.created_procs[0] == "svchost.exe":
                badscore += 1
            if re.match(r".*\\Temp\\[A-Za-z]+\.exe", self.created_procs[1]):
                badscore += 1
        if self.deletes_parentfile:
            badscore += 1
        if self.hostname:
            badscore += 1
        if badscore == 4 or self.campaign:
            ret = True
            if self.campaign:
                self.data.append({"Campaign": self.campaign})
            if self.network_data:
                for payload in self.network_data:
                    self.data.append({"Payload": payload})

        return ret
