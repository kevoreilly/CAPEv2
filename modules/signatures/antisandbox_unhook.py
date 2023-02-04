# Copyright (C) 2014 Claudio "nex" Guarnieri (@botherder), Optiv, Inc. (brad.spengler@optiv.com)
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


class Unhook(Signature):
    name = "antisandbox_unhook"
    description = "Tries to unhook or modify Windows functions monitored by Cuckoo"
    severity = 3
    confidence = 60
    categories = ["anti-sandbox"]
    authors = ["nex", "Optiv"]
    minimum = "1.2"
    evented = True
    ttps = ["T1089"]  # MITRE v6
    ttps += ["T1562", "T1562.001"]  # MITRE v 7,8
    ttps += ["U1330"]  # Unprotect
    mbcs = ["OB0001", "B0003", "OB0006", "F0004", "F0004.003"]

    filter_categories = set(["__notification__"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.saw_unhook = False
        self.unhook_info = set()
        self.is_url_analysis = False
        if self.results.get("target", {}).get("category", "") == "url":
            self.is_url_analysis = True
        self.safelistprocs = ["acrord32.exe"]

    def on_call(self, call, process):
        if process["process_name"].lower() in self.safelistprocs:
            return

        subcategory = self.check_argument_call(call, api="__anomaly__", name="Subcategory", pattern="unhook")
        if subcategory:
            self.saw_unhook = True
            funcname = self.get_argument(call, "FunctionName")
            unhooktype = self.get_argument(call, "UnhookType")
            if funcname != "":
                allowed_mods = [
                    # done by IE
                    "SetUnhandledExceptionFilter",
                    "SetWindowsHookExW",
                    "UnhookWindowsHookEx",
                    "CreateWindowExW",
                    "CreateWindowExA",
                    "CoCreateInstance",
                    "CreateThread",
                ]
                addit = True
                if unhooktype == "modification" and funcname in allowed_mods:
                    addit = False
                # exempt IE behavior
                if self.is_url_analysis:
                    allowed = []
                    for name in allowed:
                        if funcname == name:
                            addit = False
                            break

                office_pkgs = ["ppt", "doc", "xls", "eml"]
                if any(e in self.results["info"]["package"] for e in office_pkgs):
                    allowed = []
                    for name in allowed:
                        if funcname == name:
                            addit = False
                            break

                if addit:
                    if self.pid:
                        self.mark_call()
                    self.unhook_info.add("function_name: " + funcname + ", type: " + self.get_argument(call, "UnhookType"))

    def on_complete(self):
        if not self.unhook_info:
            self.saw_unhook = False

        for info in self.unhook_info:
            self.data.append({"unhook": info})
        return self.saw_unhook
