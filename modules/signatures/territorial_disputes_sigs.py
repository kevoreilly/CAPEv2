# Copyright (C) 2020 ditekshen
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


class TerritorialDisputeSIGs(Signature):
    name = "territorial_disputes_sigs"
    description = "Creates an indicator observed in Territorial Disputes report"
    severity = 1
    categories = ["generic"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    references = ["https://www.crysys.hu/publications/files/tedi/ukatemicrysys_territorialdispute.pdf"]

    def run(self):
        registry_indicators = [
            (".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\StrtdCfg$", ["SIG1"]),
            (".*\\\\System\\\\CurrentControlSet\\\\Control\\\\CrashImage$", ["SIG2"]),
            (".*\\\\System\\\\CurrentControlSet\\\\Services\\\\systmmgmt\\\\Paramaters\\\\ServiceDll$", ["SIG5"]),
            (
                ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run\\\\ipmontr$",
                ["SIG6"],
            ),
            (".*\\\\Software\\\\Microsoft\\\\WinKernel\\\\Explorer\\\\Run\\\\ipmontr$", ["SIG6"]),
            (
                ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run\\\\Internet32$",
                ["SIG7"],
            ),
            (".*\\\\System\\\\CurrentControlSet\\\\Control\\\\timezoneinformation\\\\standard(date|time)bias$", ["SIG10"]),
            (".*\\\\System\\\\(Wow6432Node\\\\)?Microsoft\\\\MSFix$", ["SIG12"]),
            (
                ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\WindowsFirewallSecurityServ$",
                ["SIG14"],
            ),
            (".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\slidebar$", ["SIG14"]),
            (".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\MSDeviceDriver$", ["SIG14"]),
            (".*\\\\Software\\\\Postman$", ["SIG15"]),
            (".*\\\\System\\\\(Wow6432Node\\\\)?Microsoft\\\\WinMI$", ["SIG19"]),
            (".*\\\\Software\\\\Sun\\\\.*(AppleTlk|IsoTp)$", ["SIG22"]),
            (".*\\\\System\\\\(Wow6432Node\\\\)?Microsoft\\\\NetWin$", ["SIG23"]),
            (".*\\\\Software\\\\Adobe\\\\Fix$", ["SIG26"]),
            (
                ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\Streams\\\\Desktop\\\\Default\s(Statusbar|MenuBars|Taskbar|Zone)(\sSign)?",
                ["SIG31"],
            ),
            (".*\\\\System\\\\CurrentControlSet\\\\Services\\\\Installer\sManagement$", ["SIG34"]),
            (".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\MS\sQAG\\\\U\d{2}$", ["SIG39"]),
            (
                ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\ShellServiceObjectDelayLoad(\\\\NetIDS)?$",
                ["SIG40"],
            ),
            (".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\sNT\\\\CurrentVersion\\\\winlogo\\\\Userinit$", ["SIG40"]),
            (".*\\\\System\\\\CurrentControlSet\\\\Control\\\\DType\d$", ["SIG43"]),
            (".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Internet$", ["SIG45"]),
        ]

        for indicator in registry_indicators:
            match = self.check_key(pattern=indicator[0], regex=True)
            if match:
                self.data.append({"regkey": match})
                self.description = "{0} {1}".format(self.description, " - ".join(indicator[1]))
                return True

        return False
