# Copyright (C) 2012,2014,2015 Michael Boman (@mboman), Optiv, Inc. (brad.spengler@optiv.com)
#
# This program is free Software: you can redistribute it and/or modify
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

# Based on information from http://antivirus.about.com/od/windowsbasics/tp/autostartkeys.htm

# Additional keys added from SysInternals Administrators Guide

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature


class Autorun_scheduler(Signature):
    name = "persistence_autorun_tasks"
    description = "Installs itself for autorun at Windows startup"
    severity = 3
    categories = ["persistence"]
    authors = ["Michael Boman", "nex", "securitykitten", "Optiv", "KillerInstinct"]
    minimum = "1.3"
    evented = True
    ttps = ["T1053", "T1112"]  # MITRE v6,7,8
    ttps += ["T1053.005"]  # MITRE v7,8
    mbcs = ["OB0012", "E1112"]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey", "CreateServiceA", "CreateServiceW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.registry_writes = dict()
        self.found_autorun = False

    def on_call(self, call, process):
        if call["api"].startswith("CreateService") and call["status"]:
            starttype = int(self.get_argument(call, "StartType"), 10)
            servicename = self.get_argument(call, "ServiceName")
            binpath = self.get_argument(call, "BinaryPathName")
            if starttype < 3:
                self.data.append({"service": servicename})
                self.data.append({"service_path": binpath})
                self.found_autorun = True
                if self.pid:
                    self.mark_call()
        elif call["status"]:
            fullname = self.get_argument(call, "FullName")
            self.registry_writes[fullname] = self.get_argument(call, "Buffer")
            if self.pid:
                self.mark_call()

    def on_complete(self):
        indicators = [
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\SharedTaskScheduler\\\\.*",
        ]
        whitelists = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\{CAFEEFAC-0017-0000-FFFF-ABCDEFFEDCBA}\\\\InprocServer32\\\\.*",
            # ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\InprocServer32\\\\ThreadingModel$",
        ]

        for indicator in indicators:
            match_key = self.check_write_key(pattern=indicator, regex=True, all=True)
            if match_key:
                for match in match_key:
                    in_whitelist = False
                    for entry in whitelists:
                        if re.match(entry, match, re.IGNORECASE):
                            in_whitelist = True
                            break

                    if not in_whitelist:
                        data = self.registry_writes.get(match, "unknown")
                        if data.lower() != "c:\\program files\\java\\jre7\\bin\jp2iexp.dll":
                            self.data.append({"regkey": match})
                            self.data.append({"data": data})
                            self.found_autorun = True

        indicators = [".*\\\\WINDOWS\\\\Tasks\\\\.*"]

        for indicator in indicators:
            if "dropped" in self.results and len(self.results.get("dropped", [])):
                for drop in self.results["dropped"]:
                    for path in drop.get("guest_paths", []) or []:
                        if re.match(indicator, path, re.IGNORECASE):
                            self.data.append({"file": path})
                            self.found_autorun = True
            match_file = self.check_write_file(pattern=indicator, regex=True, all=True)
            if match_file:
                for match in match_file:
                    self.data.append({"file": match})
                self.found_autorun = True

        taskpat = ".*schtasks(\.exe)?.*/CREATE.*/SC\s+.*"
        tasked = self.check_executed_command(pattern=taskpat, regex=True)
        if tasked:
            self.found_autorun = True
            self.data.append({"task": tasked})

        return self.found_autorun


class Autorun(Signature):
    name = "persistence_autorun"
    description = "Installs itself for autorun at Windows startup"
    severity = 3
    categories = ["persistence"]
    authors = ["Michael Boman", "nex", "securitykitten", "Optiv", "KillerInstinct"]
    minimum = "1.3"
    evented = True
    ttps = ["T1060"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v6,7,8
    ttps += ["T1547", "T1547.001"]  # MITRE v7,8
    mbcs = ["OB0012", "E1112", "F0012"]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "NtSetValueKey", "CreateServiceA", "CreateServiceW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.registry_writes = dict()
        self.found_autorun = False

    def on_call(self, call, process):
        if call["api"].startswith("CreateService") and call["status"]:
            starttype = int(self.get_argument(call, "StartType"), 10)
            servicename = self.get_argument(call, "ServiceName")
            binpath = self.get_argument(call, "BinaryPathName")
            if starttype < 3:
                self.data.append({"service": servicename})
                self.data.append({"service_path": binpath})
                self.found_autorun = True
                if self.pid:
                    self.mark_call()
        elif call["status"]:
            fullname = self.get_argument(call, "FullName")
            self.registry_writes[fullname] = self.get_argument(call, "Buffer")
            if self.pid:
                self.mark_call()

    def on_complete(self):
        indicators = [
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Notify\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit$",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run\\\\.*",
            ".*\\\\Microsoft\\\\Active\\ Setup\\\\Installed Components\\\\.*",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\AppInit_DLLs$",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\[^\\\\]*\\\\\Debugger$",
            ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Shell$",
            ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\[^\\\\]*\\\\ImagePath$",
            ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\[^\\\\]*\\\\Parameters\\\\ServiceDLL$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\Exefile\\\\Shell\\\\Open\\\\Command\\\\\(Default\)$",
            ".*\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\load$",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\ShellServiceObjectDelayLoad\\\\.*",
            ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\Session\\ Manager\\\\AppCertDlls\\\\.*",
            # ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\InprocServer32\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\LocalServer32\\\\.*",
            ".*\\\\Microsoft\\\\Command\\ Processor\\\\AutoRun$",
            ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\User\ Shell\ Folders\\\\Startup$",
        ]
        whitelists = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\{CAFEEFAC-0017-0000-FFFF-ABCDEFFEDCBA}\\\\InprocServer32\\\\.*",
            # ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\InprocServer32\\\\ThreadingModel$",
        ]

        for indicator in indicators:
            match_key = self.check_write_key(pattern=indicator, regex=True, all=True)
            if match_key:
                for match in match_key:
                    in_whitelist = False
                    for entry in whitelists:
                        if re.match(entry, match, re.IGNORECASE):
                            in_whitelist = True
                            break

                    if not in_whitelist:
                        data = self.registry_writes.get(match, "unknown")
                        if data.lower() != "c:\\program files\\java\\jre7\\bin\\jp2iexp.dll":
                            self.data.append({"regkey": match})
                            self.data.append({"data": data})
                            self.found_autorun = True

        indicators = [
            ".*\\\\win\.ini$",
            ".*\\\\system\.ini$",
            ".*\\\\Start Menu\\\\Programs\\\\Startup\\\\.*",
        ]

        for indicator in indicators:
            if "dropped" in self.results and len(self.results["dropped"]):
                for drop in self.results.get("dropped", []) or []:
                    for path in drop.get("guest_paths", []) or []:
                        if re.match(indicator, path, re.IGNORECASE):
                            self.data.append({"file": path})
                            self.found_autorun = True
            match_file = self.check_write_file(pattern=indicator, regex=True, all=True)
            if match_file:
                for match in match_file:
                    self.data.append({"file": match})
                self.found_autorun = True

        return self.found_autorun


class PersistenceSafeBoot(Signature):
    name = "persistence_safeboot"
    description = "Adds itself to the Safe Mode boot to ensure its start"
    severity = 3
    categories = ["persistence"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1060"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v6,7,8
    ttps += ["T1547", "T1547.001"]  # MITRE v7,8
    mbcs = ["OB0012", "E1112"]

    def run(self):
        indicators = [
            ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\SafeBoot\\\\Minimal\\\\.*",
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False
