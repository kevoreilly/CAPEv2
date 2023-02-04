# Copyright (C) 2020 bartblaze
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


class OfficeAddinLoading(Signature):
    name = "office_addinloading"
    description = "Creates add-in (DLL) that automatically loads when launching Word or Excel."
    severity = 3
    categories = ["office", "persistence", "evasion", "execution"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1137"]  # MITRE v6,7,8
    ttps += ["T1137.006"]  # MITRE v7,8

    def run(self):
        indicators = [
            ".*\\AppData\\Roaming\\Microsoft\\Word\\startup\\*.wll",
            ".*\\AppData\\Roaming\\Microsoft\\Excel\\XLSTART\\*.xll",
            ".*\\AppData\\Roaming\\Microsoft\\AddIns\\*.xlam",
            ".*\\AppData\\Roaming\\Microsoft\\AddIns\\*.xla",
        ]

        for indicator in indicators:
            match = self.check_write_file(pattern=indicator)
            if match:
                self.data.append({"file": match})
                return True

        return False


class OfficePerfKey(Signature):
    name = "office_perfkey"
    description = "Creates registry key for persistence which will automatically load when launching any Office application."
    severity = 3
    categories = ["office", "persistence", "evasion", "execution"]
    authors = ["bartblaze"]
    minimum = "1.3"
    ttps = ["T1112", "T1137"]  # MITRE v6,7,8
    mbcs = ["OB0012", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        indicators = ["HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Office test\\\\Special\\\\Perf$"]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False


from lib.cuckoo.common.abstracts import Signature


class OfficeVBLLoad(Signature):
    name = "office_vb_load"
    description = "Office loads VB DLLs, indicative of Office Macros"
    severity = 1
    categories = ["office", "macro"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1059", "T1137", "T1204"]  # MITRE v6,7,8
    ttps += ["T1059.005", "T1137.001", "T1204.002"]  # MITRE v7,8
    mbcs = ["OB0009", "E1059"]

    filter_apinames = set(["LdrLoadDll", "LdrGetDllHandle"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.officeprocs = ["winword.exe", "excel.exe", "powerpnt.exe"]
        self.vbdlls = ["vbe7intl.dll", "vbe7.dll", "vbeui.dll"]
        self.score = int()

    def on_call(self, call, process):
        processname = process["process_name"]
        if processname and processname.lower() in self.officeprocs:
            dllname = self.get_argument(call, "FileName")
            if dllname:
                for dll in self.vbdlls:
                    if dll in dllname.lower():
                        self.score += 1
                        if self.score >= 2:
                            if self.pid:
                                self.mark_call()
                            return True


class OfficeWMILoad(Signature):
    name = "office_wmi_load"
    description = "Office loads WMI DLLs, indicative of Office Macros executing WMI commands"
    severity = 2
    categories = ["office", "macro"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1059", "T1137", "T1204"]  # MITRE v6,7,8
    ttps += ["T1137.001", "T1204.002"]  # MITRE v7,8
    mbcs = ["OB0009", "E1059"]

    filter_apinames = set(["LdrLoadDll", "LdrGetDllHandle"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.officeprocs = ["winword.exe", "excel.exe", "powerpnt.exe"]

    def on_call(self, call, process):
        processname = process["process_name"]
        if processname and processname.lower() in self.officeprocs:
            dllname = self.get_argument(call, "FileName")
            if dllname:
                if "wbemdisp.dll" in dllname.lower():
                    if self.pid:
                        self.mark_call()
                    return True


class OfficeCOMLoad(Signature):
    name = "office_com_load"
    description = "Office loads COM DLLs, indicative of Office Macros spawning CMD process for execution"
    severity = 1
    categories = ["office", "macro"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1059", "T1137", "T1204"]  # MITRE v6,7,8
    ttps += ["T1059.003", "T1137.001", "T1204.002"]  # MITRE v7,8
    mbcs = ["OB0009", "E1059"]

    filter_apinames = set(["LdrLoadDll", "LdrGetDllHandle"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.officeprocs = ["winword.exe", "excel.exe", "powerpnt.exe"]
        self.comdlls = ["combase.dll", "coml2.dll", "comsvcs.dll"]

    def on_call(self, call, process):
        processname = process["process_name"]
        if processname and processname.lower() in self.officeprocs:
            dllname = self.get_argument(call, "FileName")
            if dllname:
                for dll in self.comdlls:
                    if dll in dllname.lower():
                        if self.pid:
                            self.mark_call()
                        return True


class OfficeDotNetLoad(Signature):
    name = "office_dotnet_load"
    description = "Office loads .NET assembly or DLL, indicative of suspicious Office Macros activities"
    severity = 2
    categories = ["office", "macro"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1137", "T1204"]  # MITRE v6,7,8
    ttps += ["T1137.001", "T1204.002"]  # MITRE v7,8

    filter_apinames = set(["LdrLoadDll"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.officeprocs = ["winword.exe", "excel.exe", "powerpnt.exe"]
        self.dotnetpaths = [
            "[A-Z]:\\\\Windows\\\\assembly\\\\.*",
            "[A-Z]:\\\\Windows\\\\Microsoft.NET\\\\assembly\\\\GAC_MSIL.*",
        ]

    def on_call(self, call, process):
        processname = process["process_name"]
        if processname:
            if processname.lower() in self.officeprocs:
                dllname = self.get_argument(call, "FileName")
                if dllname:
                    if "clr.dll" in dllname.lower():
                        if self.pid:
                            self.mark_call()
                        return True
                    else:
                        for dllpath in self.dotnetpaths:
                            if re.search(dllpath, dllname.lower(), re.IGNORECASE):
                                if self.pid:
                                    self.mark_call()
                                return True


class OfficeMSHTMLLoad(Signature):
    name = "office_mshtml_load"
    description = "Office loads MSHTML DLL, indicative of ActiveX execution"
    severity = 2
    categories = ["office"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1204"]  # MITRE v6,7,8

    filter_apinames = set(["LdrLoadDll", "LdrGetDllHandle"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.officeprocs = ["wordview.exe", "winword.exe", "excel.exe", "powerpnt.exe"]

    def on_call(self, call, process):
        processname = process["process_name"]
        if processname:
            if processname.lower() in self.officeprocs:
                dllname = self.get_argument(call, "FileName")
                if dllname:
                    if "mshtml.dll" in dllname.lower():
                        if self.pid:
                            self.mark_call()
                        return True
