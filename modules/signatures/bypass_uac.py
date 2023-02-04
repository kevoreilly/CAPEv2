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


class UACBypassEventvwr(Signature):
    name = "uac_bypass_eventvwr"
    description = "Uses eventvwr technique to bypass User Access Control (UAC)"
    severity = 3
    confidence = 100
    categories = ["bypass"]
    authors = ["Kevin Ross", "Zane C. Bowers-Hadley"]
    minimum = "1.3"
    evented = True
    ttps = ["T1088"]  # MITRE v6
    ttps += ["T1548", "T1548.002"]  # MITRE v7,8
    mbcs = ["OB0006"]
    references = ["https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/"]

    filter_apinames = set(["CreateProcessInternalW", "RegQueryValueExA", "RegQueryValueExW", "NtCreateUserProcess"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.eventvrw = False
        self.ret = False

    def on_call(self, call, process):
        if call["api"].startswith("RegQueryValueEx"):
            pname = process["process_name"]
            if pname.lower() == "eventvwr.exe":
                fullname = self.get_argument(call, "FullName")
                data = self.get_argument(call, "Data")
                if "\classes\mscfile\shell\open\command" in fullname.lower():
                    self.eventvrw = True
                    self.data.append({"reg_query_name": fullname})
                    self.data.append({"reg_query_data": data})

        if call["api"] == "CreateProcessInternalW":
            pname = process["process_name"]
            if pname.lower() == "eventvwr.exe" and self.eventvrw:
                cmdline = self.get_argument(call, "CommandLine")
                if ("mmc " in cmdline.lower() or "mmc.exe" in cmdline.lower()) and "eventvwr.msc" in cmdline.lower():
                    self.data.append({"command": cmdline})
                    if self.pid:
                        self.mark_call()
                    self.ret = True

        if call["api"] == "NtCreateUserProcess":
            pname = process["process_name"]
            if pname.lower() == "eventvwr.exe" and self.eventvrw:
                cmdline = self.get_argument(call, "CommandLine")
                if ("mmc " in cmdline.lower() or "mmc.exe" in cmdline.lower()) and "eventvwr.msc" in cmdline.lower():
                    self.data.append({"command": cmdline})
                    if self.pid:
                        self.mark_call()
                    self.ret = True

    def on_complete(self):
        return self.ret


class UACBypassDelegateExecuteSdclt(Signature):
    name = "uac_bypass_delegateexecute_sdclt"
    description = "Uses delegate execute sdclt technique to bypass User Access Control (UAC)"
    severity = 3
    confidence = 100
    categories = ["bypass"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1088"]  # MITRE v6
    ttps += ["T1548", "T1548.002"]  # MITRE v7,8
    mbcs = ["OB0006"]
    references = ["http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass"]

    def run(self):
        regkey = False
        ret = False

        keys = [
            ".*\\\\Software\\\\Classes\\\\Folder\\\\shell\\\\open\\\\command\\\\DelegateExecute$",
        ]

        for check in keys:
            match = self.check_write_key(pattern=check, regex=True)
            if match:
                self.data.append({"regkey": match})
                regkey = True

        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if regkey and "sdclt" in lower:
                self.data.append({"command": cmdline})
                ret = True

        return ret


class UACBypassCMSTP(Signature):
    name = "uac_bypass_cmstp"
    description = "Uses cmstp.exe sendkeys technique to bypass User Access Control (UAC)"
    severity = 3
    confidence = 100
    categories = ["bypass"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1088"]  # MITRE v6
    ttps += ["T1548", "T1548.002"]  # MITRE v7,8
    mbcs = ["OB0006"]
    references = ["https://oddvar.moe/2017/08/15/research-on-cmstp-exe/"]

    filter_apinames = set(["CopyFileExA", "CopyFileExW", "MoveFileWithProgressW", "MoveFileWithProgressTransactedW", "NtWriteFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.inf = False
        self.droppedinf = []
        self.ret = False

    def on_call(self, call, process):
        # This is a straight catch of the .inf file with content we want being dropped
        if call["api"] == "NtWriteFile":
            filename = self.get_argument(call, "HandleName")
            if filename.endswith(".inf"):
                buf = self.get_argument(call, "Buffer")
                if "runpresetupcommands" in buf.lower():
                    self.data.append({"dropped .inf file": filename})
                    self.droppedinf.append(filename)
                    if self.pid:
                        self.mark_call()
                    self.inf = True

        # This is for a file being moved/renamed into .inf. This is to avoid a possible evasion that could be created by dropped the content in a .txt or something and then renaming the file/moving it into a .inf for use my cmstp. Also in case of copying .inf files into new ones too.
        if call["api"] in ("CopyFileExA", "CopyFileExW", "MoveFileWithProgressW", "MoveFileWithProgressTransactedW"):
            origfile = self.get_argument(call, "ExistingFileName")
            destfile = self.get_argument(call, "NewFileName")
            if destfile.endswith(".inf"):
                self.data.append({"dropped .inf file": "%s was moved to destination file %s" % (origfile, destfile)})
                self.droppedinf.append(destfile)
                if self.pid:
                    self.mark_call()
                self.inf = True

    def on_complete(self):
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if self.inf and "cmstp" in lower and ".inf" in lower:
                for dropped in self.droppedinf:
                    if dropped.lower() in lower:
                        self.data.append({"command": cmdline})
                        self.ret = True

        return self.ret


class UACBypassFodhelper(Signature):
    name = "uac_bypass_fodhelper"
    description = "Uses fodhelper.exe sendkeys technique to bypass User Access Control (UAC)"
    severity = 3
    categories = ["persistence"]
    authors = ["bartblaze"]
    minimum = "1.2"
    evented = True
    ttps = ["T1548"]
    references = ["https://winscripting.blog/2017/05/12/first-entry-welcome-and-uac-bypass/"]

    def run(self):
        ret = False
        reg_indicators = ["HKEY_CURRENT_USER\\\\Software\\\\Classes\\\\ms-settings\\\\shell \\\\open\\\\command\\\\*."]

        for indicator in reg_indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                ret = True
                self.data.append({"regkey": match})

        return ret


class UACBypassCMSTPCOM(Signature):
    name = "uac_bypass_cmstpcom"
    description = "UAC bypass via CMSTP COM interface detected"
    severity = 3
    categories = ["bypass"]
    authors = ["ditekshen"]
    minimum = "2.0"
    ttps = ["T1218"]  # MITRE v6,7,8
    ttps += ["T1218.003"]  # MITRE 7,8

    def run(self):
        # CMSTPLUA, CMLUAUTIL, Connection Manager LUA Host Object
        indicators = [
            ".*\\\\Windows\\\\(SysWOW64|System32)\\\\DllHost\.exe.*\/Processid:(\{)?3E5FC7F9-9A51-4367-9063-A120244FBEC7(\})?",
            ".*\\\\Windows\\\\(SysWOW64|System32)\\\\DllHost\.exe.*\/Processid:(\{)?3E000D72-A845-4CD9-BD83-80C07C3B881F(\})?",
            ".*\\\\Windows\\\\(SysWOW64|System32)\\\\DllHost\.exe.*\/Processid:(\{)?BA126F01-2166-11D1-B1D0-00805FC1270E(\})?",
        ]

        for indicator in indicators:
            match = self.check_executed_command(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False
