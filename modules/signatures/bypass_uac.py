# Copyright (C) 2019 Kevin Ross
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
    categories = ["uac_bypass"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/"]
    ttp = ["T1088"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.eventvrw = False
        self.ret = False

    filter_apinames = set(["CreateProcessInternalW", "RegQueryValueExA", "RegQueryValueExW"])

    def on_call(self, call, process):
        if call["api"].startswith("RegQueryValueEx"):
            pname = process["process_name"]
            if pname.lower() == "eventvwr.exe":
                fullname = self.get_argument(call, "FullName")
                data = self.get_argument(call, "Data")
                if "\classes\mscfile\shell\open\command" in fullname.lower():
                    self.eventvrw = True
                    self.data.append({"reg_query_name": fullname })
                    self.data.append({"reg_query_data": data })

        if call["api"] == "CreateProcessInternalW":
            pname = process["process_name"]
            if pname.lower() == "eventvwr.exe" and self.eventvrw:
                cmdline = self.get_argument(call, "CommandLine")
                if ("mmc " in cmdline.lower() or "mmc.exe" in cmdline.lower()) and "eventvwr.msc" in cmdline.lower():
                    self.data.append({"cmdline": cmdline })
                    self.ret = True   

    def on_complete(self):
        return self.ret

class UACBypassDelegateExecuteSdclt(Signature):
    name = "uac_bypass_delegateexecute_sdclt"
    description = "Uses delegate execute sdclt technique to bypass User Access Control (UAC)"
    severity = 3
    confidence = 100
    categories = ["uac_bypass"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["http://blog.sevagas.com/?Yet-another-sdclt-UAC-bypass"]
    ttp = ["T1088"]

    def run(self):
        regkey = False
        ret = False

        keys = [
            ".*\\\\Software\\\\Classes\\\\Folder\\\\shell\\\\open\\\\command\\\\DelegateExecute$",
        ]

        for check in keys:
            match = self.check_write_key(pattern=check, regex=True)
            if match:
                self.data.append({"regkey" : match})
                regkey = True

        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if regkey and "sdclt" in lower:
                self.data.append({"cmdline" : cmdline})
                ret = True

        return ret

class UACBypassCMSTP(Signature):
    name = "uac_bypass_cmstp"
    description = "Uses cmstp.exe sendkeys technique to bypass User Access Control (UAC)"
    severity = 3
    confidence = 100
    categories = ["uac_bypass"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["https://oddvar.moe/2017/08/15/research-on-cmstp-exe/"]
    ttp = ["T1088"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.inf = False
        self.droppedinf = []
        self.ret = False

    filter_apinames = set(["CopyFileExA","CopyFileExW","MoveFileWithProgressW","MoveFileWithProgressTransactedW","NtWriteFile"])

    def on_call(self, call, process):
        # This is a straight catch of the .inf file with content we want being dropped
        if call["api"] == "NtWriteFile":
            filename = self.get_argument(call, "HandleName")
            if filename.endswith(".inf"):
                buf = self.get_argument(call, "Buffer")
                if "runpresetupcommands" in buf.lower():
                    self.data.append({"dropped .inf file": filename })
                    self.droppedinf.append(filename)
                    self.inf = True

        # This is for a file being moved/renamed into .inf. This is to avoid a possible evasion that could be created by dropped the content in a .txt or something and then renaming the file/moving it into a .inf for use my cmstp. Also in case of copying .inf files into new ones too.        
        if call["api"] in ("CopyFileExA","CopyFileExW","MoveFileWithProgressW","MoveFileWithProgressTransactedW"):
            origfile = self.get_argument(call, "ExistingFileName")
            destfile = self.get_argument(call, "NewFileName")
            if destfile.endswith(".inf"):
                self.data.append({"dropped .inf file" : "%s was moved to destination file %s" % (origfile,destfile)})
                self.droppedinf.append(destfile)
                self.inf = True

    def on_complete(self):
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            if self.inf and "cmstp" in lower and ".inf" in lower:
                for dropped in self.droppedinf:
                    if dropped.lower() in lower:
                        self.data.append({"cmdline" : cmdline})
                        self.ret = True

        return self.ret
