# Copyright (C) 2016 Kevin Ross
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

class ScriptNetworkActvity(Signature):
    name = "script_network_activity"
    description = "A script process initiated network activity"
    severity = 3
    confidence = 100
    categories = ["downloader"]
    authors = ["Kevin Ross"]
    minimum = "1.2"
    evented = True
    ttp = ["T1064"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    filter_apinames = set(["InternetCrackUrlW","InternetCrackUrlA","URLDownloadToFileW","HttpOpenRequestW","InternetReadFile", "send", "SslEncryptPacket", "WSAConnect"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname.lower() in ["cscript.exe", "jscript.exe", "mshta.exe", "wscript.exe"]:
            if call["api"] == "URLDownloadToFileW":
                buff = self.get_argument(call, "FileName").lower()
                self.ret = True
                self.data.append({"request": buff })
            if call["api"] == "HttpOpenRequestW":
                buff = self.get_argument(call, "Path").lower()
                self.ret = True
                self.data.append({"request": buff })
            if call["api"] == "InternetCrackUrlW":
                buff = self.get_argument(call, "Url").lower()
                self.ret = True
                self.data.append({"request": buff })
            if call["api"] == "InternetCrackUrlA":
                buff = self.get_argument(call, "Url").lower()
                self.ret = True
                self.data.append({"request": buff })
            if call["api"] == "send":
                buff = self.get_argument(call, "buffer").lower()
                if buff.startswith("get") or buff.startswith("post"):
                    self.ret = True
                    self.data.append({"request": buff })
            if call["api"] == "SslEncryptPacket":
                buff = self.get_argument(call, "Buffer").lower()
                if buff.startswith("get") or buff.startswith("post"):
                    self.ret = True
                    self.data.append({"request": buff })
            if call["api"] == "WSAConnect":
                buff = self.get_argument(call, "ip").lower()
                port = self.get_argument(call, "port").lower()
                if not buff.startswith(("10.","172.16.","192.168.")):
                    self.ret = True
                    self.data.append({"request": "%s:%s" % (buff,port)})

    def on_complete(self):
        return self.ret

## MAKE PROCESSES JSCRIPT AND CSCRIPT TOO
class SuspiciousJSScript(Signature):
    name = "suspicious_js_script"
    description = "Suspicious JavaScript was executed by a script process"
    severity = 3
    confidence = 50
    categories = ["downloader"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1064"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False
        self.suspicious = [
            "cmd.exe",
            "cmd ",
            "powershell",
            ".shellexecute",
            "wscript.shell",
        ]

    filter_apinames = set(["JsEval", "COleScript_ParseScriptText"])

    def on_call(self, call, process):
        if call["api"] == "JsEval":
            pname = process["process_name"]
            if pname.lower() in ["cscript.exe", "jscript.exe", "mshta.exe", "wscript.exe"]:
                javascript = self.get_argument(call, "JavaScript")
                for suspicious in self.suspicious:
                    if suspicious in javascript.lower():
                        self.data.append({"Process executing suspicious JavaScript" : pname})
                        self.ret = True
                        break

        if call["api"] == "COleScript_ParseScriptText":
            pname = process["process_name"]
            if pname.lower() in ["cscript.exe", "jscript.exe", "wscript.exe"]:
                javascript = self.get_argument(call, "Script")
                for suspicious in self.suspicious:
                    if suspicious in javascript.lower():
                        self.data.append({"Process executing suspicious JavaScript" : pname})
                        self.ret = True
                        break

    def on_complete(self):
        return self.ret

class ScriptCreatedProcess(Signature):
    name = "script_created_process"
    description = "A script process created a new process"
    severity = 3
    confidence = 100
    categories = ["downloader", "dropper"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1064"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    filter_apinames = set(["CreateProcessInternalW"])

    def on_call(self, call, process):
        pname = process["process_name"]
        if pname.lower() in ["cscript.exe", "jscript.exe", "mshta.exe", "wscript.exe"]:
            cmdline = self.get_argument(call, "CommandLine")
            if cmdline:
                self.ret = True
                self.data.append({pname : cmdline})

    def on_complete(self):
        return self.ret
