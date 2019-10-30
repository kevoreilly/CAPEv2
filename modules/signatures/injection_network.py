# Copyright (C) 2018 Kevin Ross
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

class InjectionNetworkTraffic(Signature):
    name = "injection_network_traffic"
    description = "A system process is generating network traffic likely as a result of process injection"
    severity = 3
    confidence = 20
    categories = ["injection"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1071"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.data = []
        self.proc_list = [
            "conhost.exe",
            "csrss.exe",
            "dwm.exe",
            "explorer.exe",
            "lsass.exe",
            "services.exe",
            "smss.exe",
            "userinit.exe",
            "wininit.exe",
            "winlogon.exe",
        ]

    filter_apinames = set(["connect","HttpOpenRequestA","HttpOpenRequestW","InternetConnectA", "InternetConnectW","InternetCrackUrlW","InternetCrackUrlA","URLDownloadToFileW","WSASend"])

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.proc_list:
            addit = None
            if call["api"] == "URLDownloadToFileW":
                buff = self.get_argument(call, "Url")
                addit = {"http_downloadurl": "%s_URLDownloadToFileW_%s" % (pname,buff)}
            if call["api"] == "HttpOpenRequestA":
                buff = self.get_argument(call, "Path")
                addit = {"http_request_path": "%s_HttpOpenRequestA_%s" % (pname,buff)}
            if call["api"] == "HttpOpenRequestW":
                buff = self.get_argument(call, "Path")
                addit = {"http_request_path": "%s_HttpOpenRequestW_%s" % (pname,buff)}
            if call["api"] == "InternetCrackUrlW":
                buff = self.get_argument(call, "Url")
                addit = {"http_request": "%s_InternetCrackUrlW_%s" % (pname,buff)}
            if call["api"] == "InternetCrackUrlA":
                buff = self.get_argument(call, "Url")
                addit = {"http_request": "%s_InternetCrackUrlA_%s" % (pname,buff)}
            if call["api"] == "InternetConnectA":
                buff = self.get_argument(call, "ServerName")
                if not buff.startswith(("127.", "10.", "172.16.", "192.168.")):
                    addit = {"http_request": "%s_InternetConnectA_%s" % (pname,buff)}
            if call["api"] == "InternetConnectW":
                buff = self.get_argument(call, "ServerName")
                if not buff.startswith(("0.", "127.", "169.254.", "10.", "220.", "224.", "239.", "240.", "172.16.", "192.168.", "255.255.255.255")):
                    addit = {"http_request": "%s_InternetConnectW_%s" % (pname,buff)}
            if call["api"] == "WSASend":
                buff = self.get_argument(call, "Buffer").lower()
                addit = {"network_connection": "%s_WSASend_%s" % (pname,buff)}
            if call["api"] == "connect":
                buff = self.get_argument(call, "ip")
                if not buff.startswith(("0.", "127.", "169.254.", "10.", "220.", "224.", "239.", "240.", "172.16.", "192.168.", "255.255.255.255")):
                    addit = {"network_connection": "%s_connect_%s" % (pname,buff)}
            if addit and addit not in self.data:
                self.data.append(addit)

        return None

    def on_complete(self):
        if self.data:
            return True

        return False
