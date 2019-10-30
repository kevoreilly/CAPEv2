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

from lib.cuckoo.common.abstracts import Signature

class Tinba_APIs(Signature):
    name = "tinba_behavior"
    description = "Exhibits behavior characteristics of Tinba malware"
    severity = 3
    weight = 3
    categories = ["trojan", "banker"]
    families = ["tinba"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    filter_categories = set(["__notification__"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.unhooks = set()

    def on_call(self, call, process):
        # Collect unhook events to compare against browser injection
        # hooked APIs in on_complete
        unhook = self.check_argument_call(call,
                                          api="__anomaly__",
                                          name="Subcategory",
                                          pattern="unhook")
        if unhook:
            deld = self.get_argument(call, "UnhookType")
            if deld == "removal":
                self.unhooks.add(self.get_argument(call, "FunctionName"))

    def on_complete(self):
        malscore = 0
        runkey = r".*\\Microsoft\\Windows\\CurrentVersion\\Run\\[0-9A-F]{8}$"
        file_iocs = [
            r"^[A-Z]:\\Users\\[^\\]+\\AppData\\Roaming\\[0-9A-F]{8}\\[^\.]+\.exe$",
            r"^[A-Z]:\\Users\\[^\\]+\\AppData\\LocalLow\\[0-9A-F]{8}\\log\.dat$",
            r"^[A-Z]:\\Users\\[^\\]+\\AppData\\LocalLow\\[0-9A-F]{8}\\ntf\.dat$",
            r"^[A-Z]:\\Users\\[^\\]+\\AppData\\LocalLow\\[0-9A-F]{8}\\web\.dat$",
            r"^[A-Z]:\\Documents\ and\ Settings\\[^\\]+\\Application\ Data\\[0-9A-F]{8}\\[^\.]+\.exe$",
            r"^[A-Z]:\\Documents\ and\ Settings\\[^\\]+\\Application\ Data\\[0-9A-F]{8}\\log\.dat$",
            r"^[A-Z]:\\Documents\ and\ Settings\\[^\\]+\\Application\ Data\\[0-9A-F]{8}\\ntf\.dat$",
            r"^[A-Z]:\\Documents\ and\ Settings\\[^\\]+\\Application\ Data\\[0-9A-F]{8}\\web\.dat$",
        ]
        unhook_list = [
            "URLDownloadToFileW", "ObtainUserAgentString",
            "CoInternetSetFeatureEnabled", "InternetGetConnectedState",
            "InternetOpenA", "InternetOpenW", "InternetConnectA",
            "InternetConnectW", "InternetOpenUrlA", "InternetOpenUrlW",
            "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA",
            "HttpSendRequestW", "HttpSendRequestExA", "HttpSendRequestExW",
            "HttpAddRequestHeadersA", "HttpAddRequestHeadersW",
            "HttpEndRequestA", "HttpEndRequestW", "InternetReadFile",
            "InternetWriteFile", "InternetCloseHandle", "InternetCrackUrlA",
            "InternetCrackUrlW", "InternetSetOptionA"
        ]

        autorun = ""
        tmp = self.check_write_key(pattern=runkey, regex=True)
        if tmp:
            autorun = self.check_write_key(pattern=runkey, regex=True)
            malscore += 1

        mutexes = self.results["behavior"]["summary"]["mutexes"]
        for mutex in mutexes:
            buf = mutex + "ntf"
            if buf in mutexes:
                malscore += 2
                break

        for mutex in mutexes:
            if mutex == autorun.split("\\")[-1]:
                malscore += 10
                break

        for ioc in file_iocs:
            buf = self.check_write_file(pattern=ioc, regex=True)
            if buf:
                malscore += 2

        inject_hooks = 0
        for unhook in self.unhooks:
            if unhook in unhook_list:
                inject_hooks += 1

        if inject_hooks > 25:
            malscore += 10

        # Trigger if we match enough of the indicators
        if malscore >= 15:
            return True

        return False
