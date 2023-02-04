# Copyright (C) 2021 ditekshen
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


class CryptBotFiles(Signature):
    name = "cryptbot_files"
    description = "CryptBot file artifacts detected"
    severity = 3
    categories = ["infostealer"]
    families = ["CryptBot"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    def run(self):
        score = 0
        indicators = [
            ".*AppData\\\\Local\\\\Temp\\\\.*\\\\(_Files|files_)\\\\_AllForms_list\.txt$",
            ".*AppData\\\\Local\\\\Temp\\\\.*\\\\(_Files|files_)\\\\_Screen_Desktop\.jpeg$",
            ".*AppData\\\\Local\\\\Temp\\\\.*\\\\(_Files|files_)\\\\_Information\.txt$",
            ".*AppData\\\\Local\\\\Temp\\\\.*\\\\(_Files|files_)\\\\screenshot\.jpg$",
            ".*AppData\\\\Local\\\\Temp\\\\.*\\\\(_Files|files_)\\\\system_info\.txt$",
            ".*AppData\\\\Local\\\\Temp\\\\.*\\\\(_Files|files_)\\\\forms\.txt$",
        ]

        for indicator in indicators:
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                score += 1
                self.data.append({"file": match})

        if score >= 4:
            return True

        return False


class CryptBotNetwork(Signature):
    name = "cryptbot_network"
    description = "CryptBot network artifacts detected"
    severity = 3
    categories = ["infostealer"]
    families = ["CryptBot"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["HttpOpenRequestW", "HttpSendRequestW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.matchpath = False
        self.matchpost = False

    def on_call(self, call, process):
        if call["api"] == "HttpOpenRequestW":
            httppath = self.get_argument(call, "Path")
            if httppath and httppath == "/index.php":
                self.matchpath = True
                if self.pid:
                    self.mark_call()
        if call["api"] == "HttpSendRequestW":
            httppost = self.get_argument(call, "PostData")
            if httppost and "_AllForms_list.t" in httppost:
                self.matchpost = True
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        if self.matchpath and self.matchpost:
            return True

        return False
