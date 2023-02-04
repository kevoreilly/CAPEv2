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


class FirefoxDisablesProcessPerTab(Signature):
    name = "firefox_disables_process_tab"
    description = "Disables Firefox creating a new process per tab, possbily for browser injection"
    severity = 3
    categories = ["banker"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1185"]
    references = [" https://www.kryptoslogic.com/blog/2022/01/deep-dive-into-trickbots-web-injection/"]

    filter_apinames = set(["NtWriteFile"])

    def on_call(self, call, process):
        buf = self.get_argument(call, "Buffer")
        if "browser.tabs.remote.autostart" in buf.lower():
            handlename = self.get_argument(call, "HandleName")
            self.data.append({"handlename": handlename})
            self.data.append({"written_content": buf})
            if self.pid:
                self.mark_call()
            return True


class IEDisablesProcessPerTab(Signature):
    name = "ie_disables_process_tab"
    description = "Disables Interner Explorer creating a new process per tab, possibly for browser injection"
    severity = 3
    categories = ["banker"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1185"]
    references = [" https://www.kryptoslogic.com/blog/2022/01/deep-dive-into-trickbots-web-injection/"]

    def run(self):
        indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Internet Explorer\\\\Main\\\\TabProcGrowth$",
        ]
        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True
