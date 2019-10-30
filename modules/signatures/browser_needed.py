# Copyright (C) 2016 KillerInstinct
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

class BrowserNeeded(Signature):
    name = "browser_needed"
    description = "Repeatedly searches for a not-found browser, may want to run with startbrowser=1 option"
    severity = 2
    categories = ["generic"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.class_names = {
            "Internet Explorer_Hidden": 0,
            "IEFrame": 0,
            "Chrome_WidgetWin_1": 0,
            "MozillaWindowClass": 0,
        }

    filter_apinames = set(["FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW"])

    def on_call(self, call, process):
        class_name = self.get_argument(call, "ClassName")
        if class_name and class_name in self.class_names:
            # Not interested in a successful status
            if not call["status"]:
                self.class_names[class_name] += 1

    def on_complete(self):
        ret = False
        for class_name in self.class_names:
            if self.class_names[class_name] >= 3:
                ret = True
                self.data.append({"ClassName": class_name})

        return ret
