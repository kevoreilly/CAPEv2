# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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

class SpoofsProcname(Signature):
    name = "spoofs_procname"
    description = "Spoofs its process name and/or associated pathname to appear as a legitimate process"
    severity = 3
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True

    filter_categories = set(["__notification__"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.saw_spoof = False
        self.spoof_sets = []

    def on_call(self, call, process):
        procname = self.check_argument_call(call,
                                               api="__anomaly__",
                                               name="Subcategory",
                                               pattern="procname")
        if procname:
            self.saw_spoof = True
            origname = self.get_argument(call, "OriginalProcessName")
            origpath = self.get_argument(call, "OriginalProcessPath")
            modname = self.get_argument(call, "ModifiedProcessName")
            modpath = self.get_argument(call, "ModifiedProcessPath")
            newentry = {"original_name" :  origname, "original_path" : origpath, "modified_name" : modname, "modified_path" : modpath}
            if newentry not in self.spoof_sets:
                self.spoof_sets.append(newentry)
    
    def on_complete(self):
        for spoof in self.spoof_sets:
            self.data.append(spoof)
        return self.saw_spoof
