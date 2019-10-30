# CAPE - Config And Payload Extraction
# Copyright(C) 2018 redsand (redsand@redsand.net)
# 
# This program is free software : you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class injection_themeinitapihook(Signature):
    name = "injection_themeinitapihook"
    description = "Possible ThemeInitApiHook Injection detected"
    severity = 1
    categories = ["injection"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.loadctr = 0
        self.list = []

    filter_apinames = set(["ThemeInitApiHook"])

    def on_call(self, call, process):
        if call["api"] == "ThemeInitApiHook":
            self.loadctr += 1
            self.data.append({"Injection" : "%s/%s" % (self.get_argument(call, "ModuleName"), self.get_argument(call, "FunctionName")) })

    def on_complete(self):
        if self.loadctr > 0:
            return True

