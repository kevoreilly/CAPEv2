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

class antidebug_outputdebugstring(Signature):
    name = "antidebug_outputdebugstring"
    description = "OutputDebugString detected (possible anti-debug)"
    severity = 1
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.set_err = False
        self.output = False

    filter_apinames = set(["OutputDebugStringA", "OutputDebugStringW", "SetLastError", "GetLastError"])

    def on_call(self, call, process):
        if call["api"] == "OutputDebugStringA" or call["api"] == "OutputDebugStringW":
            if self.set_err: 
                self.output = True
            else:
                self.output = False
        elif call["api"] == "SetLastError": 
            self.output = False
            self.set_err = True
        elif call["api"] == "GetLastError": 
            if not self.set_err or not self.output:
                self.set_err = self.output = False

        def on_complete(self):
            if self.set_err and self.output:
                return True

