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

class WineDetectFunc(Signature):
    name = "antiemu_wine_func"
    description = "Detects the presence of Wine emulator via function name"
    severity = 3
    categories = ["anti-emulation"]
    authors = ["Optiv"]
    minimum = "1.0"
    evented = True

    filter_apinames = set(["LdrGetProcedureAddress"])

    def on_call(self, call, process):
        funcname = self.get_argument(call, "FunctionName")
        if not call["status"] and funcname == "wine_get_unix_file_name":
            return True