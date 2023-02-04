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


class CapturesScreenshot(Signature):
    name = "captures_screenshot"
    description = "Captures Screenshot"
    severity = 3
    categories = ["infostealer", "rat"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    ttps = ["T1113"]  # MITRE v6,7,8
    mbcs = ["E1113"]

    filter_apinames = set(["LdrGetProcedureAddress", "NtCreateFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.capturesc = False
        self.savesc = False
        self.wrtiesc = False

    def on_call(self, call, process):
        if call["api"] == "LdrGetProcedureAddress":
            modulename = self.get_argument(call, "ModuleName")
            if modulename:
                if modulename.lower() == "gdiplus.dll":
                    funcationname = self.get_argument(call, "FunctionName")
                    if funcationname:
                        if (
                            funcationname.lower() == "gdipcreatebitmapfromhbitmap"
                            or funcationname.lower() == "gdipcreatebitmapfromscan0"
                        ):
                            self.capturesc = True
                            if self.pid:
                                self.mark_call()
                        if funcationname.lower() == "gdipsaveimagetofile":
                            self.savesc = True
                            if self.pid:
                                self.mark_call()

        if self.capturesc and self.savesc:
            if call["api"] == "NtCreateFile":
                filename = self.get_argument(call, "FileName")
                if filename:
                    if filename.lower().endswith((".jpg", ".jpeg", ".png", ".bmp")):
                        self.wrtiesc = True
                        if self.pid:
                            self.mark_call()

    def on_complete(self):
        if self.capturesc and self.savesc and self.wrtiesc:
            return True

        return False
