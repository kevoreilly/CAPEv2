# Copyright (C) 2012 Claudio "nex" Guarnieri (@botherder)
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


class VBoxDetectLibs(Signature):
    name = "antivm_vbox_libs"
    description = "Detects VirtualBox through the presence of a library"
    severity = 3
    categories = ["anti-vm"]
    authors = ["nex"]
    minimum = "1.3"
    evented = True
    ttps = ["T1057", "T1083", "T1497"]  # MITRE v6,7,8
    ttps += ["U1333", "U1314"]  # Unprotect
    mbcs = ["OB0001", "B0009", "B0009.001", "OB0007", "E1083"]

    filter_apinames = set(["LdrLoadDll"])

    def on_call(self, call, process):
        indicators = [
            "VBoxDisp.dll",
            "VBoxHook.dll",
            "VBoxMRXNP.dll",
            "VBoxOGL.dll",
            "VBoxOGLarrayspu.dll",
            "VBoxOGLcrutil.dll",
            "VBoxOGLerrorspu.dll",
            "VBoxOGLfeedbackspu.dll",
            "VBoxOGLpackspu.dll",
            "VBoxOGLpassthroughspu.dll",
        ]

        for indicator in indicators:
            if self.check_argument_call(call, pattern=indicator, name="FileName", ignorecase=True):
                if self.pid:
                    self.mark_call()
                return True
