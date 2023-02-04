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


class DllLoadUncommonFileTypes(Signature):
    name = "dll_load_uncommon_file_types"
    description = "A file with an unusual extension was attempted to be loaded as a DLL."
    severity = 1
    categories = ["anti-debug"]
    authors = ["@CybercentreCanada"]
    minimum = "1.2"
    ttps = ["T1574"]
    evented = True

    filter_apinames = set(["LdrLoadDll"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.indicator = ".+\.(?!dll).{1,4}$"
        self.safelist = [
            "winspool.drv",
            "wdmaud.drv",
            "_socket.pyd",
            "annots.api",
            "mscss7wre_en.dub",
            "outlook.exe",
            ".cnv",  # Word
            ".api",  # Adobe Reader
            ".dub",  # Word
        ]

    def on_call(self, call, _):
        dllname = self.get_argument(call, "FileName")
        if not any(item in dllname.lower() for item in self.safelist):
            if self._check_value(self.indicator, dllname, regex=True):
                if self.pid:
                    self.mark_call()
                return True
