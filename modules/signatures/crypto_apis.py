# Copyright (C) 2017 Kevin Ross
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


class CryptGenKey(Signature):
    name = "generates_crypto_key"
    description = "Uses Windows APIs to generate a cryptographic key"
    severity = 1
    # Migrated by @CybercentreCanada
    authors = ["Kevin Ross", "@CybercentreCanada"]
    minimum = "1.2"
    evented = True

    filter_apinames = set(["CryptGenKey", "CryptExportKey"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.process_safelist = ["powershell.exe", "winword.exe", "powerpnt.exe", "excel.exe"]

    def on_call(self, _, process):
        if process["process_name"] in self.process_safelist:
            return False
        if self.pid:
            self.mark_call()
        return True
