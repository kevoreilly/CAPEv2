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

class SecurityXploded_Modules(Signature):
    name = "securityxploded_modules"
    description = "Sample executed known SecurityXploded programs"
    severity = 3
    categories = ["stealer"]
    authors = ["KillerInstinct"]
    minimum = "1.0"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        # Tuple with file IOC and 'module' name
        self.indicators = [
            ("Browser Password Recovery Report", "BrowserPasswordDecryptor"),
            ("FTP Password Recovery Report", "FTPPasswordDecryptor"),
            ("Email Password Recovery Report", "MailPasswordDecryptor"),
            ("Outlook Password Recovery Report", "OutlookPasswordDecryptor"),
            ("Instant Messengers Password Recovery", "IMPasswordDump"),
            ("Windows License Key Recovery Report", "ProductKeyDecryptor"),
        ]

    filter_apinames = set(["NtWriteFile"])

    def on_call(self, call, process):
        data = self.get_argument(call, "Buffer")
        if data:
            for indicator in self.indicators:
                if indicator[0].lower() in data.lower():
                    saved_to = self.get_argument(call, "HandleName")
                    addit = { indicator[1]: saved_to }
                    if addit not in self.data:
                        self.data.append(addit)

    def on_complete(self):
        if self.data:
            return True

        return False
