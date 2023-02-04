# Copyright (C) 2019 Kevin Ross
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


class ModifiesAttachmentManager(Signature):
    name = "modify_attachment_manager"
    description = (
        "Attempts to modify the Microsoft attachment manager possibly to bypass security checks on mail and Internet saved files"
    )
    severity = 3
    categories = ["anti-av", "bypass"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    ttps = ["T1089"]  # MITRE v6
    ttps += ["T1112"]  # MITRE v6,7,8
    ttps += ["T1562", "T1562.001"]  # MITRE v7,8
    ttps += ["U0508"]  # Unprotect
    mbcs = ["OB0006", "E1112", "F0004", "F0004.005"]
    mbcs += ["OC0008", "C0036", "C0036.001"]  # micro-behaviour
    references = ["https://support.microsoft.com/en-us/help/883260/information-about-the-attachment-manager-in-microsoft-windows"]

    def run(self):
        reg_indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Attachments\\\\SaveZoneInformation$",
        ]

        for indicator in reg_indicators:
            reg_match = self.check_write_key(pattern=indicator, regex=True, all=True)
            if reg_match:
                return True

        return False
