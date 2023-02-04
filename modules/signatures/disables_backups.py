# Copyright (C) 2020 bartblaze
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


class DisablesBackups(Signature):
    name = "disables_backups"
    description = "Disables backups, often seen in ransomware"
    severity = 3
    categories = ["ransomware"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1112", "T1490"]  # MITRE v6,7,8
    mbcs = ["OB0006", "E1112"]
    mbcs += ["OC0008", "C0036"]  # micro-behaviour

    def run(self):
        indicators = [
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\DisableBackupToDisk",
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\DisableBackupToNetwork",
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\DisableBackupToOptical",
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\DisableBackupLauncher",
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\DisableRestoreUI",
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\DisableBackupUI",
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\DisableSystemBackupUI",
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\NoBackupToDisk",
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\NoBackupToNetwork",
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\NoBackupToOptical",
            ".*\\\\Software\\\\Policies\\\\Microsoft\\\\Windows\\\\Backup\\\\Client\\\\NoRunNowBackup",
        ]

        for indicator in indicators:
            match = self.check_write_key(pattern=indicator, regex=True)
            if match:
                self.data.append({"regkey": match})
                return True

        return False
