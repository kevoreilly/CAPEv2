# Copyright (C) 2012-2014 Claudio "nex" Guarnieri (@botherder), Optiv Inc. (brad.spengler@optiv.com)
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

class FTPStealer(Signature):
    name = "infostealer_ftp"
    description = "Harvests credentials from local FTP client softwares"
    severity = 3
    categories = ["infostealer"]
    authors = ["nex", "Optiv"]
    minimum = "1.2"
    ttp = ["T1081", "T1003", "T1005"]

    def run(self):
        file_indicators = [
            ".*\\\\CuteFTP\\\\sm\.dat$",
            ".*\\\\FlashFXP\\\\.*\\\\Sites\.dat$",
            ".*\\\\FlashFXP\\\\.*\\\\Quick\.dat$",
            ".*\\\\FileZilla\\\\sitemanager\.xml$",
            ".*\\\\FileZilla\\\\recentservers\.xml$",
            ".*\\\\FTPRush\\\\RushSite\.xml$",
            ".*\\\\VanDyke\\\\Config\\\\Sessions\\\\.*",
            ".*\\\\Far\\ Manager\\\\.*",
            ".*\\\\FTP\\ Explorer\\\\.*",
            ".*\\\\FTP\\ Commander.*",
            ".*\\\\SmartFTP\\\\.*",
            ".*\\\\TurboFTP\\\\.*",
            ".*\\\\FTPRush\\\\.*",
            ".*\\\\LeapFTP\\\\.*",
            ".*\\\\FTPGetter\\\\.*",
            ".*\\\\ALFTP\\\\.*",
            ".*\\\\Ipswitch\\\\WS_FTP\\\\.*",
            ".*\\\\cftp\\\\ftplist.txt$",
        ]
        registry_indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Far.*\\\\Hosts$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Far.*\\\\FTPHost$",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?GlobalSCAPE\\\\CuteFTP.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Ghisler\\\\Windows Commander.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Ghisler\\\\Total Commander.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?BPFTP\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?FileZilla.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?TurboFTP.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Sota\\\\FFFTP.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?FTPWare\\\\CoreFTP\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?FTP\\ Explorer\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?FTPClient\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?LinasFTP\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Robo-FTP.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?MAS-Soft\\\\FTPInfo\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?SoftX\.org\\\\FTPClient\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?NCH\\ Software\\\\CoreFTP\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?BulletProof Software\\\\BulletProof FTP Client.*"
        ]
        found_stealer = False
        for indicator in file_indicators:
            file_match = self.check_file(pattern=indicator, regex=True, all=True)
            if file_match:
                for match in file_match:
                    self.data.append({"file" : match })
                found_stealer = True
        for indicator in registry_indicators:
            key_match = self.check_key(pattern=indicator, regex=True, all=True)
            if key_match:
                for match in key_match:
                    self.data.append({"key" : match })
                found_stealer = True
        return found_stealer
