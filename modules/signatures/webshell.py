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


class WebShellProcesses(Signature):
    name = "web_shell_processes"
    description = "Creates or executes process commonly used for running web applications, used by web shells"
    severity = 2
    categories = ["command", "evasion"]
    authors = ["bartblaze"]
    minimum = "1.3"
    evented = True
    ttps = ["T1505"]  # MITRE v6,7,8
    ttps += ["T1505.003"]  # MITRE v7,8

    def run(self):
        utilities = [
            "w3wp.exe",
            "httpd.exe",
            "jbosssvc.exe",
            "nginx.exe",
            "php-cgi.exe",
            "tomcat.exe",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    ret = True
                    self.data.append({"command": cmdline})

        return ret


class WebShellFiles(Signature):
    name = "web_shell_files"
    description = "Writes to the inetpub or inetsrv default path, typically seen in web shells"
    severity = 2
    categories = ["command", "evasion"]
    authors = ["bartblaze"]
    minimum = "0.5"
    ttps = ["T1505"]  # MITRE v6,7,8
    ttps += ["T1505.003"]  # MITRE v7,8

    def run(self):
        indicators = [".*\\\\inetpub\\\\wwwroot\\\\.*", ".*\\\\System32\\\\inetsrv\\\\.*"]

        for indicator in indicators:
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False


class OWAWebShellFiles(Signature):
    name = "owa_web_shell_files"
    description = "Writes to the Exchange OWA folder, typically seen in Outlook Web Access web shells"
    severity = 2
    categories = ["command", "evasion"]
    authors = ["bartblaze"]
    minimum = "0.5"
    ttps = ["T1505"]  # MITRE v6,7,8
    ttps += ["T1505.003"]  # MITRE v7,8

    def run(self):
        indicators = [
            "C:\\\\Program Files\\\\Microsoft\\\\Exchange Server\\\\V[0-9]{2}\\\\FrontEnd\\\\HttpProxy\\\\owa\\\\.*",
        ]

        for indicator in indicators:
            match = self.check_write_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False
