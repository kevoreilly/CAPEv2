# Copyright (C) 2018 Kevin Ross
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

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class CmdlineObfuscation(Signature):
    name = "cmdline_obfuscation"
    description = "Appears to use command line obfuscation"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = ["https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf"]

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            # using cmd.exe via comspec
            if "%comspec" in cmdline.lower():
                ret = True
                self.data.append({"command" : cmdline})

            # character obfuscation
            elif "cmd" in cmdline.lower() and (cmdline.count("^") > 3 or cmdline.count("&") > 6 or cmdline.count("+") > 4 or cmdline.count("\"") > 8 or cmdline.count(";") > 6):
                ret = True
                self.data.append({"command" : cmdline})

            # concatenation
            elif "cmd" in cmdline.lower() and re.search('(%[^%]+%){4}', cmdline):
                ret = True
                self.data.append({"command" : cmdline})

            # Set variables obfsucation
            elif "cmd" in cmdline.lower() and cmdline.lower().count("set ") > 2:
                ret = True
                self.data.append({"command" : cmdline})

            # Set call obfuscation
            elif "cmd" in cmdline.lower() and "set " in cmdline.lower() and "call " in cmdline.lower():
                ret = True
                self.data.append({"command" : cmdline})

            # for loop obfuscation
            elif "cmd" in cmdline.lower() and "set " in cmdline.lower() and "for " in cmdline.lower():
                ret = True
                self.data.append({"command" : cmdline})

        return ret

class CmdlineSwitches(Signature):
    name = "cmdline_switches"
    description = "Executed a command line with /V argument which modifies variable behaviour and whitespace allowing for increased obfuscation options"
    severity = 2
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            if "cmd" in cmdline.lower() and ("/V" in cmdline or "\V" in cmdline):
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class CmdlineTerminate(Signature):
    name = "cmdline_terminate"
    description = "Executed a command line with /C or /R argument to terminate command shell on completion which can be used to hide execution"
    severity = 1
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            if "cmd" in cmdline.lower() and ("/C" in cmdline or "\C" in cmdline or "/R" in cmdline or "\R" in cmdline):
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class LongCommandline(Signature):
    name = "long_commandline"
    description = "Executed a very long command line or script command which may be indicative of chained commands or obfuscation"
    severity = 2
    confidence = 50
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        utilities = [
            "cmd ",
            "cmd.exe",
            "cscript",
            "hta ",
            "hta.exe",
            "powershell",
            "wscript",
        ]

        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower and len(lower) > 250:
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class CommandLineHTTPLink(Signature):
    name = "cmdline_http_link"
    description = "A HTTP/S link was seen in a script or command line"
    severity = 2
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        utilities = [
            "cmd ",
            "cmd.exe",
            "cscript",
            "hta ",
            "hta.exe",
            "powershell",
            "wscript",
            "msiexec",
        ]
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    if "http://" in lower or "https://" in lower:
                        ret = True
                        self.data.append({"command" : cmdline})

        return ret

class CommandLineReversedHTTPLink(Signature):
    name = "cmdline_reversed_http_link"
    description = "A reversed HTTP/S link was seen in a script or command line"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        utilities = [
            "cmd ",
            "cmd.exe",
            "cscript",
            "hta ",
            "hta.exe",
            "powershell",
            "wscript",
            "msiexec",
        ]
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            lower = cmdline.lower()
            for utility in utilities:
                if utility in lower:
                    if "//:ptth" in lower or "//:sptth" in lower:
                        ret = True
                        self.data.append({"command" : cmdline})

        return ret

class PowershellRenamedCommandLine(Signature):
    name = "powershell_renamed_commandline"
    description = "PowerShell has likely been renamed in a command line"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            if "powershell" in cmdline.lower() and not cmdline.lower().startswith("powershell"):
                if re.findall('=\W+powershell', cmdline.lower()):
                    ret = True
                    self.data.append({"command" : cmdline})

        return ret

class CommandLineLongString(Signature):
    name = "commandline_long_string"
    description = "A script or command line contains a long continuous string indicative of obfuscation"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        utilities = [
            "cmd ",
            "cmd.exe",
            "cscript",
            "hta ",
            "hta.exe",
            "powershell",
            "wscript",
        ]
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            for utility in utilities:
                if utility in cmdline.lower():
                    for string in cmdline.split():
                        if len(string) > 100 and "http://" not in string and "https://" not in string:
                            ret = True
                            self.data.append({"command" : cmdline})
                            break

        return ret
    
class CommandLineForFilesWildCard(Signature):
    name = "commandline_forfiles_wildcard"
    description = "Possible use of forfiles utility with wildcard to potentially launch a utility"
    severity = 3
    categories = ["commands"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    references = "https://twitter.com/danielhbohannon/status/1130833190019653633"

    def run(self):
        ret = False
        cmdlines = self.results["behavior"]["summary"]["executed_commands"]
        for cmdline in cmdlines:
            if "forfiles" in cmdline.lower() and "@file" in cmdline.lower() and "*" in cmdline:
                ret = True
                self.data.append({"command" : cmdline})

        return ret
