# Copyright (C) 2020 ditekshen
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


class MassLoggerVersion(Signature):
    name = "masslogger_version"
    description = "MassLogger infostealer version detected"
    severity = 3
    categories = ["infostealer"]
    families = ["MassLogger"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    mbcs = ["OC0001", "C0052"]  # micro-behaviour

    filter_apinames = set(["NtWriteFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pathpat = "[A-Z]:\\\\.*\\\\AppData\\\\Local\\\\Temp\\\\[A-F0-9]{10}\\\\Log\.txt$"
        self.verpats = [
            "MassLogger\sv\d+\.\d+\.\d+\.\d+",
            "<\|\|\s(v)?\d+\.\d+\.\d+\.\d+\s\|\|>",
        ]

    def on_call(self, call, process):
        handle = self.get_argument(call, "HandleName")
        if handle:
            if re.match(self.pathpat, handle):
                buff = self.get_argument(call, "Buffer")
                if buff and "MassLogger" in buff:
                    for pat in self.verpats:
                        version = re.search(pat, buff)
                        if version:
                            self.data.append({"Version": version})
                            if self.pid:
                                self.mark_call()
                            return True


class MassLoggerArtifacts(Signature):
    name = "masslogger_artifacts"
    description = "MassLogger infostealer artifacts detected"
    severity = 3
    categories = ["infostealer"]
    families = ["MassLogger"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    mbcs = ["OC0001", "C0052"]  # micro-behaviour

    filter_apinames = set(["FindFirstFileExW", "CryptDecrypt"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.artifacts = [
            "[A-Z]:\\\\Windows\\\\assembly\\\\NativeImages_v.*\\\\MassBin.*",
            "[A-Z]:\\\\Windows\\\\assembly\\\\NativeImages_v.*\\\\MassLoggerBin.*",
        ]

    def on_call(self, call, process):
        if call["api"] == "FindFirstFileExW":
            filename = self.get_argument(call, "FileName")
            if filename:
                for artifact in self.artifacts:
                    if re.match(artifact, filename):
                        self.data.append({"Artifact": filename})
                        if self.pid:
                            self.mark_call()
                        return True

        if call["api"] == "CryptDecrypt":
            buff = self.get_argument(call, "Buffer")
            if buff and buff.startswith("MassLogger"):
                self.data.append({"Buffer": buff})
                if self.pid:
                    self.mark_call()
                return True


class MassLoggerFiles(Signature):
    name = "masslogger_files"
    description = "Creates MassLogger infostealer files"
    severity = 3
    categories = ["infostealer"]
    families = ["MassLogger"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    mbcs = ["OC0001", "C0016"]  # micro-behaviour

    def run(self):
        user = self.get_environ_entry(self.get_initial_process(), "UserName")
        indicators = [
            ".*\\\\AppData\\\\Local\\\\Temp\\\\[A-F0-9]{10}\\\\Log\.txt$",
            ".*\\\\AppData\\\\Local\\\\Temp\\\\[A-F0-9]{10}\\\\Screenshot\.jpeg$",
            ".*\\\\AppData\\\\Local\\\\Temp\\\\[A-F0-9]{10}\\\\DotNetZip-.*\.tmp$",
        ]
        score = 0

        try:
            indicators.append(
                ".*\\\\AppData\\\\Local\\\\Temp\\\\[A-F0-9]{10}\\\\"
                + user.decode("utf-8")
                + "_.*_[A-F0-9]{10}_\d{2}-\d{2}-\d{4}\s.*.zip"
            )
        except Exception:
            return False

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                score += 1
                self.data.append({"file": match})

        if score >= 2:
            return True

        return False
