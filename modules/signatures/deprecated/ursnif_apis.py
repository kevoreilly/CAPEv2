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


class Ursnif_APIs(Signature):
    name = "ursnif_behavior"
    description = "Exhibits behavior characteristics of Ursnif spyware"
    severity = 3
    weight = 3
    categories = ["keylogger"]
    families = ["Ursnif"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RtlDecompressBuffer"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.decompMZ = set()

    def on_call(self, call, process):
        buf = self.get_argument(call, "UncompressedBuffer")
        if buf.startswith("MZ"):
            try:
                self.decompMZ.add(str(process["module_path"]).lower())
                if self.pid:
                    self.mark_call()
            except:
                pass

    def on_complete(self):
        badness = 0
        cmdpat = r"^[A-Za-z]:\\.*\\[0-9A-Fa-f]{2,4}\\[0-9A-Fa-f]{1,4}\.bat\s"
        if self.check_executed_command(pattern=cmdpat, regex=True):
            arg1, arg2 = None, None
            for command in self.results["behavior"]["summary"]["executed_commands"]:
                command = command.lower()
                if len(command.split()) == 3 and ".bat" in command.split()[0][-5:]:
                    _, arg1, arg2 = command.split()
                else:
                    if command.replace(" ", "").startswith("cmd/c") and arg1 and arg2:
                        buf = command.split('"')
                        arg1 = arg1.replace('"', "")
                        arg2 = arg2.replace('"', "")
                        if arg2 in buf:
                            self.ttps += ["T1059"]  # MITRE v6,7,8
                            self.mbcs += ["OB0009", "E1059"]
                            if arg1 in buf:
                                badness += 8
                            # Handle shortnames
                            elif "~1" in arg1:
                                tmp = arg1.split("~1")
                                if all(z in buf for z in tmp):
                                    badness += 8
                    else:
                        pass

            if arg1 and arg1 in self.decompMZ:
                badness += 4
            # Handle shortnames
            elif arg1 and "~1" in arg1:
                tmp = arg1.split("~1")
                for mpath in self.decompMZ:
                    if all(z in mpath for z in tmp):
                        badness += 4
                        break

        keypat = r".*\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\EnableSPDY3_0$"
        if self.check_write_key(pattern=keypat, regex=True):
            self.ttps += ["T1112"]  # MITRE v6,7,8
            self.mbcs += ["E1112"]
            self.mbcs += ["OC0008", "C0036"]  # micro-behaviour
            badness += 2

        mutexpat = r"(?:Local\\)?\{[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\}"
        mutexes = self.check_mutex(pattern=mutexpat, regex=True, all=True)
        if mutexes:
            self.mbcs += ["OC0003", "C0042"]  # micro-behaviour
            mutex_count = len(mutexes)
            if mutex_count >= 2:
                badness += 2
            else:
                badness += mutex_count

        if badness >= 13:
            return True

        return False
