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

class DCRatFiles(Signature):
    name = "dcrat_files"
    description = "Creates DCRat RAT directories and/or files"
    severity = 3
    categories = ["infostealer", "keylogger", "RAT"]
    families = ["DCRat"]
    authors = ["ditekshen"]
    minimum = "1.3"

    def run(self):
        indicators = [
            ".*\\\\dclib\\\.*\.dclib$",
            ".*\\\\dclib\\\\AntiVM.dclib$",
        ]

        for indicator in indicators:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.data.append({"file": match})
                return True

        return False

class DCRatMutex(Signature):
    name = "dcrat_mutexes"
    description = "Creates DCRat RAT mutexes"
    severity = 3
    categories = ["infostealer", "keylogger", "RAT"]
    families = ["DCRat"]
    authors = ["ditekshen"]
    minimum = "1.3"

    def run(self):
        indicators = [
            "^[a-f0-9]{32}$",
            "DCR_MUTEX-.*",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False

def unbuffered_b64decode(data):
    data = data.replace("\r", "").replace("\n","")
    data += "=" * ((4 - len(data) % 4) % 4)
    try:
        data = data.decode("base64")
    except Exception as e:
        pass

    return data

class DCRatAPIs(Signature):
    name = "dcrat_behavior"
    description = "Exhibits behavior characteristics of DCRat RAT"
    severity = 3
    weight = 3
    categories = ["infostealer", "keylogger", "RAT"]
    families = ["DCRat"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["GetAddrInfo", "GetAddrInfoW", "CryptHashData"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.score = 0
        self.nodename = str()
        self.pat = re.compile('^(s_comm|m_comm|command)[a-f0-9]{40}$')
        self.dkeywords = [
            "token_uid",
            "data_name",
            "data_extension",
            "password",
        ]
        self.bkeywords = [
            "MX:DCR_MUTEX-",
            "MHost:",
            "BHost:",
            ", TAG:"
        ]

    def on_call(self, call, process):
        if call["api"] == "GetAddrInfoW":
            buff = self.get_argument(call, "NodeName")
            if buff:
                self.nodename = buff

        elif call["api"] == "CryptHashData":
            buff = self.get_argument(call, "Buffer")
            if buff:
                match = re.match(self.pat, buff)
                if match:
                    self.score += 1
                elif buff.startswith(self.nodename):
                    for word in self.dkeywords:
                        tag = self.nodename + word
                        if buff == tag:
                            self.score += 1
                elif buff.startswith("userdatahttp"):
                    self.score += 1
                else:
                    decoded = unbuffered_b64decode(buff)
                    for word in self.bkeywords:
                        if word in decoded:
                            self.score += 2
    
    def on_complete(self):
        if self.score >= 5:
            return True

        return False
