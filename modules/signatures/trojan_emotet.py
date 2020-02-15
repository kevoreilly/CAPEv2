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

from lib.cuckoo.common.abstracts import Signature

class EmotetMutexes(Signature):
    name = "emotet_mutexes"
    description = "Creates Emotet Trojan mutexes"
    severity = 3
    categories = ["trojan"]
    families = ["Emotet"]
    authors = ["ditekshen"]
    minimum = "1.3"

    def run(self):
        indicators = [
            "^Global\\\\[IM][A-F0-9]{7,8}$",
        ]

        for indicator in indicators:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})
                return True

        return False

class EmotetRegistryKeys(Signature):
    name = "emotet_registry_keys"
    description = "Creates Emotet Trojan registry keys"
    severity = 3
    categories = ["trojan"]
    families = ["Emotet"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    reference = ["https://github.com/JPCERTCC/EmoCheck/blob/master/emocheck/emocheck.cpp"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.volumeserialnumber = str()

    filter_apinames = set(["GetVolumeInformationByHandleW"])

    def on_call(self, call, process):
        buff = self.get_argument(call, "VolumeSerial")
        if buff:
            self.volumeserialnumber = buff

    def on_complete(self):
        indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\",
            ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\\\CurrentVersion\\\\explorer\\\\",
        ]

        if self.volumeserialnumber:
            for indicator in indicators:
                indicator = indicator + self.volumeserialnumber.lstrip("0x").lower()
                match = self.check_key(pattern=indicator, regex=True)
                if match:
                    self.data.append({"regkey": match})
                    return True

        return False


def get_word(keywords, ptr, keylen):
    keyword = str()
    for i in range(ptr, 0, -1):
        if keywords[i] != ',':
            continue
        else:
            ptr = i
            break

    if keywords[ptr] == ",":
        ptr += 1

    for i in range(ptr, keylen, 1):
        if keywords[i] != ',':
            keyword = keyword + keywords[i]
            ptr += 1
        else:
            break

    return keyword

# First method - old emotet (- 2020/02/05)
class EmotetPrcocessNamesList(Signature):
    name = "emotet_process_names_list"
    description = "Creates Emotet Trojan process name via list"
    severity = 3
    categories = ["trojan"]
    families = ["Emotet"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    reference = ["https://github.com/JPCERTCC/EmoCheck/blob/master/emocheck/emocheck.cpp"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.volumeserialnumber = 0
        self.keywords = "duck,mfidl,targets,ptr,khmer,purge,metrics,acc,inet,msra,symbol,driver," \
        "sidebar,restore,msg,volume,cards,shext,query,roam,etw,mexico,basic,url," \
        "createa,blb,pal,cors,send,devices,radio,bid,format,thrd,taskmgr,timeout," \
        "vmd,ctl,bta,shlp,avi,exce,dbt,pfx,rtp,edge,mult,clr,wmistr,ellipse,vol," \
        "cyan,ses,guid,wce,wmp,dvb,elem,channel,space,digital,pdeft,violet,thunk"
        self.mkeyword = list()

    filter_apinames = set(["GetVolumeInformationByHandleW"])

    def on_call(self, call, process):
        keylen = len(self.keywords)

        if call["api"] == "GetVolumeInformationByHandleW":
            buff = self.get_argument(call, "VolumeSerial")
            if buff:
                self.volumeserialnumber = buff

        # first round
        q = int(self.volumeserialnumber, 16) / keylen
        mod = int(self.volumeserialnumber, 16) % keylen
        self.mkeyword.append(get_word(self.keywords, mod, keylen))

        # second round
        seed = 0xFFFFFFFF - q
        mod = seed % keylen
        self.mkeyword.append(get_word(self.keywords, mod, keylen))

    def on_complete(self):
        if self.mkeyword:
            for keyword in self.mkeyword:
                match = self.check_process_name(pattern=keyword, regex=True)
                if match:
                    self.data.append({"process": match})
                    return True

        return False

# Second method - new emotet (2020/02/06 -)
"""
class EmotetPrcocessNamesRegistry(Signature):
    name = "emotet_process_names_registry"
    description = "Creates Emotet Trojan process name via registry"
    severity = 3
    categories = ["trojan"]
    families = ["Emotet"]
    authors = ["ditekshen"]
    minimum = "1.3"
    evented = True
    reference = ["https://github.com/JPCERTCC/EmoCheck/blob/master/emocheck/emocheck.cpp"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.volumeserialnumber = str()
        self.emoprocname = str()

    filter_apinames = set(["GetVolumeInformationByHandleW", "RegSetValueExW"])

    def on_call(self, call, process):
        if call["api"] == "GetVolumeInformationByHandleW":
            buff = self.get_argument(call, "VolumeSerial")
            if buff:
                self.volumeserialnumber = buff

        if call["api"] == "RegSetValueExW":
            valuename = self.get_argument(call, "ValueName")
            if valuename and valuename.lower() == self.volumeserialnumber.lstrip("0x").lower():
                bufflen = self.get_argument(call, "BufferLength")
                buff = self.get_argument(call, "Buffer")
                if buff:
                    self.emoprocname = buff
"""
