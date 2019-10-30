# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class IMStealer(Signature):
    name = "infostealer_im"
    description = "Harvests information related to installed instant messenger clients"
    severity = 3
    categories = ["infostealer"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttp = ["T1081", "T1003", "T1005"]

    def run(self):
        file_indicators = [
            ".*\\\\AIM\\\\aimx\.bin$",
            ".*\\\\Digsby\\\\loginfo\.yaml$",
            ".*\\\\Digsby\\\\Digsby\.dat$",
            ".*\\\\Meebo\\\\MeeboAccounts\.txt$",
            ".*\\\\Miranda\\\\.*\.dat$",
            ".*\\\\MySpace\\\\IM\\\\users\.txt$",
            ".*\\\\\.purple\\\\Accounts\.xml$",
            ".*\\\\Application\\ Data\\\\Miranda\\\\.*",
            ".*\\\\AppData\\\\Roaming\\\\Miranda\\\\.*",
            ".*\\\\Skype\\\\.*\\\\config\.xml$",
            ".*\\\\Tencent\\ Files\\\\.*\\\\QQ\\\\Registry\.db$",
            ".*\\\\Trillian\\\\users\\\\global\\\\accounts\.ini$",
            ".*\\\\Xfire\\\\XfireUser\.ini$"
        ]
        registry_indicators = [
            ".*\\\\Software\\\\(Wow6432Node\\\\)?America\\ Online\\\\AIM6\\\\Passwords.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?AIM\\\\AIMPRO\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Beyluxe\\ Messenger\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?BigAntSoft\\\\BigAntMessenger\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Camfrog\\\\Client\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Google\\\\Google\\ Talk\\\\Accounts.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?IMVU\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Nimbuzz\\\\PCClient\\\\Application\\\\.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Paltalk.*",
            ".*\\\\Software\\\\(Wow6432Node\\\\)?Yahoo\\\\Pager\\\\.*"
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
