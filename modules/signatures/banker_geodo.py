# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class Geodo(Signature):
    name = "geodo_banking_trojan"
    description = "Geodo Banking Trojan"
    severity = 3
    categories = ["Banking", "Trojan"]
    families = ["Geodo","Emotet"]
    authors = ["Optiv"]
    minimum = "1.2"

    def run(self):
        match_file = self.check_file(pattern=".*\\\\Application\\ Data\\\\Microsoft\\\\[a-z]{3}(api32|audio|bios|boot|cap32|common|config|crypt|edit32|error|mgr32|serial|setup|share|sock|system|update|video|windows)\.exe$", regex=True, all=True)
        match_batch_file = self.check_file(pattern=".*\\\\Application\\ Data\\\\\d{1,10}\.bat$", regex=True, all=True)
        match_runkey = self.check_key(pattern=".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\[a-z]{3}(api32|audio|bios|boot|cap32|common|config|crypt|edit32|error|mgr32|serial|setup|share|sock|system|update|video|windows)\.exe$", regex=True, all=True)
        match_otherkey = self.check_key(pattern=".*\\\\Microsoft\\\\Office\\\\Common\\\\(?P<hex>[A-F0-9]+)\\\\(?P=hex)(CS|PS|SS|RS)", regex=True, all=True)
        match_mutex = self.check_mutex(pattern="^[A-F0-9]{1,8}(I|M|RM)$", regex=True, all=True)
        if match_file:
            for match in match_file:
                self.data.append({"file": match})
        if match_batch_file:
            for match in match_batch_file:
                self.data.append({"batchfile": match})
        if match_runkey:
            for match in match_runkey:
                self.data.append({"runkey": match})
        if match_otherkey:
            for match in match_otherkey:
                self.data.append({"otherkey": match})
        if match_mutex:
            for match in match_mutex:
                self.data.append({"mutex": match})

        if match_file and match_batch_file and match_mutex and match_runkey and match_otherkey:
                return True

        return False
