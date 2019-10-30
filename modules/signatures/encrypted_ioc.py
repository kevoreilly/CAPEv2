# Copyright (C) 2015 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class EncryptedIOC(Signature):
    name = "encrypted_ioc"
    description = "At least one IP Address, Domain, or File Name was found in a crypto call"
    severity = 2
    weight = 0
    categories = ["crypto"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.iocs = []

    # May add to this later
    filter_apinames = set(["CryptHashData"])
    filter_analysistypes = set(["file"])

    def on_call(self, call, process):
        if call["api"] == "CryptHashData":
            self.iocs.append(self.get_raw_argument(call, "Buffer"))
        return None

    def on_complete(self):
        matches = [
            r'(https?:\/\/)?([\da-z\.-]+)\.([0-9a-z\.]{2,6})(:\d{1,5})?([\/\w\.-]*)\/?',
        ]
        whitelist = [
            "http://crl.microsoft.com",
            "http://www.microsoft.com",
            "asm.v1",
            "asm.v3",
            "verisign.com",
            "symantec.com",
            "thawte.com",
        ]
        dedup = list()
        extracted_data= False
        for potential_ioc in self.iocs:
            for entry in matches:
                all_matches = re.findall(entry, potential_ioc)
                if all_matches:
                    for buf in all_matches:
                        ioc = ""
                        idx = 0
                        for tmp in buf:
                            idx += 1
                            if tmp == '':
                                pass
                            # Account for match groups and the second
                            # (or third depending on match) period as a
                            # delimiter. We need to add it in manually.
                            if idx == 2:
                                ioc += tmp + "."
                            else:
                                ioc += tmp
                        
                        addit = True
                        for item in whitelist:
                            if item in ioc:
                                addit = False
                        if addit and ioc not in dedup:
                            dedup.append(ioc)
        if dedup:
            extracted_data = True
            for ioc in dedup:
                self.data.append({"ioc": ioc})

        return extracted_data
