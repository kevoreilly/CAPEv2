# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class VersionInfoAnomaly(Signature):
    name = "static_versioninfo_anomaly"
    description = "Unusual version info supplied for binary"
    severity = 3
    categories = ["static"]
    authors = ["Optiv"]
    minimum = "1.3"

    def run(self):
        found_sig = False

        if not "static" in self.results or not "pe" in self.results["static"] or not "versioninfo" in self.results["static"]["pe"]:
            return False

        msincopyright = None
        msincompanyname = None
        mstransposed = False
    
        # Microsoft Corporation sorted
        mscorpsorted = " CMacfiinoooooprrrstt"

        for info in self.results["static"]["pe"]["versioninfo"]:
            if info["name"] == "LegalCopyright":
                if "microsoft" in info["value"].lower():
                    msincopyright = True
                else:
                    msincopyright = False
            elif info["name"] == "CompanyName":
                if ''.join(sorted(info["value"])) == mscorpsorted and info["value"] != "Microsoft Corporation":
                    mstransposed = True

                if "microsoft" in info["value"].lower():
                    msincompanyname = True
                else:
                    msincompanyname = False

        if msincopyright == True and msincompanyname == False:
            self.data.append({"anomaly" : "Microsoft mentioned in LegalCopyright, but not in CompanyName field"})
            found_sig = True
        if mstransposed == True:
            self.data.append({"anomaly" : "CompanyName is a transposed form of \"Microsoft Corporation\"."})
            self.families = ["Bedep"]
            found_sig = True

        return found_sig
