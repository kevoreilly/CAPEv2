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

        if "static" not in self.results or "pe" not in self.results["static"] or "versioninfo" not in self.results["static"]["pe"]:
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
                if "".join(sorted(info["value"])) == mscorpsorted and info["value"] != "Microsoft Corporation":
                    mstransposed = True

                if "microsoft" in info["value"].lower():
                    msincompanyname = True
                else:
                    msincompanyname = False

        if msincopyright is True and msincompanyname is False:
            self.data.append({"anomaly": "Microsoft mentioned in LegalCopyright, but not in CompanyName field"})
            found_sig = True
        if mstransposed is True:
            self.data.append({"anomaly": 'CompanyName is a transposed form of "Microsoft Corporation".'})
            self.families = ["Bedep"]
            found_sig = True

        return found_sig
