# Copyright (C) 2014-2016 Optiv, Inc. (brad.spengler@optiv.com), KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Signature

class InstalledApps(Signature):
    name = "recon_programs"
    description = "Collects information about installed applications"
    severity = 3
    confidence = 20
    categories = ["recon"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttp = ["T1012", "T1082"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.programs = set()
        self.check = True
        office_pkgs = ["ppt","doc","xls","eml","pdf"]
        if any(e in self.results["info"]["package"] for e in office_pkgs):
            self.check = False

    filter_apinames = set(["RegQueryValueExA", "RegQueryValueExW"])

    def on_call(self, call, process):
        if not self.check:
            return None

        if call["api"].startswith("RegQueryValueEx"):
            keyname = self.get_argument(call, "FullName")
            uninstall = "\\microsoft\\windows\\currentversion\\uninstall"
            if (keyname and uninstall in keyname.lower() and
                keyname.lower().endswith("displayname")):
                app = self.get_argument(call, "Data")
                if app:
                    # Ignore language/architecture name segments
                    buf = re.sub(r"\([^\)]+\)", "", app).strip()
                    self.programs.add(buf)

    def on_complete(self):
        if self.programs:
            for program in self.programs:
                self.data.append({"Program": program})
            return True

        return False
