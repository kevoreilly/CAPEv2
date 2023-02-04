# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class UpatreFiles(Signature):
    name = "upatre_files"
    description = "Creates known Upatre files"
    severity = 3
    categories = ["rat"]
    families = ["upatre"]
    # Migrated by @CybercentreCanada
    authors = ["RedSocks", "@CybercentreCanada"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.files_re = [
            ".*Temp.*account.*report.*scr",
            ".*Temp.*invoice.*exe",
            ".*Temp.*mmo.*txt",
            ".*Temp.*doc.*pdf.*scr",
            ".*WINDOWS.*system32.*qcap.*dll",
            ".*Temp.*seefile.*exe",
            ".*Temp.*sinstall.*exe",
            ".*Temp.*Umlineded.*exe",
            ".*Temp.*planeris.*exe",
        ]

    def on_complete(self):
        for indicator in self.files_re:
            regkey = self.check_file(pattern=indicator, regex=True)
            if regkey:
                self.data.append({"file": regkey})

        if len(self.data) > 0:
            return True
        else:
            return False
