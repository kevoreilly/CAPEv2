# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class SennaMutexes(Signature):
    name = "rat_senna_mutexes"
    description = "Creates known Senna Spy mutexes"
    severity = 3
    categories = ["rat"]
    families = ["Senna"]
    # Migrated by @CybercentreCanada
    authors = ["RedSocks", "@CybercentreCanada"]
    minimum = "1.2"

    def on_complete(self):
        mutexes_re = [
            ".*Senna\\ Spy\\ Fenasoft\\ 2000\\ Virus",
            ".*Senna\\ Spy\\ Rock\\ In\\ Rio\\ 2001\\ Virus",
            ".*Senna\\ Spy\\ Virus",
        ]
        for indicator in mutexes_re:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.data.append({"mutex": match})

        if len(self.data) > 0:
            return True
        else:
            return False
