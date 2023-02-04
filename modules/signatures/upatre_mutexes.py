# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# This signature was contributed by RedSocks - http://redsocks.nl
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class UpatreMutexes(Signature):
    name = "upatre_files"
    description = "Creates known Upatre mutexes"
    severity = 3
    categories = ["rat"]
    families = ["upatre"]
    # Migrated by @CybercentreCanada
    authors = ["RedSocks", "@CybercentreCanada"]
    minimum = "2.0"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.mutexes_re = [
            ".*553wwerdty7",
            ".*zx5fwtw4ep",
        ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.data.append({"mutex": mutex})

        if len(self.data) > 0:
            return True
        else:
            return False
