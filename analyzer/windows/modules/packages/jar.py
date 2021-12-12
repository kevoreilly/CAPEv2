# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

from lib.common.abstracts import Package


class Jar(Package):
    """Java analysis package."""

    PATHS = [
        ("ProgramFiles", "Java", "jre*", "bin", "java.exe"),
    ]

    def start(self, path):
        java = self.get_path_glob("Java")
        class_path = self.options.get("class")

        if class_path:
            args = f'-cp "{path}" {class_path}'
        else:
            args = f'-jar "{path}"'

        return self.execute(java, args, path)
