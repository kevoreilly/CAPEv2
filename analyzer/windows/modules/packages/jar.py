# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class Jar(Package):
    """Java analysis package."""

    PATHS = [
        ("ProgramFiles", "Java", "jre*", "bin", "java.exe"),
    ]

    def start(self, path):
        java = self.get_path_glob("Java")
        class_path = self.options.get("class")

        args = f'-cp "{path}" {class_path}' if class_path else f'-jar "{path}"'
        return self.execute(java, args, path)
