# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


from __future__ import absolute_import
import os
from lib.common.abstracts import Package


class XLS2207(Package):
    """Excel analysis package."""

    def __init__(self, options={}, config=None):
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office*", "root", "Office16", "EXCEL.EXE"),
    ]

    def start(self, path):
        if "." not in os.path.basename(path):
            new_path = path + ".xls"
            os.rename(path, new_path)
            path = new_path

        excel = self.get_path_glob("Microsoft Office Excel")
        return self.execute(excel, '"%s" /dde' % path, path)
