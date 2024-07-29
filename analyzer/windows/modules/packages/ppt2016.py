# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.constants import MSOFFICE_TRUSTED_PATH, TRUSTED_PATH_TEXT


class PPT2007(Package):
    """PowerPoint analysis package."""

    default_curdir = MSOFFICE_TRUSTED_PATH

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    PATHS = [
        ("ProgramFiles", "Microsoft Office*", "root", "Office16", "POWERPNT.EXE"),
    ]
    summary = "Opens sample file with Powerpoint."
    description = f"""Uses 'Office16\\POWERPNT.EXE /s <sample>' to open a powerpoint presentation file.
    {TRUSTED_PATH_TEXT}
    """

    def start(self, path):
        powerpoint = self.get_path_glob("POWERPNT.EXE")
        return self.execute(powerpoint, f'/s "{path}"', path)
