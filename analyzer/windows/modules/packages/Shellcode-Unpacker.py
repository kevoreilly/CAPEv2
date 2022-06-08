# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil

from lib.common.abstracts import Package

log = logging.getLogger(__name__)


class Shellcode_Unpacker(Package):
    """32-bit Shellcode Unpacker package."""

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.options["unpacker"] = "1"
        self.options["procdump"] = "0"
        self.options["dump-caller-regions"] = "0"

    def start(self, path):
        loaderpath = "bin\\loader.exe"
        arguments = f"shellcode {path}"

        # we need to move out of the analyzer directory
        # due to a check in monitor dll
        basepath = os.path.dirname(path)
        newpath = os.path.join(basepath, os.path.basename(loaderpath))
        shutil.copy(loaderpath, newpath)

        log.info("[-] newpath : %s", newpath)
        log.info("[-] arguments : %s", arguments)

        return self.execute(newpath, arguments, newpath)
