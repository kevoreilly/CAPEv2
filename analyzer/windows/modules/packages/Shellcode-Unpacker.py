# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import shutil

from lib.common.abstracts import Package
from lib.common.constants import OPT_PROCDUMP, OPT_UNPACKER

log = logging.getLogger(__name__)

_OPT_DUMP_CALLER_REGIONS = "dump-caller-regions"


class Shellcode_Unpacker(Package):
    """32-bit Shellcode Unpacker package."""

    summary = "Execute 32-bit Shellcode using loader.exe with the unpacker option."
    description = f"""Use 'bin\\loader.exe shellcode <sample>' to execute 32-bit Shellcode.
    Set the option '{OPT_UNPACKER}=1'.
    Set the option '{OPT_PROCDUMP}=0' and '{_OPT_DUMP_CALLER_REGIONS}=0'."""

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.options[OPT_UNPACKER] = "1"
        self.options[OPT_PROCDUMP] = "0"
        self.options[_OPT_DUMP_CALLER_REGIONS] = "0"

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
