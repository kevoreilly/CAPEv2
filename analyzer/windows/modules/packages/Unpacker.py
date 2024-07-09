# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS, OPT_INJECTION, OPT_PROCDUMP, OPT_UNPACKER


class Unpacker(Package):
    """CAPE Unpacker analysis package."""

    # PATHS = [
    #    ("SystemRoot", "system32"),
    # ]
    summary = "Execute a .exe file with the unpacker option."
    description = f"""Execute the sample passing 'arguments' if any, using the 'unpacker' option.
    Turn off the '{OPT_PROCDUMP}' and '{OPT_INJECTION}' options.
    The .exe filename extension will be added automatically."""
    option_names = (OPT_ARGUMENTS,)

    def __init__(self, options=None, config=None):
        """@param options: options dict."""
        if options is None:
            options = {}
        self.config = config
        self.options = options
        self.pids = []
        self.options[OPT_UNPACKER] = "1"
        self.options[OPT_PROCDUMP] = "0"
        self.options[OPT_INJECTION] = "0"

    def start(self, path):
        arguments = self.options.get(OPT_ARGUMENTS)

        # If the file doesn't have an extension, add .exe
        # See CWinApp::SetCurrentHandles(), it will throw
        # an exception that will crash the app if it does
        # not find an extension on the main exe's filename
        path = check_file_extension(path, ".exe")
        return self.execute(path, arguments, path)
