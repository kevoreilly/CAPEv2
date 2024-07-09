# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class LNK(Package):
    """LNK analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]
    summary = "Execute a .lnk file using cmd.exe."
    description = """Use cmd.exe with the "/wait" option to run a .lnk file.
    For context behind this command:
    /C          Carries out the command specified by string and then terminates
    START       Starts a separate window to run a specified program or command.
    /WAIT       Start application and wait for it to terminate.
    ""          The name of the separate window
    "path"      The path of the uploaded sample
    The .lnk extension will be added automatically."""

    def start(self, path):
        path = check_file_extension(path, ".lnk")
        cmd_path = self.get_path("cmd.exe")
        cmd_args = f'/c start /wait "" "{path}"'
        return self.execute(cmd_path, cmd_args, path)
