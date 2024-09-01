# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class Batch(Package):
    """batch analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]
    summary = "Executes the batch scripts with cmd.exe."
    description = """Uses 'cmd.exe /c start /wait "" "path"' to execute sample files.
    For context behind this command:
    /C          Carries out the command specified by string and then terminates
    START       Starts a separate window to run a specified program or command.
    /WAIT       Start application and wait for it to terminate.
    ""          The name of the separate window
    "path"      The path of the uploaded batch file.
    """

    def start(self, path):
        cmd_path = self.get_path("cmd.exe")
        # For context behind this command:
        # /C          Carries out the command specified by string and then terminates
        # START       Starts a separate window to run a specified program or command.
        # WAIT        Start application and wait for it to terminate.
        # ""          The name of the separate window
        # "{path}"    The name of the specific batch file

        path = check_file_extension(path, ".bat")
        cmd_args = f'/c start /wait "" "{path}"'
        return self.execute(cmd_path, cmd_args, path)
