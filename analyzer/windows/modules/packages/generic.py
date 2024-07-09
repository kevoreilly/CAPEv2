# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class Generic(Package):
    """Generic analysis package.
    The sample is started using START command in a cmd.exe prompt.
    """

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]
    summary = "Execute the sample file with cmd.exe."
    description = """Uses 'cmd.exe /c start /wait "" "path"' to execute sample files.
    For context behind this command:
    /C          Carries out the command specified by string and then terminates
    START       Starts a separate window to run a specified program or command.
    /WAIT       Start application and wait for it to terminate.
    ""          The name of the separate window
    "path"      The path of the uploaded sample
    """

    def start(self, path):
        cmd_path = self.get_path("cmd.exe")
        # For context behind this command:
        # /C          Carries out the command specified by string and then terminates
        # START       Starts a separate window to run a specified program or command.
        # WAIT        Start application and wait for it to terminate.
        # ""          The name of the separate window
        # "{path}"    The name of the specific program
        cmd_args = f'/c start /wait "" "{path}"'
        return self.execute(cmd_path, cmd_args, path)
