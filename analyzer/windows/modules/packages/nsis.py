# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class NSIS(Package):
    """NSIS analysis package with no crc check.
    The sample is started using START command in a cmd.exe prompt.
    """

    PATHS = [
        ("SystemRoot", "system32", "cmd.exe"),
    ]
    summary = "Execute the sample file with cmd.exe /NCRC"
    description = """Uses 'cmd.exe /c start /wait "" "path" /NCRC' to execute sample files.
    For context behind this command:
    /C          Carries out the command specified by string and then terminates
    START       Starts a separate window to run a specified program or command.
    /WAIT       Start application and wait for it to terminate.
    ""          The name of the separate window
    "path"      The path of the uploaded sample
    /NCRC       Disable CRC checking
    """

    def start(self, path):
        path = check_file_extension(path, ".exe")
        cmd_path = self.get_path("cmd.exe")
        cmd_args = f'/c start /wait "" "{path}" /NCRC'
        return self.execute(cmd_path, cmd_args, path)
