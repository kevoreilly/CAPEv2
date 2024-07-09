# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class MSBUILD(Package):
    """msbuild analysis package."""

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        self.config = config
        self.options = options

    PATHS = [
        ("SystemRoot", "Microsoft.NET", "Framework", "v4.0.30319", "msbuild.exe"),
    ]
    summary = "Open a dotnet project file with MSBuild."
    description = """Use 'MSBUILD.EXE <sample>' to open a dotnet project file."""

    def start(self, path):
        msbuild = self.get_path_glob("msbuild.exe")
        return self.execute(msbuild, f'"{path}"', path)
