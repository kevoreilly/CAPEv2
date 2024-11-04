from lib.common.abstracts import Package
from lib.common.common import check_file_extension


class RDP(Package):
    """RDP analysis package."""

    PATHS = [
        ("SystemRoot", "system32", "mstsc.exe"),
    ]

    def start(self, path):
        args = self.options.get("arguments")

        path = check_file_extension(path, ".rdp")
        mstsc = self.get_path_glob("mstsc.exe")
        return self.execute(mstsc, f'"{path}" {args}', path)
