from lib.common.abstracts import Package
from lib.common.common import check_file_extension
from lib.common.constants import OPT_ARGUMENTS


class NodeJS(Package):
    """Package for executing JavaScript files using NodeJS."""

    PATHS = [
        ("ProgramFiles", "NodeJS", "node.exe"),
        ("LOCALAPPDATA", "Programs", "NodeJS", "node.exe"),
    ]
    summary = "Executes a JS sample using NodeJS."
    description = "Uses node.exe instead of wscript.exe to execute JavaScript files."
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        node = self.get_path("node.exe")
        path = check_file_extension(path, ".js")
        args = self.options.get(OPT_ARGUMENTS, "")
        return self.execute(node, f'"{path}" {args}', path)
