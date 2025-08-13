from lib.common.abstracts import Package


class NodeJS(Package):
    """Package for executing JavaScript files using NodeJS."""

    PATHS = [
        ("ProgramFiles", "NodeJS", "node.exe"),
        ("LOCALAPPDATA", "Programs", "NodeJS", "node.exe"),
    ]
    summary = "Executes a JS sample using NodeJS."
    description = "Uses node.exe instead of wscript.exe to execute JavaScript files."

    def start(self, path):
        node_path = self.get_path("node.exe")
        return self.execute(node_path, f'"{path}"', path)
