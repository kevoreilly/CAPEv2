from lib.common.abstracts import Package


class AutoIT(Package):
    """AutoIT analysis package."""

    def start(self, path):
        arguments = self.options.get("arguments", "")
        return self.execute("bin\\autoit3.exe", f"{path} {arguments}", path)
