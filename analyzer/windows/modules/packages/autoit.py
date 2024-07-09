from lib.common.abstracts import Package
from lib.common.constants import OPT_ARGUMENTS


class AutoIT(Package):
    """AutoIT analysis package."""

    summary = "Execute the sample with autoit3."
    description = """Use 'bin\\autoit3.exe <sample> [arguments]' to execute the sample,
    Use the 'arguments' option to provide additional arguments."""
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        arguments = self.options.get(OPT_ARGUMENTS, "")
        return self.execute("bin\\autoit3.exe", f"{path} {arguments}", path)
