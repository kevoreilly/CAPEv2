from lib.common.abstracts import Package
from lib.common.constants import OPT_ARGUMENTS


class AutoIT(Package):
    """AutoIT analysis package."""

    summary = "Executes the sample with autoit3."
    description = f"""Uses 'bin\\autoit3.exe <sample> [arguments]' to execute the sample,
    Set the '{OPT_ARGUMENTS}' option to provide additional arguments."""
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        arguments = self.options.get(OPT_ARGUMENTS, "")
        return self.execute("bin\\autoit3.exe", f"{path} {arguments}", path)
