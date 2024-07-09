from lib.common.abstracts import Package
from lib.common.constants import OPT_ARGUMENTS


class OllyDbg(Package):
    """OllyDbg analysis package."""

    summary = "Open the sample with OllyDbg"
    description = f"""Use 'bin\\OllyDbg\\OLLYDBG.EXE <sample> [arguments]' to launch the sample.
    The '{OPT_ARGUMENTS}' option can be used to pass additional arguments."""
    option_names = (OPT_ARGUMENTS,)

    def start(self, path):
        arguments = self.options.get(OPT_ARGUMENTS, "")
        return self.execute("bin\\OllyDbg\\OLLYDBG.EXE", f"{path} {arguments}", path)
