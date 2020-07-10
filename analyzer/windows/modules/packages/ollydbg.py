from __future__ import absolute_import
from lib.common.abstracts import Package


class OllyDbg(Package):
    """OllyDbg analysis package."""

    def start(self, path):
        arguments = self.options.get("arguments", "")
        return self.execute("bin\\OllyDbg\\OLLYDBG.EXE", "%s %s" % (path, arguments), path)
