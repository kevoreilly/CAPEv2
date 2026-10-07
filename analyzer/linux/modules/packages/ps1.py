#!/usr/bin/env python
from lib.core.packages import Package


class Pwsh(Package):
    """Powershell script analysis package."""

    def prepare(self):
        self.args = [self.target] + self.args
        self.target = "/usr/bin/pwsh -NoProfile -File"
