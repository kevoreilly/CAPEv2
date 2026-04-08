#!/usr/bin/env python

from lib.core.packages import Package


class Xdg_open(Package):
    """Start file with xdg-open"""

    summary = "Run via xdg-open"
    description = "Generic package that uses xdg-open to run sample"

    def prepare(self):
        self.args = [self.target] + self.args
        self.target = "/usr/bin/xdg-open"
