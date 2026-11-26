#!/usr/bin/env python
# Copyright (C) 2024 xiangchen96
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import shlex
import sys

from lib.core.packages import Package


class Python_whl(Package):
    """Python wheel analysis package."""

    def prepare(self):
        self.args = [self.target] + self.args
        python_bin = shlex.quote(sys.executable or "/usr/bin/python3")
        self.target = f"/usr/bin/env PIP_BREAK_SYSTEM_PACKAGES=1 {python_bin} -m pip install"
