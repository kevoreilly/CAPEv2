#!/usr/bin/env python
# Copyright (C) 2018 phdphuc
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

from os import system
from lib.core.packages import Package


class Generic(Package):
    """ Generic analysis package. """

    def prepare(self):
        # Make sure that our target is executable
        # /usr/bin/open will handle it
        system('/bin/chmod +x "%s"' % self.target)
        self.args = [self.target] + self.args
        self.target = "sh -c"
