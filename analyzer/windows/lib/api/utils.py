# Copyright (C) 2014-2015 Will Metcalf (william.metcalf@gmail.com)
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import
import os
import logging
import subprocess
import socket

try:
    import re2 as re
except ImportError:
    import re

log = logging.getLogger(__name__)


class Utils:
    """Various Utilities"""

    def is_valid_ipv4(self, ip):
        if ip:
            if re.match("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip) == None:
                return False
            else:
                try:
                    socket.inet_aton(ip)
                    return True
                except socket.error:
                    return False
        else:
            return False

    def cmd_wrapper(self, cmd):
        # print("running command and waiting for it to finish %s" % (cmd))
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = p.communicate()
        return (p.returncode, stdout, stderr)
