#!/usr/bin/python

# Copyright 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import sys
import os
import time
from six.moves import range

iface = ""
for idx, arg in enumerate(sys.argv):
    if arg == "-i" and idx < len(sys.argv) - 1:
        iface = sys.argv[idx + 1]

for i in range(30):
    f = open("/proc/net/dev", "rb")
    for line in f:
        dev = line.split(":")[0]
        if dev == iface:
            break
    f.close()
    time.sleep(0.5)

os.execve("/usr/sbin/tcpdump", sys.argv, os.environ)
