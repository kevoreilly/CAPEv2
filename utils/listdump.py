#!/usr/bin/env python
# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import struct

PAGE_EXECUTE_READWRITE = 0x40


def main():
    if len(sys.argv) != 2:
        print("Usage: listdump.py <dump file>")
        return None
    try:
        f = open(sys.argv[1], "rb")
        while True:
            data = f.read(24)
            if data == "":
                break
            addr, size, mem_state, mem_type, mem_prot = struct.unpack("QIIII", data)
            offset = f.tell()
            extra = ""
            if mem_prot == PAGE_EXECUTE_READWRITE:
                extra += ", RWX"
            if f.read(2) == "MZ":
                extra += ", HAS PE"
            print("0x%x: " % offset + "(0x%x" % addr + " -> " + "0x%x)" % (addr + size) + extra)
            f.seek(size - 2, 1)
    except:
        print("Unable to open {0}.".format(sys.argv[1]))
        return None


if __name__ == "__main__":
    main()
