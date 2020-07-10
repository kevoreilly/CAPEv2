# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os.path

HAVE_RE2 = False
try:
    import re2 as re

    HAVE_RE2 = True
except ImportError:
    import re

from lib.cuckoo.common.utils import bytes2str
from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError


class Strings(Processing):
    """Extract strings from analyzed file."""

    def run(self):
        """Run extract of printable strings.
        @return: list of printable strings.
        """
        self.key = "strings"
        strings = []

        if self.task["category"] in ("file", "static"):
            if not os.path.exists(self.file_path):
                raise CuckooProcessingError('Sample file doesn\'t exist: "%s"' % self.file_path)

            try:
                data = open(self.file_path, "rb").read()
            except (IOError, OSError) as e:
                raise CuckooProcessingError("Error opening file %s" % e)

            nulltermonly = self.options.get("nullterminated_only", True)
            minchars = self.options.get("minchars", 5)

            endlimit = b""
            if not HAVE_RE2:
                endlimit = b"8192"

            if nulltermonly:
                apat = b"([\x20-\x7e]{" + str(minchars).encode("utf-8") + b"," + endlimit + b"})\x00"
                upat = b"((?:[\x20-\x7e][\x00]){" + str(minchars).encode("utf-8") + b"," + endlimit + b"})\x00\x00"
            else:
                apat = b"[\x20-\x7e]{" + str(minchars).encode("utf-8") + b"," + endlimit + b"}"
                upat = b"(?:[\x20-\x7e][\x00]){" + str(minchars).encode("utf-8") + b"," + endlimit + b"}"

            strings = [bytes2str(string) for string in re.findall(apat, data)]
            for ws in re.findall(upat, data):
                strings.append(str(ws.decode("utf-16le")))

        return strings
