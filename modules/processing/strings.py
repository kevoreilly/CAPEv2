# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os.path

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError
from lib.cuckoo.common.utils import bytes2str

try:
    import re2 as re

    HAVE_RE2 = True
except ImportError:
    import re

    HAVE_RE2 = False


def extract_strings(path, nulltermonly, minchars):
    strings = []

    try:
        with open(path, "rb") as f:
            data = f.read()
    except (IOError, OSError) as e:
        raise CuckooProcessingError(f"Error opening file {e}") from e

    endlimit = b"8192" if not HAVE_RE2 else b""
    if nulltermonly:
        apat = b"([\x20-\x7e]{" + str(minchars).encode() + b"," + endlimit + b"})\x00"
        upat = b"((?:[\x20-\x7e][\x00]){" + str(minchars).encode() + b"," + endlimit + b"})\x00\x00"
    else:
        apat = b"[\x20-\x7e]{" + str(minchars).encode() + b"," + endlimit + b"}"
        upat = b"(?:[\x20-\x7e][\x00]){" + str(minchars).encode() + b"," + endlimit + b"}"

    strings = [bytes2str(string) for string in re.findall(apat, data)]
    strings.extend(str(ws.decode("utf-16le")) for ws in re.findall(upat, data))
    return strings


class Strings(Processing):
    """Extract strings from analyzed file."""

    def run(self):
        """Run extract of printable strings.
        @return: list of printable strings.
        """
        self.key = "strings"

        nulltermonly = self.options.get("nullterminated_only", True)
        minchars = self.options.get("minchars", 5)

        if self.task["category"] in ("file", "static") and not os.path.exists(self.file_path):
            raise CuckooProcessingError(f'Sample file doesn\'t exist: "{self.file_path}"')

        return extract_strings(self.file_path, nulltermonly, minchars)
