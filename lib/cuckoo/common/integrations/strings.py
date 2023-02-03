# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os.path

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.utils import bytes2str

try:
    import re2 as re

    HAVE_RE2 = True
except ImportError:
    import re

    HAVE_RE2 = False

processing_cfg = Config("processing")
log = logging.getLogger(__name__)


def extract_strings(filepath: str, on_demand: bool = False):
    """Extract strings from analyzed file.
    @return: list of printable strings.
    """
    if not processing_cfg.strings.enabled or processing_cfg.strings.on_demand and not on_demand:
        return

    nulltermonly = processing_cfg.strings.nullterminated_only
    minchars = processing_cfg.strings.minchars

    if not os.path.exists(filepath):
        log.error("Sample file doesn't exist: %s", filepath)
        return

    strings = []

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except (IOError, OSError) as e:
        log.error("Error reading file: %s", e)
        return

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
