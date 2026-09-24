# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import tempfile

from lib.common.rand import random_string

# Stock Android has no writable /tmp; unlike upstream platforms we can't rely
# on tempfile.gettempdir()'s default resolution alone, so fall back explicitly
# to /data/local/tmp (the standard shell-writable location) when none of
# TMPDIR/TEMP/TMP are already set in the environment.
if not any(os.environ.get(var) for var in ("TMPDIR", "TEMP", "TMP")):
    os.environ["TMPDIR"] = "/data/local/tmp"

ROOT = os.path.join(tempfile.gettempdir(), random_string(6, 10))

PATHS = {
    "root": ROOT,
    "logs": os.path.join(ROOT, "logs"),
    "files": os.path.join(ROOT, "files"),
    "shots": os.path.join(ROOT, "shots"),
    "memory": os.path.join(ROOT, "memory"),
    "drop": os.path.join(ROOT, "drop"),
}

OPT_CURDIR = "curdir"
