# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os

_current_dir = os.path.abspath(os.path.dirname(__file__))
CUCKOO_ROOT = os.path.normpath(os.path.join(_current_dir, "..", "..", ".."))

ANALYSIS_BASE_PATH = os.path.join(CUCKOO_ROOT, "storage", "analyses")

CUCKOO_VERSION = "2.2-CAPE"
CUCKOO_GUEST_PORT = 8000
CUCKOO_GUEST_INIT = 0x001
CUCKOO_GUEST_RUNNING = 0x002
CUCKOO_GUEST_COMPLETED = 0x003
CUCKOO_GUEST_FAILED = 0x004
