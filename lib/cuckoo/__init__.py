# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import re
import sys

_FALLBACK_MIN_PYTHON = (3, 14)
_PYPROJECT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "pyproject.toml")
_MIN_PYTHON_RE = re.compile(r'^\s*requires-python\s*=\s*["\'][^"\']*?>=\s*(\d+)\.(\d+)', re.MULTILINE)
_OVERRIDE_RE = re.compile(r"^(\d+)\.(\d+)(?:\.\d+)?$")


def get_min_python_version(pyproject_path=None):
    """Return the minimum supported host (major, minor) Python version.

    Precedence:
    1. ``CAPE_MIN_PYTHON`` environment variable (e.g. ``3.14``).
    2. ``requires-python`` lower bound in ``pyproject.toml``.
    3. ``_FALLBACK_MIN_PYTHON`` when ``pyproject.toml`` is absent or unparseable.
    """
    override = os.getenv("CAPE_MIN_PYTHON", "").strip()
    if override:
        match = _OVERRIDE_RE.match(override)
        if match:
            return (int(match.group(1)), int(match.group(2)))

    path = pyproject_path or _PYPROJECT_PATH
    try:
        with open(path, "r", encoding="utf-8") as f:
            match = _MIN_PYTHON_RE.search(f.read())
            if match:
                return (int(match.group(1)), int(match.group(2)))
    except OSError:
        pass
    return _FALLBACK_MIN_PYTHON


def check_python_version(pyproject_path=None):
    """Exit if the running Python interpreter is older than the minimum version.

    Set ``CAPE_SKIP_PYTHON_VERSION_CHECK=1`` to bypass.
    """
    if os.getenv("CAPE_SKIP_PYTHON_VERSION_CHECK", "0") == "1":
        return
    min_version = get_min_python_version(pyproject_path=pyproject_path)
    if sys.version_info[:2] < min_version:
        sys.exit("You are running an incompatible version of Python, please use >= %d.%d" % min_version)


check_python_version()
