# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.colors import black, blue, bold, color, cyan, green, magenta, red, white, yellow  # noqa: F401


def test_return_text():
    """Test colorized text contains the input string."""
    assert "foo" in color("foo", 11)


def test_style():
    style = {"black": 30, "red": 31, "green": 32, "yellow": 33, "blue": 34, "magenta": 35, "cyan": 36, "white": 37, "bold": 1}

    for s in style:
        fn = globals()[s]
        assert fn("test") == "\x1b[%smtest\x1b[0m" % style[s]
