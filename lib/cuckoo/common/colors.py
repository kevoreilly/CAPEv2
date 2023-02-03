# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import sys


def color(text: str, color_code: int) -> str:
    """Colorize text.
    @param text: text.
    @param color_code: color.
    @return: colorized text.
    """
    # $TERM under Windows:
    # cmd.exe -> "" (what would you expect..?)
    # cygwin -> "cygwin" (should support colors, but doesn't work somehow)
    # mintty -> "xterm" (supports colors)
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text
    return "\x1b[{}m{}\x1b[0m".format(color_code, text)


def black(text: str) -> str:
    return color(text, 30)


def red(text: str) -> str:
    return color(text, 31)


def green(text: str) -> str:
    return color(text, 32)


def yellow(text: str) -> str:
    return color(text, 33)


def blue(text: str) -> str:
    return color(text, 34)


def magenta(text: str) -> str:
    return color(text, 35)


def cyan(text: str) -> str:
    return color(text, 36)


def white(text: str) -> str:
    return color(text, 37)


def bold(text: str) -> str:
    return color(text, 1)
