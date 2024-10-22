#!/usr/bin/env python3
#
# dotnet_constants.py
#
# Author: jeFF0Falltrades
#
# Useful .NET constants and enums
#
# MIT License
#
# Copyright (c) 2024 Jeff Archer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from enum import IntEnum
from re import DOTALL, compile

# Notable CIL Opcodes and Tokens
OPCODE_LDC_I4_0 = b"\x16"
OPCODE_LDSTR = b"\x72"
OPCODE_LDTOKEN = b"\xd0"
MDT_FIELD_DEF = 0x04000000
MDT_METHOD_DEF = 0x06000000
MDT_STRING = 0x70000000
PATTERN_LDSTR_OP = compile(
    rb"\x72(.{3}\x70)",
    flags=DOTALL,
)


# IntEnum derivative used for translating a SpecialFolder ID to its name
class SpecialFolder(IntEnum):
    ADMINTOOLS = 48
    APPLICATIONDATA = 26
    CDBURNING = 59
    COMMONADMINTOOLS = 47
    COMMONAPPLICATIONDATA = 35
    COMMONDESKTOPDIRECTORY = 25
    COMMONDOCUMENTS = 46
    COMMONMUSIC = 53
    COMMONOEMLINKS = 58
    COMMONPICTURES = 54
    COMMONPROGRAMFILES = 43
    COMMONPROGRAMFILESX86 = 44
    COMMONPROGRAMS = 23
    COMMONSTARTMENU = 22
    COMMONSTARTUP = 24
    COMMONTEMPLATES = 45
    COMMONVIDEOS = 55
    COOKIES = 33
    DESKTOPDIRECTORY = 16
    FONTS = 20
    HISTORY = 34
    INTERNETCACHE = 32
    LOCALAPPLICATIONDATA = 28
    LOCALIZEDRESOURCES = 57
    MYCOMPUTER = 17
    MYMUSIC = 13
    MYPICTURES = 39
    MYVIDEOS = 14
    NETWORKSHORTCUTS = 19
    PRINTERSHORTCUTS = 27
    PROGRAMFILES = 38
    PROGRAMFILESX86 = 42
    RESOURCES = 56
    STARTMENU = 11
    SYSTEM = 37
    SYSTEMX86 = 41
    TEMPLATES = 21
    USERPROFILE = 40
    WINDOWS = 36
