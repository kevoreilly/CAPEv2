#!/usr/bin/env python

from __future__ import absolute_import, print_function

__description__ = "Decode VBE script"
__author__ = "Didier Stevens"
__version__ = "0.0.2"
__date__ = "2016/03/29"

"""

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2016/03/28: start
  2016/03/29: 0.0.2 added support for ZIP files and literal arguments with File2StringHash

Todo:

Reference:
  https://gallery.technet.microsoft.com/Encode-and-Decode-a-VB-a480d74c
"""

import binascii
import optparse
import re
import signal
import sys
import textwrap
import zipfile
# import os

MALWARE_PASSWORD = "infected"


def PrintManual():
    manual = """
Manual:

This program reads from the given file or standard input, and converts the encoded VBE script to VBS.

The provided file can be a password protected ZIP file (with password infected) containing the VBE script.

The content of the VBE script can also be passed as a literal argument. This is similar to a Here Document in Unix.
Start the argument (the "filename") with character # to pass a literal argument.
Example: decode-vbe.py "##@~^DgAAAA==\ko$K6,JCV^GJqAQAAA==^#~@"
Result: MsgBox "Hello"

It's also possible to use hexadecimal (prefix #h#) or base64 (prefix #b#) to pass a literal argument.
Example: decode-vbe.py #h#23407E5E4467414141413D3D5C6B6F244B362C4A437F565E474A7141514141413D3D5E237E40
Result: MsgBox "Hello"
Example: decode-vbe.py #b#I0B+XkRnQUFBQT09XGtvJEs2LEpDf1ZeR0pxQVFBQUE9PV4jfkA=
Result: MsgBox "Hello"

"""
    for line in manual.split("\n"):
        print(textwrap.fill(line))


# Convert 2 Bytes
def C2BIP3(string):
    return bytes([ord(x) for x in string])


def File2String(filename):
    try:
        with open(filename, "rb") as f:
            return f.read()
    except Exception:
        return None


def File2StringHash(filename):
    if filename.startswith("#h#"):
        return binascii.a2b_hex(filename[3:])
    elif filename.startswith("#b#"):
        return binascii.a2b_base64(filename[3:])
    elif filename.startswith("#"):
        return filename[1:]
    elif filename.lower().endswith(".zip"):
        with zipfile.ZipFile(filename, "r") as oZipfile:
            if len(oZipfile.infolist()) == 1:
                with oZipfile.open(oZipfile.infolist()[0], "r", C2BIP3(MALWARE_PASSWORD)) as oZipContent:
                    data = oZipContent.read()
            else:
                data = File2String(filename)
        return data
    else:
        return File2String(filename)


def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass


# Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != "":
        sys.stdout.write(data[0:10000])
        sys.stdout.flush()
        data = data[10000:]


def Decode(data):
    dDecode = {
        9: "\x57\x6E\x7B",
        10: "\x4A\x4C\x41",
        11: "\x0B\x0B\x0B",
        12: "\x0C\x0C\x0C",
        13: "\x4A\x4C\x41",
        14: "\x0E\x0E\x0E",
        15: "\x0F\x0F\x0F",
        16: "\x10\x10\x10",
        17: "\x11\x11\x11",
        18: "\x12\x12\x12",
        19: "\x13\x13\x13",
        20: "\x14\x14\x14",
        21: "\x15\x15\x15",
        22: "\x16\x16\x16",
        23: "\x17\x17\x17",
        24: "\x18\x18\x18",
        25: "\x19\x19\x19",
        26: "\x1A\x1A\x1A",
        27: "\x1B\x1B\x1B",
        28: "\x1C\x1C\x1C",
        29: "\x1D\x1D\x1D",
        30: "\x1E\x1E\x1E",
        31: "\x1F\x1F\x1F",
        32: "\x2E\x2D\x32",
        33: "\x47\x75\x30",
        34: "\x7A\x52\x21",
        35: "\x56\x60\x29",
        36: "\x42\x71\x5B",
        37: "\x6A\x5E\x38",
        38: "\x2F\x49\x33",
        39: "\x26\x5C\x3D",
        40: "\x49\x62\x58",
        41: "\x41\x7D\x3A",
        42: "\x34\x29\x35",
        43: "\x32\x36\x65",
        44: "\x5B\x20\x39",
        45: "\x76\x7C\x5C",
        46: "\x72\x7A\x56",
        47: "\x43\x7F\x73",
        48: "\x38\x6B\x66",
        49: "\x39\x63\x4E",
        50: "\x70\x33\x45",
        51: "\x45\x2B\x6B",
        52: "\x68\x68\x62",
        53: "\x71\x51\x59",
        54: "\x4F\x66\x78",
        55: "\x09\x76\x5E",
        56: "\x62\x31\x7D",
        57: "\x44\x64\x4A",
        58: "\x23\x54\x6D",
        59: "\x75\x43\x71",
        60: "\x4A\x4C\x41",
        61: "\x7E\x3A\x60",
        62: "\x4A\x4C\x41",
        63: "\x5E\x7E\x53",
        64: "\x40\x4C\x40",
        65: "\x77\x45\x42",
        66: "\x4A\x2C\x27",
        67: "\x61\x2A\x48",
        68: "\x5D\x74\x72",
        69: "\x22\x27\x75",
        70: "\x4B\x37\x31",
        71: "\x6F\x44\x37",
        72: "\x4E\x79\x4D",
        73: "\x3B\x59\x52",
        74: "\x4C\x2F\x22",
        75: "\x50\x6F\x54",
        76: "\x67\x26\x6A",
        77: "\x2A\x72\x47",
        78: "\x7D\x6A\x64",
        79: "\x74\x39\x2D",
        80: "\x54\x7B\x20",
        81: "\x2B\x3F\x7F",
        82: "\x2D\x38\x2E",
        83: "\x2C\x77\x4C",
        84: "\x30\x67\x5D",
        85: "\x6E\x53\x7E",
        86: "\x6B\x47\x6C",
        87: "\x66\x34\x6F",
        88: "\x35\x78\x79",
        89: "\x25\x5D\x74",
        90: "\x21\x30\x43",
        91: "\x64\x23\x26",
        92: "\x4D\x5A\x76",
        93: "\x52\x5B\x25",
        94: "\x63\x6C\x24",
        95: "\x3F\x48\x2B",
        96: "\x7B\x55\x28",
        97: "\x78\x70\x23",
        98: "\x29\x69\x41",
        99: "\x28\x2E\x34",
        100: "\x73\x4C\x09",
        101: "\x59\x21\x2A",
        102: "\x33\x24\x44",
        103: "\x7F\x4E\x3F",
        104: "\x6D\x50\x77",
        105: "\x55\x09\x3B",
        106: "\x53\x56\x55",
        107: "\x7C\x73\x69",
        108: "\x3A\x35\x61",
        109: "\x5F\x61\x63",
        110: "\x65\x4B\x50",
        111: "\x46\x58\x67",
        112: "\x58\x3B\x51",
        113: "\x31\x57\x49",
        114: "\x69\x22\x4F",
        115: "\x6C\x6D\x46",
        116: "\x5A\x4D\x68",
        117: "\x48\x25\x7C",
        118: "\x27\x28\x36",
        119: "\x5C\x46\x70",
        120: "\x3D\x4A\x6E",
        121: "\x24\x32\x7A",
        122: "\x79\x41\x2F",
        123: "\x37\x3D\x5F",
        124: "\x60\x5F\x4B",
        125: "\x51\x4F\x5A",
        126: "\x20\x42\x2C",
        127: "\x36\x65\x57"
    }

    dCombination = {
        0: 0,
        1: 1,
        2: 2,
        3: 0,
        4: 1,
        5: 2,
        6: 1,
        7: 2,
        8: 2,
        9: 1,
        10: 2,
        11: 1,
        12: 0,
        13: 2,
        14: 1,
        15: 2,
        16: 0,
        17: 2,
        18: 1,
        19: 2,
        20: 0,
        21: 0,
        22: 1,
        23: 2,
        24: 2,
        25: 1,
        26: 0,
        27: 2,
        28: 1,
        29: 2,
        30: 2,
        31: 1,
        32: 0,
        33: 0,
        34: 2,
        35: 1,
        36: 2,
        37: 1,
        38: 2,
        39: 0,
        40: 2,
        41: 0,
        42: 0,
        43: 1,
        44: 2,
        45: 0,
        46: 2,
        47: 1,
        48: 0,
        49: 2,
        50: 1,
        51: 2,
        52: 0,
        53: 0,
        54: 1,
        55: 2,
        56: 2,
        57: 0,
        58: 0,
        59: 1,
        60: 2,
        61: 0,
        62: 2,
        63: 1
    }

    result = ""
    index = -1
    for char in data.replace("@&", "\n").replace("@#", "\r").replace("@*", ">").replace("@!", "<").replace("@$", "@"):
        byte = ord(char)
        if byte < 128:
            index += 1
        if (byte == 9 or 31 < byte < 128) and byte not in (60, 62, 64):
            char = [c for c in dDecode[byte]][dCombination[index % 64]]
        result += char

    return result


def DecodeVBEJSE(content, options):
    data = False
    """
    FixPipe()
    if sys.platform == 'win32':
        import msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
    if filename == '':
        content = sys.stdin.read()
    else:
        content = File2StringHash(filename)
    print(content[:20])
    """
    oMatch = re.search(r"#@~\^......==(.+)......==\^#~@", content)
    if oMatch is None:
        print("No encoded script found!")
    else:
        data = Decode(oMatch.groups()[0])
    return data


def Main():
    oParser = optparse.OptionParser(usage=f"usage: %prog [options] [file]\n{__description__}", version=f"%prog {__version__}")
    oParser.add_option("-m", "--man", action="store_true", default=False, help="Print manual")
    options, args = oParser.parse_args()

    if options.man:
        oParser.print_help()
        PrintManual()
        return

    if len(args) > 1:
        oParser.print_help()
        print("")
        print("  Source code put in the public domain by Didier Stevens, no Copyright")
        print("  Use at your own risk")
        print("  https://DidierStevens.com")
        return
    elif len(args) == 0:
        data = DecodeVBEJSE("", options)
    else:
        with open(args[0], "rb") as file:
            data = DecodeVBEJSE(file.read(), options)
    if data:
        StdoutWriteChunked(data)


if __name__ == "__main__":
    Main()
