#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function

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

import optparse
import sys
import os
import signal
import textwrap
import re
import zipfile
import binascii

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
        print((textwrap.fill(line)))


# Convert 2 Bytes If Python 3
def C2BIP3(string):
    if sys.version_info[0] > 2:
        return bytes([ord(x) for x in string])
    else:
        return string


def File2String(filename):
    try:
        f = open(filename, "rb")
    except:
        return None
    try:
        return f.read()
    except:
        return None
    finally:
        f.close()


def File2StringHash(filename):
    decoded = None
    if filename.startswith("#h#"):
        try:
            decoded = binascii.a2b_hex(filename[3:])
        finally:
            return decoded
    elif filename.startswith("#b#"):
        try:
            decoded = binascii.a2b_base64(filename[3:])
        finally:
            return decoded
    elif filename.startswith("#"):
        return filename[1:]
    elif filename.lower().endswith(".zip"):
        oZipfile = zipfile.ZipFile(filename, "r")
        if len(oZipfile.infolist()) == 1:
            oZipContent = oZipfile.open(oZipfile.infolist()[0], "r", C2BIP3(MALWARE_PASSWORD))
            data = oZipContent.read()
            oZipContent.close()
        else:
            data = File2String(filename)
        oZipfile.close()
        return data
    else:
        return File2String(filename)


def FixPipe():
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except:
        pass


# Fix for http://bugs.python.org/issue11395
def StdoutWriteChunked(data):
    while data != "":
        sys.stdout.write(data[0:10000])
        sys.stdout.flush()
        data = data[10000:]


def Decode(data):
    dDecode = {}
    dDecode[9] = "\x57\x6E\x7B"
    dDecode[10] = "\x4A\x4C\x41"
    dDecode[11] = "\x0B\x0B\x0B"
    dDecode[12] = "\x0C\x0C\x0C"
    dDecode[13] = "\x4A\x4C\x41"
    dDecode[14] = "\x0E\x0E\x0E"
    dDecode[15] = "\x0F\x0F\x0F"
    dDecode[16] = "\x10\x10\x10"
    dDecode[17] = "\x11\x11\x11"
    dDecode[18] = "\x12\x12\x12"
    dDecode[19] = "\x13\x13\x13"
    dDecode[20] = "\x14\x14\x14"
    dDecode[21] = "\x15\x15\x15"
    dDecode[22] = "\x16\x16\x16"
    dDecode[23] = "\x17\x17\x17"
    dDecode[24] = "\x18\x18\x18"
    dDecode[25] = "\x19\x19\x19"
    dDecode[26] = "\x1A\x1A\x1A"
    dDecode[27] = "\x1B\x1B\x1B"
    dDecode[28] = "\x1C\x1C\x1C"
    dDecode[29] = "\x1D\x1D\x1D"
    dDecode[30] = "\x1E\x1E\x1E"
    dDecode[31] = "\x1F\x1F\x1F"
    dDecode[32] = "\x2E\x2D\x32"
    dDecode[33] = "\x47\x75\x30"
    dDecode[34] = "\x7A\x52\x21"
    dDecode[35] = "\x56\x60\x29"
    dDecode[36] = "\x42\x71\x5B"
    dDecode[37] = "\x6A\x5E\x38"
    dDecode[38] = "\x2F\x49\x33"
    dDecode[39] = "\x26\x5C\x3D"
    dDecode[40] = "\x49\x62\x58"
    dDecode[41] = "\x41\x7D\x3A"
    dDecode[42] = "\x34\x29\x35"
    dDecode[43] = "\x32\x36\x65"
    dDecode[44] = "\x5B\x20\x39"
    dDecode[45] = "\x76\x7C\x5C"
    dDecode[46] = "\x72\x7A\x56"
    dDecode[47] = "\x43\x7F\x73"
    dDecode[48] = "\x38\x6B\x66"
    dDecode[49] = "\x39\x63\x4E"
    dDecode[50] = "\x70\x33\x45"
    dDecode[51] = "\x45\x2B\x6B"
    dDecode[52] = "\x68\x68\x62"
    dDecode[53] = "\x71\x51\x59"
    dDecode[54] = "\x4F\x66\x78"
    dDecode[55] = "\x09\x76\x5E"
    dDecode[56] = "\x62\x31\x7D"
    dDecode[57] = "\x44\x64\x4A"
    dDecode[58] = "\x23\x54\x6D"
    dDecode[59] = "\x75\x43\x71"
    dDecode[60] = "\x4A\x4C\x41"
    dDecode[61] = "\x7E\x3A\x60"
    dDecode[62] = "\x4A\x4C\x41"
    dDecode[63] = "\x5E\x7E\x53"
    dDecode[64] = "\x40\x4C\x40"
    dDecode[65] = "\x77\x45\x42"
    dDecode[66] = "\x4A\x2C\x27"
    dDecode[67] = "\x61\x2A\x48"
    dDecode[68] = "\x5D\x74\x72"
    dDecode[69] = "\x22\x27\x75"
    dDecode[70] = "\x4B\x37\x31"
    dDecode[71] = "\x6F\x44\x37"
    dDecode[72] = "\x4E\x79\x4D"
    dDecode[73] = "\x3B\x59\x52"
    dDecode[74] = "\x4C\x2F\x22"
    dDecode[75] = "\x50\x6F\x54"
    dDecode[76] = "\x67\x26\x6A"
    dDecode[77] = "\x2A\x72\x47"
    dDecode[78] = "\x7D\x6A\x64"
    dDecode[79] = "\x74\x39\x2D"
    dDecode[80] = "\x54\x7B\x20"
    dDecode[81] = "\x2B\x3F\x7F"
    dDecode[82] = "\x2D\x38\x2E"
    dDecode[83] = "\x2C\x77\x4C"
    dDecode[84] = "\x30\x67\x5D"
    dDecode[85] = "\x6E\x53\x7E"
    dDecode[86] = "\x6B\x47\x6C"
    dDecode[87] = "\x66\x34\x6F"
    dDecode[88] = "\x35\x78\x79"
    dDecode[89] = "\x25\x5D\x74"
    dDecode[90] = "\x21\x30\x43"
    dDecode[91] = "\x64\x23\x26"
    dDecode[92] = "\x4D\x5A\x76"
    dDecode[93] = "\x52\x5B\x25"
    dDecode[94] = "\x63\x6C\x24"
    dDecode[95] = "\x3F\x48\x2B"
    dDecode[96] = "\x7B\x55\x28"
    dDecode[97] = "\x78\x70\x23"
    dDecode[98] = "\x29\x69\x41"
    dDecode[99] = "\x28\x2E\x34"
    dDecode[100] = "\x73\x4C\x09"
    dDecode[101] = "\x59\x21\x2A"
    dDecode[102] = "\x33\x24\x44"
    dDecode[103] = "\x7F\x4E\x3F"
    dDecode[104] = "\x6D\x50\x77"
    dDecode[105] = "\x55\x09\x3B"
    dDecode[106] = "\x53\x56\x55"
    dDecode[107] = "\x7C\x73\x69"
    dDecode[108] = "\x3A\x35\x61"
    dDecode[109] = "\x5F\x61\x63"
    dDecode[110] = "\x65\x4B\x50"
    dDecode[111] = "\x46\x58\x67"
    dDecode[112] = "\x58\x3B\x51"
    dDecode[113] = "\x31\x57\x49"
    dDecode[114] = "\x69\x22\x4F"
    dDecode[115] = "\x6C\x6D\x46"
    dDecode[116] = "\x5A\x4D\x68"
    dDecode[117] = "\x48\x25\x7C"
    dDecode[118] = "\x27\x28\x36"
    dDecode[119] = "\x5C\x46\x70"
    dDecode[120] = "\x3D\x4A\x6E"
    dDecode[121] = "\x24\x32\x7A"
    dDecode[122] = "\x79\x41\x2F"
    dDecode[123] = "\x37\x3D\x5F"
    dDecode[124] = "\x60\x5F\x4B"
    dDecode[125] = "\x51\x4F\x5A"
    dDecode[126] = "\x20\x42\x2C"
    dDecode[127] = "\x36\x65\x57"

    dCombination = {}
    dCombination[0] = 0
    dCombination[1] = 1
    dCombination[2] = 2
    dCombination[3] = 0
    dCombination[4] = 1
    dCombination[5] = 2
    dCombination[6] = 1
    dCombination[7] = 2
    dCombination[8] = 2
    dCombination[9] = 1
    dCombination[10] = 2
    dCombination[11] = 1
    dCombination[12] = 0
    dCombination[13] = 2
    dCombination[14] = 1
    dCombination[15] = 2
    dCombination[16] = 0
    dCombination[17] = 2
    dCombination[18] = 1
    dCombination[19] = 2
    dCombination[20] = 0
    dCombination[21] = 0
    dCombination[22] = 1
    dCombination[23] = 2
    dCombination[24] = 2
    dCombination[25] = 1
    dCombination[26] = 0
    dCombination[27] = 2
    dCombination[28] = 1
    dCombination[29] = 2
    dCombination[30] = 2
    dCombination[31] = 1
    dCombination[32] = 0
    dCombination[33] = 0
    dCombination[34] = 2
    dCombination[35] = 1
    dCombination[36] = 2
    dCombination[37] = 1
    dCombination[38] = 2
    dCombination[39] = 0
    dCombination[40] = 2
    dCombination[41] = 0
    dCombination[42] = 0
    dCombination[43] = 1
    dCombination[44] = 2
    dCombination[45] = 0
    dCombination[46] = 2
    dCombination[47] = 1
    dCombination[48] = 0
    dCombination[49] = 2
    dCombination[50] = 1
    dCombination[51] = 2
    dCombination[52] = 0
    dCombination[53] = 0
    dCombination[54] = 1
    dCombination[55] = 2
    dCombination[56] = 2
    dCombination[57] = 0
    dCombination[58] = 0
    dCombination[59] = 1
    dCombination[60] = 2
    dCombination[61] = 0
    dCombination[62] = 2
    dCombination[63] = 1

    result = ""
    index = -1
    for char in data.replace("@&", chr(10)).replace("@#", chr(13)).replace("@*", ">").replace("@!", "<").replace("@$", "@"):
        byte = ord(char)
        if byte < 128:
            index = index + 1
        if (byte == 9 or byte > 31 and byte < 128) and byte != 60 and byte != 62 and byte != 64:
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
    if oMatch == None:
        print("No encoded script found!")
    else:
        data = Decode(oMatch.groups()[0])
    return data


def Main():
    oParser = optparse.OptionParser(usage="usage: %prog [options] [file]\n" + __description__, version="%prog " + __version__)
    oParser.add_option("-m", "--man", action="store_true", default=False, help="Print manual")
    (options, args) = oParser.parse_args()

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
        data = DecodeVBEJSE(open(args[0], "rb").read(), options)
    if data:
        StdoutWriteChunked(data)


if __name__ == "__main__":
    Main()
