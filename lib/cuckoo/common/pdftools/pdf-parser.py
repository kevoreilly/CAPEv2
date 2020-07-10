#!/usr/bin/python
from __future__ import absolute_import
from __future__ import print_function

__description__ = "pdf-parser, use it to parse a PDF document"
__author__ = "Didier Stevens"
__version__ = "0.7.4"
__date__ = "2019/11/05"
__minimum_python_version__ = (2, 5, 1)
__maximum_python_version__ = (3, 7, 5)

"""
Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2008/05/02: continue
  2008/05/03: continue
  2008/06/02: streams
  2008/10/19: refactor, grep & extract functionality
  2008/10/20: reference
  2008/10/21: cleanup
  2008/11/12: V0.3 dictionary parser
  2008/11/13: option elements
  2008/11/14: continue
  2009/05/05: added /ASCIIHexDecode support (thanks Justin Prosco)
  2009/05/11: V0.3.1 updated usage, added --verbose and --extract
  2009/07/16: V0.3.2 Added Canonicalize (thanks Justin Prosco)
  2009/07/18: bugfix EqualCanonical
  2009/07/24: V0.3.3 Added --hash option
  2009/07/25: EqualCanonical for option --type, added option --nocanonicalizedoutput
  2009/07/28: V0.3.4 Added ASCII85Decode support
  2009/08/01: V0.3.5 Updated ASCIIHexDecode to support whitespace obfuscation
  2009/08/30: V0.3.6 TestPythonVersion
  2010/01/08: V0.3.7 Added RLE and LZW support (thanks pARODY); added dump option
  2010/01/09: Fixed parsing of incomplete startxref
  2010/09/22: V0.3.8 Changed dump option, updated PrettyPrint, added debug option
  2011/12/17: fixed bugs empty objects
  2012/03/11: V0.3.9 fixed bugs double nested [] in PrettyPrintSub (thanks kurt)
  2013/01/11: V0.3.10 Extract and dump bug fixes by Priit; added content option
  2013/02/16: Performance improvement in cPDFTokenizer by using StringIO for token building by Christophe Vandeplas; xrange replaced with range
  2013/02/16: V0.4.0 added http/https support; added error handling for missing file or URL; ; added support for ZIP file with password 'infected'
  2013/03/13: V0.4.1 fixes for Python 3
  2013/04/11: V0.4.2 modified PrettyPrintSub for strings with unprintable characters
  2013/05/04: Added options searchstream, unfiltered, casesensitive, regex
  2013/09/18: V0.4.3 fixed regression bug -w option
  2014/09/25: V0.5.0 added option -g
  2014/09/29: Added PrintGenerateObject and PrintOutputObject
  2014/12/05: V0.6.0 Added YARA support
  2014/12/09: cleanup, refactoring
  2014/12/13: Python 3 fixes
  2015/01/11: Added support for multiple YARA rule files; added request to search in trailer
  2015/01/31: V0.6.1 Added optionyarastrings
  2015/02/09: Added decoders
  2015/04/05: V0.6.2 Added generateembedded
  2015/04/06: fixed bug reported by Kurt for stream produced by Ghostscript where endstream is not preceded by whitespace; fixed prettyprint bug
  2015/04/24: V0.6.3 when option dump's filename is -, content is dumped to stdout
  2015/08/12: V0.6.4 option hash now also calculates hashes of streams when selecting or searching objects; and displays hexasciidump first line
  2016/07/27: V0.6.5 bugfix whitespace 0x00 0x0C after stream 0x0D 0x0A reported by @mr_me
  2016/11/20: V0.6.6 added workaround zlib errors FlateDecode
  2016/12/17: V0.6.7 added option -k
  2017/01/07: V0.6.8 changed cPDFParseDictionary to handle strings () with % character
  2017/10/28: fixed bug
  2017/10/29: added # support for option -y
  2018/06/29: V0.6.9 added option --overridingfilters
  2018/10/20: added keywords to statistics
  2019/02/22: V0.7.0 added option -O --objstm to parse the stream of /ObjStm objects, inspired by a contributor wishing anonymity
  2019/03/01: V0.7.1 added ContainsName for correct keyword statistics (-a)
  2019/04/12: V0.7.2 Python 2.6.6 compatibility fix
  2019/07/30: bug fixes (including fixes Josef Hinteregger)
  2019/09/26: V0.7.3 added multiple id selection to option -o; added man page (-m); added environment variable PDFPARSER_OPTIONS; bug fixes
  2019/11/05: V0.7.4 fixed plugin path when compiled with pyinstaller, replaced eval with int

Todo:
  - handle printf todo
  - support for JS hex string EC61C64349DB8D88AF0523C4C06E0F4D.pdf.vir

"""

import re
import optparse
import zlib
import binascii
import hashlib
import sys
import zipfile
import time
import os
import textwrap

if sys.version_info[0] >= 3:
    from io import StringIO
    import urllib.request

    urllib23 = urllib.request
    import configparser as ConfigParser
else:
    from cStringIO import StringIO
    import urllib2

    urllib23 = urllib2
    import ConfigParser
try:
    import yara
except:
    pass

CHAR_WHITESPACE = 1
CHAR_DELIMITER = 2
CHAR_REGULAR = 3

CONTEXT_NONE = 1
CONTEXT_OBJ = 2
CONTEXT_XREF = 3
CONTEXT_TRAILER = 4

PDF_ELEMENT_COMMENT = 1
PDF_ELEMENT_INDIRECT_OBJECT = 2
PDF_ELEMENT_XREF = 3
PDF_ELEMENT_TRAILER = 4
PDF_ELEMENT_STARTXREF = 5
PDF_ELEMENT_MALFORMED = 6

dumplinelength = 16


def PrintManual():
    manual = """
Manual:

This manual is a work in progress.

There is a free PDF analysis book:
https://blog.didierstevens.com/2010/09/26/free-malicious-pdf-analysis-e-book/

Option -o is used to select objects by id. Provide a single id or multiple ids separated by a comma (,).

When environment variable PDFPARSER_OPTIONS is defined, the options it defines are added implicitely to the command line arguments.
Use this to define options you want included with each use of pdf-parser.py.
Like option -O, to parse stream objects (/ObjStm).
By defining PDFPARSER_OPTIONS=-O, pdf-parser will always parse stream objects (when found).
PS: this feature is experimental.

"""
    for line in manual.split("\n"):
        print(textwrap.fill(line))


# Convert 2 Bytes If Python 3


def C2BIP3(string):
    if sys.version_info[0] > 2:
        if type(string) == bytes:
            return string
        else:
            return bytes([ord(x) for x in string])
    else:
        return string


# Convert 2 String If Python 3


def C2SIP3(bytes):
    if sys.version_info[0] > 2:
        return "".join([chr(byte) for byte in bytes])
    else:
        return bytes


# CIC: Call If Callable


def CIC(expression):
    if callable(expression):
        return expression()
    else:
        return expression


# IFF: IF Function


def IFF(expression, valueTrue, valueFalse):
    if expression:
        return CIC(valueTrue)
    else:
        return CIC(valueFalse)


def Timestamp(epoch=None):
    if epoch == None:
        localTime = time.localtime()
    else:
        localTime = time.localtime(epoch)
    return "%04d%02d%02d-%02d%02d%02d" % localTime[0:6]


def CopyWithoutWhiteSpace(content):
    result = []
    for token in content:
        if token[0] != CHAR_WHITESPACE:
            result.append(token)
    return result


def Obj2Str(content):
    return "".join(map(lambda x: repr(x[1])[1:-1], CopyWithoutWhiteSpace(content)))


class cPDFDocument:
    def __init__(self, file):
        self.file = file
        if type(file) != str:
            self.infile = file
        elif file.lower().startswith(("http://", "https://")):
            try:
                if sys.hexversion >= 0x020601F0:
                    self.infile = urllib23.urlopen(file, timeout=5)
                else:
                    self.infile = urllib23.urlopen(file)
            except urllib23.HTTPError:
                print("Error accessing URL %s" % file)
                print(sys.exc_info()[1])
                sys.exit()
        elif file.lower().endswith(".zip"):
            try:
                self.zipfile = zipfile.ZipFile(file, "r")
                self.infile = self.zipfile.open(self.zipfile.infolist()[0], "r", C2BIP3("infected"))
            except:
                print("Error opening file %s" % file)
                print(sys.exc_info()[1])
                sys.exit()
        else:
            try:
                self.infile = open(file, "rb")
            except:
                print("Error opening file %s" % file)
                print(sys.exc_info()[1])
                sys.exit()
        self.ungetted = []
        self.position = -1

    def byte(self):
        if len(self.ungetted) != 0:
            self.position += 1
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte or inbyte == "":
            self.infile.close()
            return None
        self.position += 1
        return ord(inbyte)

    def unget(self, byte):
        self.position -= 1
        self.ungetted.append(byte)


def CharacterClass(byte):
    if byte == 0 or byte == 9 or byte == 10 or byte == 12 or byte == 13 or byte == 32:
        return CHAR_WHITESPACE
    if (
        byte == 0x28
        or byte == 0x29
        or byte == 0x3C
        or byte == 0x3E
        or byte == 0x5B
        or byte == 0x5D
        or byte == 0x7B
        or byte == 0x7D
        or byte == 0x2F
        or byte == 0x25
    ):
        return CHAR_DELIMITER
    return CHAR_REGULAR


def IsNumeric(str):
    return re.match("^[0-9]+", str)


class cPDFTokenizer:
    def __init__(self, file):
        self.oPDF = cPDFDocument(file)
        self.ungetted = []

    def Token(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        if self.oPDF == None:
            return None
        self.byte = self.oPDF.byte()
        if self.byte == None:
            self.oPDF = None
            return None
        elif CharacterClass(self.byte) == CHAR_WHITESPACE:
            file_str = StringIO()
            while self.byte != None and CharacterClass(self.byte) == CHAR_WHITESPACE:
                file_str.write(chr(self.byte))
                self.byte = self.oPDF.byte()
            if self.byte != None:
                self.oPDF.unget(self.byte)
            else:
                self.oPDF = None
            self.token = file_str.getvalue()
            return (CHAR_WHITESPACE, self.token)
        elif CharacterClass(self.byte) == CHAR_REGULAR:
            file_str = StringIO()
            while self.byte != None and CharacterClass(self.byte) == CHAR_REGULAR:
                file_str.write(chr(self.byte))
                self.byte = self.oPDF.byte()
            if self.byte != None:
                self.oPDF.unget(self.byte)
            else:
                self.oPDF = None
            self.token = file_str.getvalue()
            return (CHAR_REGULAR, self.token)
        else:
            if self.byte == 0x3C:
                self.byte = self.oPDF.byte()
                if self.byte == 0x3C:
                    return (CHAR_DELIMITER, "<<")
                else:
                    self.oPDF.unget(self.byte)
                    return (CHAR_DELIMITER, "<")
            elif self.byte == 0x3E:
                self.byte = self.oPDF.byte()
                if self.byte == 0x3E:
                    return (CHAR_DELIMITER, ">>")
                else:
                    self.oPDF.unget(self.byte)
                    return (CHAR_DELIMITER, ">")
            elif self.byte == 0x25:
                file_str = StringIO()
                while self.byte != None:
                    file_str.write(chr(self.byte))
                    if self.byte == 10 or self.byte == 13:
                        self.byte = self.oPDF.byte()
                        break
                    self.byte = self.oPDF.byte()
                if self.byte != None:
                    if self.byte == 10:
                        file_str.write(chr(self.byte))
                    else:
                        self.oPDF.unget(self.byte)
                else:
                    self.oPDF = None
                self.token = file_str.getvalue()
                return (CHAR_DELIMITER, self.token)
            return (CHAR_DELIMITER, chr(self.byte))

    def TokenIgnoreWhiteSpace(self):
        token = self.Token()
        while token != None and token[0] == CHAR_WHITESPACE:
            token = self.Token()
        return token

    def Tokens(self):
        tokens = []
        token = self.Token()
        while token != None:
            tokens.append(token)
            token = self.Token()
        return tokens

    def unget(self, byte):
        self.ungetted.append(byte)


class cPDFParser:
    def __init__(self, file, verbose=False, extract=None, objstm=None):
        self.context = CONTEXT_NONE
        self.content = []
        self.oPDFTokenizer = cPDFTokenizer(file)
        self.verbose = verbose
        self.extract = extract
        self.objstm = objstm

    def GetObject(self):
        while True:
            if self.context == CONTEXT_OBJ:
                self.token = self.oPDFTokenizer.Token()
            else:
                self.token = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
            if self.token:
                if self.token[0] == CHAR_DELIMITER:
                    if self.token[1][0] == "%":
                        if self.context == CONTEXT_OBJ:
                            self.content.append(self.token)
                        else:
                            return cPDFElementComment(self.token[1])
                    elif self.token[1] == "/":
                        self.token2 = self.oPDFTokenizer.Token()
                        if self.token2[0] == CHAR_REGULAR:
                            if self.context != CONTEXT_NONE:
                                self.content.append((CHAR_DELIMITER, self.token[1] + self.token2[1]))
                            elif self.verbose:
                                print("todo 1: %s" % (self.token[1] + self.token2[1]))
                        else:
                            self.oPDFTokenizer.unget(self.token2)
                            if self.context != CONTEXT_NONE:
                                self.content.append(self.token)
                            elif self.verbose:
                                print("todo 2: %d %s" % (self.token[0], repr(self.token[1])))
                    elif self.context != CONTEXT_NONE:
                        self.content.append(self.token)
                    elif self.verbose:
                        print("todo 3: %d %s" % (self.token[0], repr(self.token[1])))
                elif self.token[0] == CHAR_WHITESPACE:
                    if self.context != CONTEXT_NONE:
                        self.content.append(self.token)
                    elif self.verbose:
                        print("todo 4: %d %s" % (self.token[0], repr(self.token[1])))
                else:
                    if self.context == CONTEXT_OBJ:
                        if self.token[1] == "endobj":
                            self.oPDFElementIndirectObject = cPDFElementIndirectObject(
                                self.objectId, self.objectVersion, self.content, self.objstm
                            )
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementIndirectObject
                        else:
                            self.content.append(self.token)
                    elif self.context == CONTEXT_TRAILER:
                        if self.token[1] == "startxref" or self.token[1] == "xref":
                            self.oPDFElementTrailer = cPDFElementTrailer(self.content)
                            self.oPDFTokenizer.unget(self.token)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementTrailer
                        else:
                            self.content.append(self.token)
                    elif self.context == CONTEXT_XREF:
                        if self.token[1] == "trailer" or self.token[1] == "xref":
                            self.oPDFElementXref = cPDFElementXref(self.content)
                            self.oPDFTokenizer.unget(self.token)
                            self.context = CONTEXT_NONE
                            self.content = []
                            return self.oPDFElementXref
                        else:
                            self.content.append(self.token)
                    else:
                        if IsNumeric(self.token[1]):
                            self.token2 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                            if IsNumeric(self.token2[1]):
                                self.token3 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                                if self.token3[1] == "obj":
                                    self.objectId = int(self.token[1], 10)
                                    self.objectVersion = int(self.token2[1], 10)
                                    self.context = CONTEXT_OBJ
                                else:
                                    self.oPDFTokenizer.unget(self.token3)
                                    self.oPDFTokenizer.unget(self.token2)
                                    if self.verbose:
                                        print("todo 6: %d %s" % (self.token[0], repr(self.token[1])))
                            else:
                                self.oPDFTokenizer.unget(self.token2)
                                if self.verbose:
                                    print("todo 7: %d %s" % (self.token[0], repr(self.token[1])))
                        elif self.token[1] == "trailer":
                            self.context = CONTEXT_TRAILER
                            self.content = [self.token]
                        elif self.token[1] == "xref":
                            self.context = CONTEXT_XREF
                            self.content = [self.token]
                        elif self.token[1] == "startxref":
                            self.token2 = self.oPDFTokenizer.TokenIgnoreWhiteSpace()
                            if self.token2 and IsNumeric(self.token2[1]):
                                return cPDFElementStartxref(int(self.token2[1], 10))
                            else:
                                self.oPDFTokenizer.unget(self.token2)
                                if self.verbose:
                                    print("todo 9: %d %s" % (self.token[0], repr(self.token[1])))
                        elif self.extract:
                            self.bytes = ""
                            while self.token:
                                self.bytes += self.token[1]
                                self.token = self.oPDFTokenizer.Token()
                            return cPDFElementMalformed(self.bytes)
                        elif self.verbose:
                            print("todo 10: %d %s" % (self.token[0], repr(self.token[1])))
            else:
                break


class cPDFElementComment:
    def __init__(self, comment):
        self.type = PDF_ELEMENT_COMMENT
        self.comment = comment


#                        if re.match('^%PDF-[0-9]\.[0-9]', self.token[1]):
#                            print(repr(self.token[1]))
#                        elif re.match('^%%EOF', self.token[1]):
#                            print(repr(self.token[1]))


class cPDFElementXref:
    def __init__(self, content):
        self.type = PDF_ELEMENT_XREF
        self.content = content


class cPDFElementTrailer:
    def __init__(self, content):
        self.type = PDF_ELEMENT_TRAILER
        self.content = content

    def Contains(self, keyword):
        data = ""
        for i in range(0, len(self.content)):
            if self.content[i][1] == "stream":
                break
            else:
                data += Canonicalize(self.content[i][1])
        return data.upper().find(keyword.upper()) != -1


def IIf(expr, truepart, falsepart):
    if expr:
        return truepart
    else:
        return falsepart


class cPDFElementIndirectObject:
    def __init__(self, id, version, content, objstm=None):
        self.type = PDF_ELEMENT_INDIRECT_OBJECT
        self.id = id
        self.version = version
        self.content = content
        self.objstm = objstm
        # fix stream for Ghostscript bug reported by Kurt
        if self.ContainsStream():
            position = len(self.content) - 1
            if position < 0:
                return
            while self.content[position][0] == CHAR_WHITESPACE and position >= 0:
                position -= 1
            if position < 0:
                return
            if self.content[position][0] != CHAR_REGULAR:
                return
            if self.content[position][1] == "endstream":
                return
            if not self.content[position][1].endswith("endstream"):
                return
            self.content = (
                self.content[0:position]
                + [(self.content[position][0], self.content[position][1][: -len("endstream")])]
                + [(self.content[position][0], "endstream")]
                + self.content[position + 1 :]
            )

    def GetType(self):
        content = CopyWithoutWhiteSpace(self.content)
        dictionary = 0
        for i in range(0, len(content)):
            if content[i][0] == CHAR_DELIMITER and content[i][1] == "<<":
                dictionary += 1
            if content[i][0] == CHAR_DELIMITER and content[i][1] == ">>":
                dictionary -= 1
            if dictionary == 1 and content[i][0] == CHAR_DELIMITER and EqualCanonical(content[i][1], "/Type") and i < len(content) - 1:
                return content[i + 1][1]
        return ""

    def GetReferences(self):
        content = CopyWithoutWhiteSpace(self.content)
        references = []
        for i in range(0, len(content)):
            if (
                i > 1
                and content[i][0] == CHAR_REGULAR
                and content[i][1] == "R"
                and content[i - 2][0] == CHAR_REGULAR
                and IsNumeric(content[i - 2][1])
                and content[i - 1][0] == CHAR_REGULAR
                and IsNumeric(content[i - 1][1])
            ):
                references.append((content[i - 2][1], content[i - 1][1], content[i][1]))
        return references

    def References(self, index):
        for ref in self.GetReferences():
            if ref[0] == index:
                return True
        return False

    def ContainsStream(self):
        for i in range(0, len(self.content)):
            if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == "stream":
                return self.content[0:i]
        return False

    def Contains(self, keyword):
        data = ""
        for i in range(0, len(self.content)):
            if self.content[i][1] == "stream":
                break
            else:
                data += Canonicalize(self.content[i][1])
        return data.upper().find(keyword.upper()) != -1

    def ContainsName(self, keyword):
        for token in self.content:
            if token[1] == "stream":
                return False
            if token[0] == CHAR_DELIMITER and EqualCanonical(token[1], keyword):
                return True
        return False

    def StreamContains(self, keyword, filter, casesensitive, regex, overridingfilters):
        if not self.ContainsStream():
            return False
        streamData = self.Stream(filter, overridingfilters)
        if filter and streamData == "No filters":
            streamData = self.Stream(False, overridingfilters)
        if regex:
            return re.search(keyword, streamData, IIf(casesensitive, 0, re.I))
        elif casesensitive:
            return keyword in streamData
        else:
            return keyword.lower() in streamData.lower()

    def Stream(self, filter=True, overridingfilters=""):
        state = "start"
        countDirectories = 0
        data = ""
        filters = []
        for i in range(0, len(self.content)):
            if state == "start":
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == "<<":
                    countDirectories += 1
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == ">>":
                    countDirectories -= 1
                if countDirectories == 1 and self.content[i][0] == CHAR_DELIMITER and EqualCanonical(self.content[i][1], "/Filter"):
                    state = "filter"
                elif countDirectories == 0 and self.content[i][0] == CHAR_REGULAR and self.content[i][1] == "stream":
                    state = "stream-whitespace"
            elif state == "filter":
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1][0] == "/":
                    filters = [self.content[i][1]]
                    state = "search-stream"
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == "[":
                    state = "filter-list"
            elif state == "filter-list":
                if self.content[i][0] == CHAR_DELIMITER and self.content[i][1][0] == "/":
                    filters.append(self.content[i][1])
                elif self.content[i][0] == CHAR_DELIMITER and self.content[i][1] == "]":
                    state = "search-stream"
            elif state == "search-stream":
                if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == "stream":
                    state = "stream-whitespace"
            elif state == "stream-whitespace":
                if self.content[i][0] == CHAR_WHITESPACE:
                    whitespace = self.content[i][1]
                    if whitespace.startswith("\x0D\x0A") and len(whitespace) > 2:
                        data += whitespace[2:]
                    elif whitespace.startswith("\x0A") and len(whitespace) > 1:
                        data += whitespace[1:]
                else:
                    data += self.content[i][1]
                state = "stream-concat"
            elif state == "stream-concat":
                if self.content[i][0] == CHAR_REGULAR and self.content[i][1] == "endstream":
                    if filter:
                        if overridingfilters == "":
                            return self.Decompress(data, filters)
                        elif overridingfilters == "raw":
                            return data
                        else:
                            return self.Decompress(data, overridingfilters.split(" "))
                    else:
                        return data
                else:
                    data += self.content[i][1]
            else:
                return "Unexpected filter state"
        return filters

    def Decompress(self, data, filters):
        for filter in filters:
            if EqualCanonical(filter, "/FlateDecode") or EqualCanonical(filter, "/Fl"):
                try:
                    data = FlateDecode(data)
                except zlib.error as e:
                    message = "FlateDecode decompress failed"
                    if len(data) > 0 and ord(data[0]) & 0x0F != 8:
                        message += ", unexpected compression method: %02x" % ord(data[0])
                    return message + ". zlib.error %s" % e.message
            elif EqualCanonical(filter, "/ASCIIHexDecode") or EqualCanonical(filter, "/AHx"):
                try:
                    data = ASCIIHexDecode(data)
                except:
                    return "ASCIIHexDecode decompress failed"
            elif EqualCanonical(filter, "/ASCII85Decode") or EqualCanonical(filter, "/A85"):
                try:
                    data = ASCII85Decode(data.rstrip(">"))
                except:
                    return "ASCII85Decode decompress failed"
            elif EqualCanonical(filter, "/LZWDecode") or EqualCanonical(filter, "/LZW"):
                try:
                    data = LZWDecode(data)
                except:
                    return "LZWDecode decompress failed"
            elif EqualCanonical(filter, "/RunLengthDecode") or EqualCanonical(filter, "/R"):
                try:
                    data = RunLengthDecode(data)
                except:
                    return "RunLengthDecode decompress failed"
            #            elif i.startswith('/CC')                        # CCITTFaxDecode
            #            elif i.startswith('/DCT')                       # DCTDecode
            else:
                return "Unsupported filter: %s" % repr(filters)
        if len(filters) == 0:
            return "No filters"
        else:
            return data

    def StreamYARAMatch(self, rules, decoders, decoderoptions, filter, overridingfilters):
        if not self.ContainsStream():
            return None
        streamData = self.Stream(filter, overridingfilters)
        if filter and streamData == "No filters":
            streamData = self.Stream(False, overridingfilters)

        oDecoders = [cIdentity(streamData, None)]
        for cDecoder in decoders:
            try:
                oDecoder = cDecoder(streamData, decoderoptions)
                oDecoders.append(oDecoder)
            except Exception as e:
                print("Error instantiating decoder: %s" % cDecoder.name)
                raise e
        results = []
        for oDecoder in oDecoders:
            while oDecoder.Available():
                yaraResults = rules.match(data=oDecoder.Decode())
                if yaraResults != []:
                    results.append([oDecoder.Name(), yaraResults])

        return results


class cPDFElementStartxref:
    def __init__(self, index):
        self.type = PDF_ELEMENT_STARTXREF
        self.index = index


class cPDFElementMalformed:
    def __init__(self, content):
        self.type = PDF_ELEMENT_MALFORMED
        self.content = content


def TrimLWhiteSpace(data):
    while data != [] and data[0][0] == CHAR_WHITESPACE:
        data = data[1:]
    return data


def TrimRWhiteSpace(data):
    while data != [] and data[-1][0] == CHAR_WHITESPACE:
        data = data[:-1]
    return data


class cPDFParseDictionary:
    def __init__(self, content, nocanonicalizedoutput):
        self.content = content
        self.nocanonicalizedoutput = nocanonicalizedoutput
        dataTrimmed = TrimLWhiteSpace(TrimRWhiteSpace(self.content))
        if dataTrimmed == []:
            self.parsed = None
        elif self.isOpenDictionary(dataTrimmed[0]) and (
            self.isCloseDictionary(dataTrimmed[-1]) or self.couldBeCloseDictionary(dataTrimmed[-1])
        ):
            self.parsed = self.ParseDictionary(dataTrimmed)[0]
        else:
            self.parsed = None

    def isOpenDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == "<<"

    def isCloseDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1] == ">>"

    def couldBeCloseDictionary(self, token):
        return token[0] == CHAR_DELIMITER and token[1].rstrip().endswith(">>")

    def ParseDictionary(self, tokens):
        state = 0  # start
        dictionary = []
        while tokens != []:
            if state == 0:
                if self.isOpenDictionary(tokens[0]):
                    state = 1
                else:
                    return None, tokens
            elif state == 1:
                if self.isOpenDictionary(tokens[0]):
                    pass
                elif self.isCloseDictionary(tokens[0]):
                    return dictionary, tokens
                elif tokens[0][0] != CHAR_WHITESPACE:
                    key = ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput)
                    value = []
                    state = 2
            elif state == 2:
                if self.isOpenDictionary(tokens[0]):
                    value, tokens = self.ParseDictionary(tokens)
                    dictionary.append((key, value))
                    state = 1
                elif self.isCloseDictionary(tokens[0]):
                    dictionary.append((key, value))
                    return dictionary, tokens
                elif value == [] and tokens[0][0] == CHAR_WHITESPACE:
                    pass
                elif value == [] and tokens[0][1] == "[":
                    value.append(tokens[0][1])
                elif value != [] and value[0] == "[" and tokens[0][1] != "]":
                    value.append(tokens[0][1])
                elif value != [] and value[0] == "[" and tokens[0][1] == "]":
                    value.append(tokens[0][1])
                    dictionary.append((key, value))
                    value = []
                    state = 1
                elif value == [] and tokens[0][1] == "(":
                    value.append(tokens[0][1])
                elif value != [] and value[0] == "(" and tokens[0][1] != ")":
                    if tokens[0][1][0] == "%":
                        tokens = [tokens[0]] + cPDFTokenizer(StringIO(tokens[0][1][1:])).Tokens() + tokens[1:]
                        value.append("%")
                    else:
                        value.append(tokens[0][1])
                elif value != [] and value[0] == "(" and tokens[0][1] == ")":
                    value.append(tokens[0][1])
                    balanced = 0
                    for item in value:
                        if item == "(":
                            balanced += 1
                        elif item == ")":
                            balanced -= 1
                    if balanced < 0 and self.verbose:
                        print("todo 11: " + repr(value))
                    if balanced < 1:
                        dictionary.append((key, value))
                        value = []
                        state = 1
                elif value != [] and tokens[0][1][0] == "/":
                    dictionary.append((key, value))
                    key = ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput)
                    value = []
                    state = 2
                else:
                    value.append(ConditionalCanonicalize(tokens[0][1], self.nocanonicalizedoutput))
            tokens = tokens[1:]

    def Retrieve(self):
        return self.parsed

    def PrettyPrintSubElement(self, prefix, e):
        if e[1] == []:
            print("%s  %s" % (prefix, e[0]))
        elif type(e[1][0]) == type(""):
            if len(e[1]) == 3 and IsNumeric(e[1][0]) and e[1][1] == "0" and e[1][2] == "R":
                joiner = " "
            else:
                joiner = ""
            value = joiner.join(e[1]).strip()
            reprValue = repr(value)
            if "'" + value + "'" != reprValue:
                value = reprValue
            print("%s  %s %s" % (prefix, e[0], value))
        else:
            print("%s  %s" % (prefix, e[0]))
            self.PrettyPrintSub(prefix + "    ", e[1])

    def PrettyPrintSub(self, prefix, dictionary):
        if dictionary != None:
            print("%s<<" % prefix)
            for e in dictionary:
                self.PrettyPrintSubElement(prefix, e)
            print("%s>>" % prefix)

    def PrettyPrint(self, prefix):
        self.PrettyPrintSub(prefix, self.parsed)

    def Get(self, select):
        for key, value in self.parsed:
            if key == select:
                return value
        return None

    def GetNestedSub(self, dictionary, select):
        for key, value in dictionary:
            if key == select:
                return self.PrettyPrintSubElement("", [select, value])
            if type(value) == type([]) and len(value) > 0 and type(value[0]) == type((None,)):
                result = self.GetNestedSub(value, select)
                if result != None:
                    return self.PrettyPrintSubElement("", [select, result])
        return None

    def GetNested(self, select):
        return self.GetNestedSub(self.parsed, select)


def FormatOutput(data, raw):
    if raw:
        if type(data) == type([]):
            return "".join(map(lambda x: x[1], data))
        else:
            return data
    elif sys.version_info[0] > 2:
        return ascii(data)
    else:
        return repr(data)


# Fix for http://bugs.python.org/issue11395


def StdoutWriteChunked(data):
    if sys.version_info[0] > 2:
        sys.stdout.buffer.write(data)
    else:
        while data != "":
            sys.stdout.write(data[0:10000])
            try:
                sys.stdout.flush()
            except IOError:
                return
            data = data[10000:]


def IfWIN32SetBinary(io):
    if sys.platform == "win32":
        import msvcrt

        msvcrt.setmode(io.fileno(), os.O_BINARY)


def PrintOutputObject(object, options):
    if options.dump == "-":
        filtered = object.Stream(options.filter == True, options.overridingfilters)
        if filtered == []:
            filtered = ""
        IfWIN32SetBinary(sys.stdout)
        StdoutWriteChunked(filtered)
        return

    print("obj %d %d" % (object.id, object.version))
    if object.objstm != None:
        print(" Containing /ObjStm: %d %d" % object.objstm)
    print(" Type: %s" % ConditionalCanonicalize(object.GetType(), options.nocanonicalizedoutput))
    print(" Referencing: %s" % ", ".join(map(lambda x: "%s %s %s" % x, object.GetReferences())))
    dataPrecedingStream = object.ContainsStream()
    oPDFParseDictionary = None
    if dataPrecedingStream:
        print(" Contains stream")
        if options.debug:
            print(" %s" % FormatOutput(dataPrecedingStream, options.raw))
        oPDFParseDictionary = cPDFParseDictionary(dataPrecedingStream, options.nocanonicalizedoutput)
        if options.hash:
            streamContent = object.Stream(False, options.overridingfilters)
            print("  unfiltered")
            print("   len: %6d md5: %s" % (len(streamContent), hashlib.md5(streamContent).hexdigest()))
            print("   %s" % HexAsciiDumpLine(streamContent))
            streamContent = object.Stream(True, options.overridingfilters)
            print("  filtered")
            print("   len: %6d md5: %s" % (len(streamContent), hashlib.md5(streamContent).hexdigest()))
            print("   %s" % HexAsciiDumpLine(streamContent))
            streamContent = None
    else:
        if options.debug or options.raw:
            print(" %s" % FormatOutput(object.content, options.raw))
        oPDFParseDictionary = cPDFParseDictionary(object.content, options.nocanonicalizedoutput)
    print("")
    oPDFParseDictionary.PrettyPrint("  ")
    print("")
    if options.filter and not options.dump:
        filtered = object.Stream(overridingfilters=options.overridingfilters)
        if filtered == []:
            print(" %s" % FormatOutput(object.content, options.raw))
        else:
            print(" %s" % FormatOutput(filtered, options.raw))
    if options.content:
        if object.ContainsStream():
            stream = object.Stream(False, options.overridingfilters)
            if stream != []:
                print(" %s" % FormatOutput(stream, options.raw))
        else:
            print("".join([token[1] for token in object.content]))

    if options.dump:
        filtered = object.Stream(options.filter == True, options.overridingfilters)
        if filtered == []:
            filtered = ""
        try:
            fDump = open(options.dump, "wb")
            try:
                fDump.write(C2BIP3(filtered))
            except:
                print("Error writing file %s" % options.dump)
            fDump.close()
        except:
            print("Error writing file %s" % options.dump)
    print("")
    return


def Canonicalize(sIn):
    if sIn == "":
        return sIn
    elif sIn[0] != "/":
        return sIn
    elif sIn.find("#") == -1:
        return sIn
    else:
        i = 0
        iLen = len(sIn)
        sCanonical = ""
        while i < iLen:
            if sIn[i] == "#" and i < iLen - 2:
                try:
                    sCanonical += chr(int(sIn[i + 1 : i + 3], 16))
                    i += 2
                except:
                    sCanonical += sIn[i]
            else:
                sCanonical += sIn[i]
            i += 1
        return sCanonical


def EqualCanonical(s1, s2):
    return Canonicalize(s1) == s2


def ConditionalCanonicalize(sIn, nocanonicalizedoutput):
    if nocanonicalizedoutput:
        return sIn
    else:
        return Canonicalize(sIn)


# http://code.google.com/p/pdfminerr/source/browse/trunk/pdfminer/pdfminer/ascii85.py


def ASCII85Decode(data):
    import struct

    n = b = 0
    out = ""
    for c in data:
        if "!" <= c and c <= "u":
            n += 1
            b = b * 85 + (ord(c) - 33)
            if n == 5:
                out += struct.pack(">L", b)
                n = b = 0
        elif c == "z":
            assert n == 0
            out += "\0\0\0\0"
        elif c == "~":
            if n:
                for _ in range(5 - n):
                    b = b * 85 + 84
                out += struct.pack(">L", b)[: n - 1]
            break
    return out


def ASCIIHexDecode(data):
    return binascii.unhexlify("".join([c for c in data if c not in " \t\n\r"]).rstrip(">"))


# if inflating fails, we try to inflate byte per byte (sample 4da299d6e52bbb79c0ac00bad6a1d51d4d5fe42965a8d94e88a359e5277117e2)


def FlateDecode(data):
    try:
        return zlib.decompress(C2BIP3(data))
    except:
        if len(data) <= 10:
            raise
        oDecompress = zlib.decompressobj()
        oStringIO = StringIO()
        count = 0
        for byte in C2BIP3(data):
            try:
                oStringIO.write(oDecompress.decompress(byte))
                count += 1
            except:
                break
        if len(data) - count <= 2:
            return oStringIO.getvalue()
        else:
            raise


def RunLengthDecode(data):
    f = StringIO(data)
    decompressed = ""
    runLength = ord(f.read(1))
    while runLength:
        if runLength < 128:
            decompressed += f.read(runLength + 1)
        if runLength > 128:
            decompressed += f.read(1) * (257 - runLength)
        if runLength == 128:
            break
        runLength = ord(f.read(1))
    #    return sub(r'(\d+)(\D)', lambda m: m.group(2) * int(m.group(1)), data)
    return decompressed


#### LZW code sourced from pdfminer
# Copyright (c) 2004-2009 Yusuke Shinyama <yusuke at cs dot nyu dot edu>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:


class LZWDecoder(object):
    def __init__(self, fp):
        self.fp = fp
        self.buff = 0
        self.bpos = 8
        self.nbits = 9
        self.table = None
        self.prevbuf = None
        return

    def readbits(self, bits):
        v = 0
        while 1:
            # the number of remaining bits we can get from the current buffer.
            r = 8 - self.bpos
            if bits <= r:
                # |-----8-bits-----|
                # |-bpos-|-bits-|  |
                # |      |----r----|
                v = (v << bits) | ((self.buff >> (r - bits)) & ((1 << bits) - 1))
                self.bpos += bits
                break
            else:
                # |-----8-bits-----|
                # |-bpos-|---bits----...
                # |      |----r----|
                v = (v << r) | (self.buff & ((1 << r) - 1))
                bits -= r
                x = self.fp.read(1)
                if not x:
                    raise EOFError
                self.buff = ord(x)
                self.bpos = 0
        return v

    def feed(self, code):
        x = ""
        if code == 256:
            self.table = [chr(c) for c in range(256)]  # 0-255
            self.table.append(None)  # 256
            self.table.append(None)  # 257
            self.prevbuf = ""
            self.nbits = 9
        elif code == 257:
            pass
        elif not self.prevbuf:
            x = self.prevbuf = self.table[code]
        else:
            if code < len(self.table):
                x = self.table[code]
                self.table.append(self.prevbuf + x[0])
            else:
                self.table.append(self.prevbuf + self.prevbuf[0])
                x = self.table[code]
            l = len(self.table)
            if l == 511:
                self.nbits = 10
            elif l == 1023:
                self.nbits = 11
            elif l == 2047:
                self.nbits = 12
            self.prevbuf = x
        return x

    def run(self):
        while 1:
            try:
                code = self.readbits(self.nbits)
            except EOFError:
                break
            x = self.feed(code)
            yield x
        return


####


def LZWDecode(data):
    return "".join(LZWDecoder(StringIO(data)).run())


def PrintGenerateObject(object, options, newId=None):
    if newId == None:
        objectId = object.id
    else:
        objectId = newId
    dataPrecedingStream = object.ContainsStream()
    if dataPrecedingStream:
        if options.filter:
            decompressed = object.Stream(True, options.overridingfilters)
            if decompressed == "No filters" or decompressed.startswith("Unsupported filter: "):
                print(
                    "    oPDF.stream(%d, %d, %s, %s)"
                    % (
                        objectId,
                        object.version,
                        repr(object.Stream(False, options.overridingfilters).rstrip()),
                        repr(re.sub("/Length\s+\d+", "/Length %d", FormatOutput(dataPrecedingStream, True)).strip()),
                    )
                )
            else:
                dictionary = FormatOutput(dataPrecedingStream, True)
                dictionary = re.sub(r"/Length\s+\d+", "", dictionary)
                dictionary = re.sub(r"/Filter\s*/[a-zA-Z0-9]+", "", dictionary)
                dictionary = re.sub(r"/Filter\s*\[.+\]", "", dictionary)
                dictionary = re.sub(r"^\s*<<", "", dictionary)
                dictionary = re.sub(r">>\s*$", "", dictionary)
                dictionary = dictionary.strip()
                print("    oPDF.stream2(%d, %d, %s, %s, 'f')" % (objectId, object.version, repr(decompressed.rstrip()), repr(dictionary)))
        else:
            print(
                "    oPDF.stream(%d, %d, %s, %s)"
                % (
                    objectId,
                    object.version,
                    repr(object.Stream(False, options.overridingfilters).rstrip()),
                    repr(re.sub("/Length\s+\d+", "/Length %d", FormatOutput(dataPrecedingStream, True)).strip()),
                )
            )
    else:
        print("    oPDF.indirectobject(%d, %d, %s)" % (objectId, object.version, repr(FormatOutput(object.content, True).strip())))


def PrintObject(object, options):
    if options.generate:
        PrintGenerateObject(object, options)
    else:
        PrintOutputObject(object, options)


def File2Strings(filename):
    try:
        f = open(filename, "r")
    except:
        return None
    try:
        return map(lambda line: line.rstrip("\n"), f.readlines())
    except:
        return None
    finally:
        f.close()


def ProcessAt(argument):
    if argument.startswith("@"):
        strings = File2Strings(argument[1:])
        if strings == None:
            raise Exception("Error reading %s" % argument)
        else:
            return strings
    else:
        return [argument]


def YARACompile(ruledata):
    if ruledata.startswith("#"):
        if ruledata.startswith("#h#"):
            rule = binascii.a2b_hex(ruledata[3:])
        elif ruledata.startswith("#b#"):
            rule = binascii.a2b_base64(ruledata[3:])
        elif ruledata.startswith("#s#"):
            rule = 'rule string {strings: $a = "%s" ascii wide nocase condition: $a}' % ruledata[3:]
        elif ruledata.startswith("#q#"):
            rule = ruledata[3:].replace("'", '"')
        else:
            rule = ruledata[1:]
        return yara.compile(source=rule)
    else:
        dFilepaths = {}
        if os.path.isdir(ruledata):
            for root, dirs, files in os.walk(ruledata):
                for file in files:
                    filename = os.path.join(root, file)
                    dFilepaths[filename] = filename
        else:
            for filename in ProcessAt(ruledata):
                dFilepaths[filename] = filename
        return yara.compile(filepaths=dFilepaths)


def AddDecoder(cClass):
    global decoders

    decoders.append(cClass)


class cDecoderParent:
    pass


def GetScriptPath():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(sys.argv[0])


def LoadDecoders(decoders, verbose):
    if decoders == "":
        return
    scriptPath = GetScriptPath()
    for decoder in sum(map(ProcessAt, decoders.split(",")), []):
        try:
            if not decoder.lower().endswith(".py"):
                decoder += ".py"
            if os.path.dirname(decoder) == "":
                if not os.path.exists(decoder):
                    scriptDecoder = os.path.join(scriptPath, decoder)
                    if os.path.exists(scriptDecoder):
                        decoder = scriptDecoder
            exec(open(decoder, "r").read(), globals(), globals())
        except Exception as e:
            print("Error loading decoder: %s" % decoder)
            if verbose:
                raise e


class cIdentity(cDecoderParent):
    name = "Identity function decoder"

    def __init__(self, stream, options):
        self.stream = stream
        self.options = options
        self.available = True

    def Available(self):
        return self.available

    def Decode(self):
        self.available = False
        return self.stream

    def Name(self):
        return ""


def DecodeFunction(decoders, options, stream):
    if decoders == []:
        return stream
    return decoders[0](stream, options.decoderoptions).Decode()


class cDumpStream:
    def __init__(self):
        self.text = ""

    def Addline(self, line):
        if line != "":
            self.text += line + "\n"

    def Content(self):
        return self.text


def HexDump(data):
    oDumpStream = cDumpStream()
    hexDump = ""
    for i, b in enumerate(data):
        if i % dumplinelength == 0 and hexDump != "":
            oDumpStream.Addline(hexDump)
            hexDump = ""
        hexDump += IFF(hexDump == "", "", " ") + "%02X" % ord(b)
    oDumpStream.Addline(hexDump)
    return oDumpStream.Content()


def CombineHexAscii(hexDump, asciiDump):
    if hexDump == "":
        return ""
    return hexDump + "  " + (" " * (3 * (dumplinelength - len(asciiDump)))) + asciiDump


def HexAsciiDump(data):
    oDumpStream = cDumpStream()
    hexDump = ""
    asciiDump = ""
    for i, b in enumerate(data):
        if i % dumplinelength == 0:
            if hexDump != "":
                oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
            hexDump = "%08X:" % i
            asciiDump = ""
        hexDump += " %02X" % ord(b)
        asciiDump += IFF(ord(b) >= 32, b, ".")
    oDumpStream.Addline(CombineHexAscii(hexDump, asciiDump))
    return oDumpStream.Content()


def HexAsciiDumpLine(data):
    return HexAsciiDump(data[0:16])[10:-1]


def ParseINIFile():
    oConfigParser = ConfigParser.ConfigParser(allow_no_value=True)
    oConfigParser.optionxform = str
    oConfigParser.read(os.path.join(GetScriptPath(), "pdfid.ini"))
    keywords = []
    if oConfigParser.has_section("keywords"):
        for key, value in oConfigParser.items("keywords"):
            if not key in keywords:
                keywords.append(key)
    return keywords


def MatchObjectID(id, selection):
    return str(id) in selection.split(",")


def GetArguments():
    arguments = sys.argv[1:]
    envvar = os.getenv("PDFPARSER_OPTIONS")
    if envvar == None:
        return arguments
    return envvar.split(" ") + arguments


def Main():
    """pdf-parser, use it to parse a PDF document
    """

    global decoders

    oParser = optparse.OptionParser(usage="usage: %prog [options] pdf-file|zip-file|url\n" + __description__, version="%prog " + __version__)
    oParser.add_option("-m", "--man", action="store_true", default=False, help="Print manual")
    oParser.add_option("-s", "--search", help="string to search in indirect objects (except streams)")
    oParser.add_option(
        "-f",
        "--filter",
        action="store_true",
        default=False,
        help="pass stream object through filters (FlateDecode, ASCIIHexDecode, ASCII85Decode, LZWDecode and RunLengthDecode only)",
    )
    oParser.add_option("-o", "--object", help="id(s) of indirect object(s) to select, use comma (,) to separate ids (version independent)")
    oParser.add_option("-r", "--reference", help="id of indirect object being referenced (version independent)")
    oParser.add_option("-e", "--elements", help="type of elements to select (cxtsi)")
    oParser.add_option("-w", "--raw", action="store_true", default=False, help="raw output for data and filters")
    oParser.add_option("-a", "--stats", action="store_true", default=False, help="display stats for pdf document")
    oParser.add_option("-t", "--type", help="type of indirect object to select")
    oParser.add_option("-O", "--objstm", action="store_true", default=False, help="parse stream of /ObjStm objects")
    oParser.add_option("-v", "--verbose", action="store_true", default=False, help="display malformed PDF elements")
    oParser.add_option("-x", "--extract", help="filename to extract malformed content to")
    oParser.add_option("-H", "--hash", action="store_true", default=False, help="display hash of objects")
    oParser.add_option("-n", "--nocanonicalizedoutput", action="store_true", default=False, help="do not canonicalize the output")
    oParser.add_option("-d", "--dump", help="filename to dump stream content to")
    oParser.add_option("-D", "--debug", action="store_true", default=False, help="display debug info")
    oParser.add_option(
        "-c",
        "--content",
        action="store_true",
        default=False,
        help="display the content for objects without streams or with streams without filters",
    )
    oParser.add_option("--searchstream", help="string to search in streams")
    oParser.add_option("--unfiltered", action="store_true", default=False, help="search in unfiltered streams")
    oParser.add_option("--casesensitive", action="store_true", default=False, help="case sensitive search in streams")
    oParser.add_option("--regex", action="store_true", default=False, help="use regex to search in streams")
    oParser.add_option(
        "--overridingfilters", type=str, default="", help="override filters with given filters (use raw for the raw stream content)"
    )
    oParser.add_option(
        "-g", "--generate", action="store_true", default=False, help="generate a Python program that creates the parsed PDF file"
    )
    oParser.add_option(
        "--generateembedded", type=int, default=0, help="generate a Python program that embeds the selected indirect object as a file"
    )
    oParser.add_option("-y", "--yara", help="YARA rule (or directory or @file) to check streams (can be used with option --unfiltered)")
    oParser.add_option("--yarastrings", action="store_true", default=False, help="Print YARA strings")
    oParser.add_option("--decoders", type=str, default="", help="decoders to load (separate decoders with a comma , ; @file supported)")
    oParser.add_option("--decoderoptions", type=str, default="", help="options for the decoder")
    oParser.add_option("-k", "--key", help="key to search in dictionaries")
    (options, args) = oParser.parse_args(GetArguments())

    if options.man:
        oParser.print_help()
        PrintManual()
        return 0

    if len(args) != 1:
        oParser.print_help()
        print("")
        print("  %s" % __description__)
        print("  Source code put in the public domain by Didier Stevens, no Copyright")
        print("  Use at your own risk")
        print("  https://DidierStevens.com")

    else:
        decoders = []
        LoadDecoders(options.decoders, True)

        oPDFParser = cPDFParser(args[0], options.verbose, options.extract)
        cntComment = 0
        cntXref = 0
        cntTrailer = 0
        cntStartXref = 0
        cntIndirectObject = 0
        dicObjectTypes = {}
        keywords = ["/JS", "/JavaScript", "/AA", "/OpenAction", "/AcroForm", "/RichMedia", "/Launch", "/EmbeddedFile", "/XFA", "/URI"]
        for extrakeyword in ParseINIFile():
            if not extrakeyword in keywords:
                keywords.append(extrakeyword)

        #        dKeywords = {keyword: [] for keyword in keywords}
        # Done for compatibility with 2.6.6
        dKeywords = {}
        for keyword in keywords:
            dKeywords[keyword] = []

        selectComment = False
        selectXref = False
        selectTrailer = False
        selectStartXref = False
        selectIndirectObject = False
        if options.elements:
            for c in options.elements:
                if c == "c":
                    selectComment = True
                elif c == "x":
                    selectXref = True
                elif c == "t":
                    selectTrailer = True
                elif c == "s":
                    selectStartXref = True
                elif c == "i":
                    selectIndirectObject = True
                else:
                    print("Error: unknown --elements value %s" % c)
                    return
        else:
            selectIndirectObject = True
            if (
                not options.search
                and not options.object
                and not options.reference
                and not options.type
                and not options.searchstream
                and not options.key
            ):
                selectComment = True
                selectXref = True
                selectTrailer = True
                selectStartXref = True
            if options.search or options.key or options.reference:
                selectTrailer = True

        if options.type == "-":
            optionsType = ""
        else:
            optionsType = options.type

        if options.generate or options.generateembedded != 0:
            savedRoot = ["1", "0", "R"]
            print("#!/usr/bin/python")
            print("")
            print('"""')
            print("")
            print("Program generated by pdf-parser.py by Didier Stevens")
            print("https://DidierStevens.com")
            print("Use at your own risk")
            print("")
            print("Input PDF file: %s" % args[0])
            print("This Python program was created on: %s" % Timestamp())
            print("")
            print('"""')
            print("")
            print("import mPDF")
            print("import sys")
            print("")
            print("def Main():")
            print("    if len(sys.argv) != 2:")
            print("        print('Usage: %s pdf-file' % sys.argv[0])")
            print("        return")
            print("    oPDF = mPDF.cPDF(sys.argv[1])")

        if options.generateembedded != 0:
            print("    oPDF.header('1.1')")
            print(r"    oPDF.comment('\xd0\xd0\xd0\xd0')")
            print(
                r"    oPDF.indirectobject(1, 0, '<<\r\n /Type /Catalog\r\n /Outlines 2 0 R\r\n /Pages 3 0 R\r\n /Names << /EmbeddedFiles << /Names [(test.bin) 7 0 R] >> >>\r\n>>')"
            )
            print(r"    oPDF.indirectobject(2, 0, '<<\r\n /Type /Outlines\r\n /Count 0\r\n>>')")
            print(r"    oPDF.indirectobject(3, 0, '<<\r\n /Type /Pages\r\n /Kids [4 0 R]\r\n /Count 1\r\n>>')")
            print(
                r"    oPDF.indirectobject(4, 0, '<<\r\n /Type /Page\r\n /Parent 3 0 R\r\n /MediaBox [0 0 612 792]\r\n /Contents 5 0 R\r\n /Resources <<\r\n             /ProcSet [/PDF /Text]\r\n             /Font << /F1 6 0 R >>\r\n            >>\r\n>>')"
            )
            print(r"    oPDF.stream(5, 0, 'BT /F1 12 Tf 70 700 Td 15 TL (This PDF document embeds file test.bin) Tj ET', '<< /Length %d >>')")
            print(
                r"    oPDF.indirectobject(6, 0, '<<\r\n /Type /Font\r\n /Subtype /Type1\r\n /Name /F1\r\n /BaseFont /Helvetica\r\n /Encoding /MacRomanEncoding\r\n>>')"
            )
            print(r"    oPDF.indirectobject(7, 0, '<<\r\n /Type /Filespec\r\n /F (test.bin)\r\n /EF << /F 8 0 R >>\r\n>>')")

        if options.yara != None:
            if not "yara" in sys.modules:
                print("Error: option yara requires the YARA Python module.")
                return
            rules = YARACompile(options.yara)

        oPDFParserOBJSTM = None
        while True:
            if oPDFParserOBJSTM == None:
                object = oPDFParser.GetObject()
            else:
                object = oPDFParserOBJSTM.GetObject()
                if object == None:
                    oPDFParserOBJSTM = None
                    object = oPDFParser.GetObject()
            if options.objstm and hasattr(object, "GetType") and EqualCanonical(object.GetType(), "/ObjStm") and object.ContainsStream():
                # parsing objects inside an /ObjStm object by extracting & parsing the stream content to create a synthesized PDF document, that is then parsed by cPDFParser
                oPDFParseDictionary = cPDFParseDictionary(object.ContainsStream(), options.nocanonicalizedoutput)
                numberOfObjects = int(oPDFParseDictionary.Get("/N")[0])
                offsetFirstObject = int(oPDFParseDictionary.Get("/First")[0])
                indexes = list(map(int, C2SIP3(object.Stream())[:offsetFirstObject].strip().split(" ")))
                if len(indexes) % 2 != 0 or len(indexes) / 2 != numberOfObjects:
                    raise Exception("Error in index of /ObjStm stream")
                streamObject = C2SIP3(object.Stream()[offsetFirstObject:])
                synthesizedPDF = ""
                while len(indexes) > 0:
                    objectNumber = indexes[0]
                    offset = indexes[1]
                    indexes = indexes[2:]
                    if len(indexes) >= 2:
                        offsetNextObject = indexes[1]
                    else:
                        offsetNextObject = len(streamObject)
                    synthesizedPDF += "%d 0 obj\n%s\nendobj\n" % (objectNumber, streamObject[offset:offsetNextObject])
                oPDFParserOBJSTM = cPDFParser(StringIO(synthesizedPDF), options.verbose, options.extract, (object.id, object.version))
            if object != None:
                if options.stats:
                    if object.type == PDF_ELEMENT_COMMENT:
                        cntComment += 1
                    elif object.type == PDF_ELEMENT_XREF:
                        cntXref += 1
                    elif object.type == PDF_ELEMENT_TRAILER:
                        cntTrailer += 1
                    elif object.type == PDF_ELEMENT_STARTXREF:
                        cntStartXref += 1
                    elif object.type == PDF_ELEMENT_INDIRECT_OBJECT:
                        cntIndirectObject += 1
                        type1 = object.GetType()
                        if not type1 in dicObjectTypes:
                            dicObjectTypes[type1] = [object.id]
                        else:
                            dicObjectTypes[type1].append(object.id)
                        for keyword in dKeywords.keys():
                            if object.ContainsName(keyword):
                                dKeywords[keyword].append(object.id)
                else:
                    if object.type == PDF_ELEMENT_COMMENT and selectComment:
                        if options.generate:
                            comment = object.comment[1:].rstrip()
                            if re.match("PDF-\d\.\d", comment):
                                print("    oPDF.header('%s')" % comment[4:])
                            elif comment != "%EOF":
                                print("    oPDF.comment(%s)" % repr(comment))
                        elif options.yara == None and options.generateembedded == 0:
                            print("PDF Comment %s" % FormatOutput(object.comment, options.raw))
                            print("")
                    elif object.type == PDF_ELEMENT_XREF and selectXref:
                        if not options.generate and options.yara == None and options.generateembedded == 0:
                            if options.debug:
                                print("xref %s" % FormatOutput(object.content, options.raw))
                            else:
                                print("xref")
                            print("")
                    elif object.type == PDF_ELEMENT_TRAILER and selectTrailer:
                        oPDFParseDictionary = cPDFParseDictionary(object.content[1:], options.nocanonicalizedoutput)
                        if options.generate:
                            result = oPDFParseDictionary.Get("/Root")
                            if result != None:
                                savedRoot = result
                        elif options.yara == None and options.generateembedded == 0:
                            if (
                                not options.search
                                and not options.key
                                and not options.reference
                                or options.search
                                and object.Contains(options.search)
                            ):
                                if oPDFParseDictionary == None:
                                    print("trailer %s" % FormatOutput(object.content, options.raw))
                                else:
                                    print("trailer")
                                    oPDFParseDictionary.PrettyPrint("  ")
                                print("")
                            elif options.key:
                                if oPDFParseDictionary.parsed != None:
                                    result = oPDFParseDictionary.GetNested(options.key)
                                    if result != None:
                                        print(result)
                            elif options.reference:
                                for key, value in oPDFParseDictionary.Retrieve():
                                    if value == [str(options.reference), "0", "R"]:
                                        print("trailer")
                                        oPDFParseDictionary.PrettyPrint("  ")
                    elif object.type == PDF_ELEMENT_STARTXREF and selectStartXref:
                        if not options.generate and options.yara == None and options.generateembedded == 0:
                            print("startxref %d" % object.index)
                            print("")
                    elif object.type == PDF_ELEMENT_INDIRECT_OBJECT and selectIndirectObject:
                        if options.search:
                            if object.Contains(options.search):
                                PrintObject(object, options)
                        elif options.key:
                            contentDictionary = object.ContainsStream()
                            if not contentDictionary:
                                contentDictionary = object.content[1:]
                            oPDFParseDictionary = cPDFParseDictionary(contentDictionary, options.nocanonicalizedoutput)
                            if oPDFParseDictionary.parsed != None:
                                result = oPDFParseDictionary.GetNested(options.key)
                                if result != None:
                                    print(result)
                        elif options.object:
                            if MatchObjectID(object.id, options.object):
                                PrintObject(object, options)
                        elif options.reference:
                            if object.References(options.reference):
                                PrintObject(object, options)
                        elif options.type:
                            if EqualCanonical(object.GetType(), optionsType):
                                PrintObject(object, options)
                        elif options.hash:
                            print("obj %d %d" % (object.id, object.version))
                            rawContent = FormatOutput(object.content, True)
                            print(" len: %d md5: %s" % (len(rawContent), hashlib.md5(rawContent).hexdigest()))
                            print("")
                        elif options.searchstream:
                            if object.StreamContains(
                                options.searchstream, not options.unfiltered, options.casesensitive, options.regex, options.overridingfilters
                            ):
                                PrintObject(object, options)
                        elif options.yara != None:
                            results = object.StreamYARAMatch(
                                rules, decoders, options.decoderoptions, not options.unfiltered, options.overridingfilters
                            )
                            if results != None and results != []:
                                for result in results:
                                    for yaraResult in result[1]:
                                        print(
                                            "YARA rule%s: %s (%s)"
                                            % (
                                                IFF(result[0] == "", "", " (stream decoder: %s)" % result[0]),
                                                yaraResult.rule,
                                                yaraResult.namespace,
                                            )
                                        )
                                        if options.yarastrings:
                                            for stringdata in yaraResult.strings:
                                                print("%06x %s:" % (stringdata[0], stringdata[1]))
                                                print(" %s" % binascii.hexlify(C2BIP3(stringdata[2])))
                                                print(" %s" % repr(stringdata[2]))
                                    PrintObject(object, options)
                        elif options.generateembedded != 0:
                            if object.id == options.generateembedded:
                                PrintGenerateObject(object, options, 8)
                        else:
                            PrintObject(object, options)
                    elif object.type == PDF_ELEMENT_MALFORMED:
                        try:
                            fExtract = open(options.extract, "wb")
                            try:
                                fExtract.write(C2BIP3(object.content))
                            except:
                                print("Error writing file %s" % options.extract)
                            fExtract.close()
                        except:
                            print("Error writing file %s" % options.extract)
            else:
                break

        if options.stats:
            print("Comment: %s" % cntComment)
            print("XREF: %s" % cntXref)
            print("Trailer: %s" % cntTrailer)
            print("StartXref: %s" % cntStartXref)
            print("Indirect object: %s" % cntIndirectObject)
            for key in sorted(dicObjectTypes.keys()):
                print(" %s %d: %s" % (key, len(dicObjectTypes[key]), ", ".join(map(lambda x: "%d" % x, dicObjectTypes[key]))))
            if sum(map(len, dKeywords.values())) > 0:
                print("Search keywords:")
                for keyword in keywords:
                    if len(dKeywords[keyword]) > 0:
                        print(" %s %d: %s" % (keyword, len(dKeywords[keyword]), ", ".join(map(lambda x: "%d" % x, dKeywords[keyword]))))

        if options.generate or options.generateembedded != 0:
            print("    oPDF.xrefAndTrailer('%s')" % " ".join(savedRoot))
            print("")
            print("if __name__ == '__main__':")
            print("    Main()")


def TestPythonVersion(enforceMaximumVersion=False, enforceMinimumVersion=False):
    if sys.version_info[0:3] > __maximum_python_version__:
        if enforceMaximumVersion:
            print("This program does not work with this version of Python (%d.%d.%d)" % sys.version_info[0:3])
            print("Please use Python version %d.%d.%d" % __maximum_python_version__)
            sys.exit()
        else:
            print("This program has not been tested with this version of Python (%d.%d.%d)" % sys.version_info[0:3])
            print("Should you encounter problems, please use Python version %d.%d.%d" % __maximum_python_version__)
    if sys.version_info[0:3] < __minimum_python_version__:
        if enforceMinimumVersion:
            print("This program does not work with this version of Python (%d.%d.%d)" % sys.version_info[0:3])
            print("Please use Python version %d.%d.%d" % __maximum_python_version__)
            sys.exit()
        else:
            print("This program has not been tested with this version of Python (%d.%d.%d)" % sys.version_info[0:3])
            print("Should you encounter problems, please use Python version %d.%d.%d" % __maximum_python_version__)


if __name__ == "__main__":
    TestPythonVersion()
    Main()
