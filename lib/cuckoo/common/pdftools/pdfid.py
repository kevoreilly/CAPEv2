#!/usr/bin/env python
__description__ = "Tool to test a PDF file"
__author__ = "Didier Stevens"
__version__ = "0.2.7"
__date__ = "2019/11/05"

"""

Tool to test a PDF file

Source code put in public domain by Didier Stevens, no Copyright
https://DidierStevens.com
Use at your own risk

History:
  2009/03/27: start
  2009/03/28: scan option
  2009/03/29: V0.0.2: xml output
  2009/03/31: V0.0.3: /ObjStm suggested by Dion
  2009/04/02: V0.0.4: added ErrorMessage
  2009/04/20: V0.0.5: added Dates
  2009/04/21: V0.0.6: added entropy
  2009/04/22: added disarm
  2009/04/29: finished disarm
  2009/05/13: V0.0.7: added cPDFEOF
  2009/07/24: V0.0.8: added /AcroForm and /RichMedia, simplified %PDF header regex, extra date format (without TZ)
  2009/07/25: added input redirection, option --force
  2009/10/13: V0.0.9: added detection for CVE-2009-3459; added /RichMedia to disarm
  2010/01/11: V0.0.10: relaxed %PDF header checking
  2010/04/28: V0.0.11: added /Launch
  2010/09/21: V0.0.12: fixed cntCharsAfterLastEOF bug; fix by Russell Holloway
  2011/12/29: updated for Python 3, added keyword /EmbeddedFile
  2012/03/03: added PDFiD2JSON; coded by Brandon Dixon
  2013/02/10: V0.1.0: added http/https support; added support for ZIP file with password 'infected'
  2013/03/11: V0.1.1: fixes for Python 3
  2013/03/13: V0.1.2: Added error handling for files; added /XFA
  2013/11/01: V0.2.0: Added @file & plugins
  2013/11/02: continue
  2013/11/04: added options -c, -m, -v
  2013/11/06: added option -S
  2013/11/08: continue
  2013/11/09: added option -o
  2013/11/15: refactoring
  2014/09/30: added CSV header
  2014/10/16: V0.2.1: added output when plugin & file not pdf
  2014/10/18: some fixes for Python 3
  2015/08/12: V0.2.2: added option pluginoptions
  2015/08/13: added plugin Instructions method
  2016/04/12: added option literal
  2017/10/29: added pdfid.ini support
  2017/11/05: V0.2.3: added option -n
  2018/01/03: V0.2.4: bugfix entropy calculation for PDFs without streams; sample 28cb208d976466b295ee879d2d233c8a https://twitter.com/DubinRan/status/947783629123416069
  2018/01/15: bugfix ConfigParser privately reported
  2018/01/29: bugfix oPDFEOF.cntCharsAfterLastEOF when no %%EOF
  2018/07/05: V0.2.5 introduced cExpandFilenameArguments; renamed option literal to literalfilenames
  2019/09/30: V0.2.6 color bugfix, thanks to Leo
  2019/11/05: V0.2.7 fixed plugin path when compiled with pyinstaller

Todo:
  - update XML example (entropy, EOF)
  - code review, cleanup
"""

import binascii
import collections
import configparser as ConfigParser
import fnmatch
import glob
import json
import math
import operator
import optparse
import os
import os.path
import random
import sys
import traceback
import urllib.request as urllib23
import xml.dom.minidom
import zipfile

# Convert 2 Bytes If Python 3

FCH_FILENAME = 0
FCH_DATA = 1
FCH_ERROR = 2


def C2BIP3(string):
    return bytes([ord(x) for x in string])


def Hex2Bytes(hexadecimal):
    if len(hexadecimal) % 2 == 1:
        hexadecimal = "0" + hexadecimal
    try:
        return binascii.a2b_hex(hexadecimal)
    except Exception:
        return None


def LoremIpsumSentence(minimum, maximum):
    words = [
        "lorem",
        "ipsum",
        "dolor",
        "sit",
        "amet",
        "consectetur",
        "adipiscing",
        "elit",
        "etiam",
        "tortor",
        "metus",
        "cursus",
        "sed",
        "sollicitudin",
        "ac",
        "sagittis",
        "eget",
        "massa",
        "praesent",
        "sem",
        "fermentum",
        "dignissim",
        "in",
        "vel",
        "augue",
        "scelerisque",
        "auctor",
        "libero",
        "nam",
        "a",
        "gravida",
        "odio",
        "duis",
        "vestibulum",
        "vulputate",
        "quam",
        "nec",
        "cras",
        "nibh",
        "feugiat",
        "ut",
        "vitae",
        "ornare",
        "justo",
        "orci",
        "varius",
        "natoque",
        "penatibus",
        "et",
        "magnis",
        "dis",
        "parturient",
        "montes",
        "nascetur",
        "ridiculus",
        "mus",
        "curabitur",
        "nisl",
        "egestas",
        "urna",
        "iaculis",
        "lectus",
        "maecenas",
        "ultrices",
        "velit",
        "eu",
        "porta",
        "hac",
        "habitasse",
        "platea",
        "dictumst",
        "integer",
        "id",
        "commodo",
        "mauris",
        "interdum",
        "malesuada",
        "fames",
        "ante",
        "primis",
        "faucibus",
        "accumsan",
        "pharetra",
        "aliquam",
        "nunc",
        "at",
        "est",
        "non",
        "leo",
        "nulla",
        "sodales",
        "porttitor",
        "facilisis",
        "aenean",
        "condimentum",
        "rutrum",
        "facilisi",
        "tincidunt",
        "laoreet",
        "ultricies",
        "neque",
        "diam",
        "euismod",
        "consequat",
        "tempor",
        "elementum",
        "lobortis",
        "erat",
        "ligula",
        "risus",
        "donec",
        "phasellus",
        "quisque",
        "vivamus",
        "pellentesque",
        "tristique",
        "venenatis",
        "purus",
        "mi",
        "dictum",
        "posuere",
        "fringilla",
        "quis",
        "magna",
        "pretium",
        "felis",
        "pulvinar",
        "lacinia",
        "proin",
        "viverra",
        "lacus",
        "suscipit",
        "aliquet",
        "dui",
        "molestie",
        "dapibus",
        "mollis",
        "suspendisse",
        "sapien",
        "blandit",
        "morbi",
        "tellus",
        "enim",
        "maximus",
        "semper",
        "arcu",
        "bibendum",
        "convallis",
        "hendrerit",
        "imperdiet",
        "finibus",
        "fusce",
        "congue",
        "ullamcorper",
        "placerat",
        "nullam",
        "eros",
        "habitant",
        "senectus",
        "netus",
        "turpis",
        "luctus",
        "volutpat",
        "rhoncus",
        "mattis",
        "nisi",
        "ex",
        "tempus",
        "eleifend",
        "vehicula",
        "class",
        "aptent",
        "taciti",
        "sociosqu",
        "ad",
        "litora",
        "torquent",
        "per",
        "conubia",
        "nostra",
        "inceptos",
        "himenaeos",
    ]
    sample = random.sample(words, random.randint(minimum, maximum))
    sample[0] = sample[0].capitalize()
    return " ".join(sample) + "."


def LoremIpsum(sentences):
    return " ".join([LoremIpsumSentence(15, 30) for i in range(sentences)])


STATE_START = 0
STATE_IDENTIFIER = 1
STATE_STRING = 2
STATE_SPECIAL_CHAR = 3
STATE_ERROR = 4

FUNCTIONNAME_REPEAT = "repeat"
FUNCTIONNAME_RANDOM = "random"
FUNCTIONNAME_CHR = "chr"
FUNCTIONNAME_LOREMIPSUM = "loremipsum"


def Tokenize(expression):
    result = []
    token = ""
    state = STATE_START
    while expression != "":
        char = expression[0]
        expression = expression[1:]
        if char == "'":
            if state == STATE_START:
                state = STATE_STRING
            elif state == STATE_IDENTIFIER:
                result.append([STATE_IDENTIFIER, token])
                state = STATE_STRING
                token = ""
            elif state == STATE_STRING:
                result.append([STATE_STRING, token])
                state = STATE_START
                token = ""
        elif char >= "0" and char <= "9" or char.lower() >= "a" and char.lower() <= "z":
            if state == STATE_START:
                token = char
                state = STATE_IDENTIFIER
            else:
                token += char
        elif char == " ":
            if state == STATE_IDENTIFIER:
                result.append([STATE_IDENTIFIER, token])
                token = ""
                state = STATE_START
            elif state == STATE_STRING:
                token += char
        else:
            if state == STATE_IDENTIFIER:
                result.append([STATE_IDENTIFIER, token])
                token = ""
                state = STATE_START
                result.append([STATE_SPECIAL_CHAR, char])
            elif state == STATE_STRING:
                token += char
            else:
                result.append([STATE_SPECIAL_CHAR, char])
                token = ""
    if state == STATE_IDENTIFIER:
        result.append([state, token])
    elif state == STATE_STRING:
        result = [[STATE_ERROR, "Error: string not closed", token]]
    return result


def InterpretBytes(token):
    if token[0] == STATE_STRING:
        return token[1]
    if token[0] != STATE_IDENTIFIER:
        return None
    if not token[1].startswith("0x"):
        return None
    return Hex2Bytes(token[1][2:])


def CheckFunction(functionname, arguments, countarguments, maxcountarguments=None):
    if maxcountarguments is None:
        if countarguments == 0 and len(arguments) != 0:
            print("Error: function %s takes no arguments, %d are given" % (functionname, len(arguments)))
            return True
        if countarguments == 1 and len(arguments) != 1:
            print("Error: function %s takes 1 argument, %d are given" % (functionname, len(arguments)))
            return True
        if countarguments != len(arguments):
            print("Error: function %s takes %d arguments, %d are given" % (functionname, countarguments, len(arguments)))
            return True
    else:
        if len(arguments) < countarguments or len(arguments) > maxcountarguments:
            print(
                "Error: function %s takes between %d and %d arguments, %d are given"
                % (functionname, countarguments, maxcountarguments, len(arguments))
            )
            return True
    return False


def InterpretInteger(token):
    if token[0] != STATE_IDENTIFIER:
        return None
    try:
        return int(token[1])
    except Exception:
        return None


def InterpretHexInteger(token):
    if token[0] != STATE_IDENTIFIER:
        return None
    if not token[1].startswith("0x"):
        return None
    bytes = Hex2Bytes(token[1][2:])
    if bytes is None:
        return None
    integer = 0
    for byte in bytes:
        integer = integer * 0x100 + byte
    return integer


def InterpretNumber(token):
    number = InterpretInteger(token)
    if number is None:
        return InterpretHexInteger(token)
    else:
        return number


def CheckNumber(argument, minimum=None, maximum=None):
    number = InterpretNumber(argument)
    if number is None:
        print("Error: argument should be a number: %s" % argument[1])
        return None
    if minimum is not None and number < minimum:
        print("Error: argument should be minimum %d: %d" % (minimum, number))
        return None
    if maximum is not None and number > maximum:
        print("Error: argument should be maximum %d: %d" % (maximum, number))
        return None
    return number


def ParseFunction(tokens):
    if len(tokens) == 0:
        print("Parsing error")
        return None, tokens
    if tokens[0][0] == STATE_STRING or tokens[0][0] == STATE_IDENTIFIER and tokens[0][1].startswith("0x"):
        return [[FUNCTIONNAME_REPEAT, [[STATE_IDENTIFIER, "1"], tokens[0]]], tokens[1:]]
    if tokens[0][0] != STATE_IDENTIFIER:
        print("Parsing error")
        return None, tokens
    function = tokens[0][1]
    tokens = tokens[1:]
    if len(tokens) == 0:
        print("Parsing error")
        return None, tokens
    if tokens[0][0] != STATE_SPECIAL_CHAR or tokens[0][1] != "(":
        print("Parsing error")
        return None, tokens
    tokens = tokens[1:]
    if len(tokens) == 0:
        print("Parsing error")
        return None, tokens
    arguments = []
    while True:
        if tokens[0][0] != STATE_IDENTIFIER and tokens[0][0] != STATE_STRING:
            print("Parsing error")
            return None, tokens
        arguments.append(tokens[0])
        tokens = tokens[1:]
        if len(tokens) == 0:
            print("Parsing error")
            return None, tokens
        if tokens[0][0] != STATE_SPECIAL_CHAR or (tokens[0][1] != "," and tokens[0][1] != ")"):
            print("Parsing error")
            return None, tokens
        if tokens[0][0] == STATE_SPECIAL_CHAR and tokens[0][1] == ")":
            tokens = tokens[1:]
            break
        tokens = tokens[1:]
        if len(tokens) == 0:
            print("Parsing error")
            return None, tokens
    return [[function, arguments], tokens]


def Parse(expression):
    tokens = Tokenize(expression)
    if len(tokens) == 0:
        print("Parsing error")
        return None
    if tokens[0][0] == STATE_ERROR:
        print(tokens[0][1])
        print(tokens[0][2])
        print(expression)
        return None
    functioncalls = []
    while True:
        functioncall, tokens = ParseFunction(tokens)
        if functioncall is None:
            return None
        functioncalls.append(functioncall)
        if len(tokens) == 0:
            return functioncalls
        if tokens[0][0] != STATE_SPECIAL_CHAR or tokens[0][1] != "+":
            print("Parsing error")
            return None
        tokens = tokens[1:]


def Interpret(expression):
    functioncalls = Parse(expression)
    if functioncalls is None:
        return None
    decoded = ""
    for functioncall in functioncalls:
        functionname, arguments = functioncall
        if functionname == FUNCTIONNAME_REPEAT:
            if CheckFunction(functionname, arguments, 2):
                return None
            number = CheckNumber(arguments[0], minimum=1)
            if number is None:
                return None
            bytes = InterpretBytes(arguments[1])
            if bytes is None:
                print("Error: argument should be a byte sequence: %s" % arguments[1][1])
                return None
            decoded += number * bytes
        elif functionname == FUNCTIONNAME_RANDOM:
            if CheckFunction(functionname, arguments, 1):
                return None
            number = CheckNumber(arguments[0], minimum=1)
            if number is None:
                return None
            decoded += "".join([chr(random.randint(0, 255)) for x in range(number)])
        elif functionname == FUNCTIONNAME_LOREMIPSUM:
            if CheckFunction(functionname, arguments, 1):
                return None
            number = CheckNumber(arguments[0], minimum=1)
            if number is None:
                return None
            decoded += LoremIpsum(number)
        elif functionname == FUNCTIONNAME_CHR:
            if CheckFunction(functionname, arguments, 1, 2):
                return None
            number = CheckNumber(arguments[0], minimum=0, maximum=255)
            if number is None:
                return None
            if len(arguments) == 1:
                decoded += chr(number)
            else:
                number2 = CheckNumber(arguments[1], minimum=0, maximum=255)
                if number2 is None:
                    return None
                if number < number2:
                    decoded += "".join([chr(n) for n in range(number, number2 + 1)])
                else:
                    decoded += "".join([chr(n) for n in range(number, number2 - 1, -1)])
        else:
            print("Error: unknown function: %s" % functionname)
            return None
    return decoded


def FilenameCheckHash(filename, literalfilename):
    if literalfilename:
        return FCH_FILENAME, filename
    elif filename.startswith("#h#"):
        result = Hex2Bytes(filename[3:])
        if result is None:
            return FCH_ERROR, "hexadecimal"
        else:
            return FCH_DATA, result
    elif filename.startswith("#b#"):
        try:
            return FCH_DATA, binascii.a2b_base64(filename[3:])
        except Exception:
            return FCH_ERROR, "base64"
    elif filename.startswith("#e#"):
        result = Interpret(filename[3:])
        if result is None:
            return FCH_ERROR, "expression"
        else:
            return FCH_DATA, result
    elif filename.startswith("#"):
        return FCH_DATA, C2BIP3(filename[1:])
    else:
        return FCH_FILENAME, filename


class cBinaryFile:
    def __init__(self, file):
        self.file = file
        if file == "":
            self.infile = sys.stdin
        elif file.lower().startswith("http://") or file.lower().startswith("https://"):
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
            except Exception:
                print("Error opening file %s" % file)
                print(sys.exc_info()[1])
                sys.exit()
        else:
            try:
                self.infile = open(file, "rb")
            except Exception:
                print("Error opening file %s" % file)
                print(sys.exc_info()[1])
                sys.exit()
        self.ungetted = []

    def byte(self):
        if len(self.ungetted) != 0:
            return self.ungetted.pop()
        inbyte = self.infile.read(1)
        if not inbyte or inbyte == "":
            self.infile.close()
            return None
        return ord(inbyte)

    def bytes(self, size):
        if size <= len(self.ungetted):
            result = self.ungetted[0:size]
            del self.ungetted[0:size]
            return result
        inbytes = self.infile.read(size - len(self.ungetted))
        if inbytes == "":
            self.infile.close()
        if isinstance(inbytes, str):
            result = self.ungetted + [ord(b) for b in inbytes]
        else:
            result = self.ungetted + [b for b in inbytes]
        self.ungetted = []
        return result

    def unget(self, byte):
        self.ungetted.append(byte)

    def ungets(self, bytes):
        bytes.reverse()
        self.ungetted.extend(bytes)


class cPDFDate:
    def __init__(self):
        self.state = 0

    def parse(self, char):
        if char == "D":
            self.state = 1
            return None
        elif self.state == 1:
            if char == ":":
                self.state = 2
                self.digits1 = ""
            else:
                self.state = 0
            return None
        elif self.state == 2:
            if len(self.digits1) < 14:
                if char >= "0" and char <= "9":
                    self.digits1 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif char == "+" or char == "-" or char == "Z":
                self.state = 3
                self.digits2 = ""
                self.TZ = char
                return None
            elif char == '"':
                self.state = 0
                self.date = "D:" + self.digits1
                return self.date
            elif char < "0" or char > "9":
                self.state = 0
                self.date = "D:" + self.digits1
                return self.date
            else:
                self.state = 0
                return None
        elif self.state == 3:
            if len(self.digits2) < 2:
                if char >= "0" and char <= "9":
                    self.digits2 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif len(self.digits2) == 2:
                if char == "'":
                    self.digits2 += char
                    return None
                else:
                    self.state = 0
                    return None
            elif len(self.digits2) < 5:
                if char >= "0" and char <= "9":
                    self.digits2 += char
                    if len(self.digits2) == 5:
                        self.state = 0
                        self.date = "D:" + self.digits1 + self.TZ + self.digits2
                        return self.date
                    else:
                        return None
                else:
                    self.state = 0
                    return None


def fEntropy(countByte, countTotal):
    x = float(countByte) / countTotal
    if x > 0:
        return -x * math.log(x, 2)
    else:
        return 0.0


class cEntropy:
    def __init__(self):
        self.allBucket = [0 for i in range(256)]
        self.streamBucket = [0 for i in range(256)]

    def add(self, byte, insideStream):
        self.allBucket[byte] += 1
        if insideStream:
            self.streamBucket[byte] += 1

    def removeInsideStream(self, byte):
        if self.streamBucket[byte] > 0:
            self.streamBucket[byte] -= 1

    def calc(self):
        self.nonStreamBucket = map(operator.sub, self.allBucket, self.streamBucket)
        allCount = sum(self.allBucket)
        streamCount = sum(self.streamBucket)
        nonStreamCount = sum(self.nonStreamBucket)
        if streamCount == 0:
            return (
                allCount,
                sum(map(lambda x: fEntropy(x, allCount), self.allBucket)),
                streamCount,
                None,
                nonStreamCount,
                sum(map(lambda x: fEntropy(x, nonStreamCount), self.nonStreamBucket)),
            )
        else:
            return (
                allCount,
                sum(map(lambda x: fEntropy(x, allCount), self.allBucket)),
                streamCount,
                sum(map(lambda x: fEntropy(x, streamCount), self.streamBucket)),
                nonStreamCount,
                sum(map(lambda x: fEntropy(x, nonStreamCount), self.nonStreamBucket)),
            )


class cPDFEOF:
    def __init__(self):
        self.token = ""
        self.cntEOFs = 0

    def parse(self, char):
        if self.cntEOFs > 0:
            self.cntCharsAfterLastEOF += 1
        if self.token == "" and char == "%":
            self.token += char
            return
        elif self.token == "%" and char == "%":
            self.token += char
            return
        elif self.token == "%%" and char == "E":
            self.token += char
            return
        elif self.token == "%%E" and char == "O":
            self.token += char
            return
        elif self.token == "%%EO" and char == "F":
            self.token += char
            return
        elif self.token == "%%EOF" and (char == "\n" or char == "\r" or char == " " or char == "\t"):
            self.cntEOFs += 1
            self.cntCharsAfterLastEOF = 0
            if char == "\n":
                self.token = ""
            else:
                self.token += char
            return
        elif self.token == "%%EOF\r":
            if char == "\n":
                self.cntCharsAfterLastEOF = 0
            self.token = ""
        else:
            self.token = ""


def FindPDFHeaderRelaxed(oBinaryFile):
    bytes = oBinaryFile.bytes(1024)
    index = "".join([chr(byte) for byte in bytes]).find("%PDF")
    if index == -1:
        oBinaryFile.ungets(bytes)
        return ([], None)
    for endHeader in range(index + 4, index + 4 + 10):
        if bytes[endHeader] == 10 or bytes[endHeader] == 13:
            break
    oBinaryFile.ungets(bytes[endHeader:])
    return (bytes[0:endHeader], "".join([chr(byte) for byte in bytes[index:endHeader]]))


def Hexcode2String(char):
    if isinstance(char, int):
        return "#%02x" % char
    else:
        return char


def SwapCase(char):
    if isinstance(char, int):
        return ord(chr(char).swapcase())
    else:
        return char.swapcase()


def HexcodeName2String(hexcodeName):
    return "".join(map(Hexcode2String, hexcodeName))


def SwapName(wordExact):
    return map(SwapCase, wordExact)


def UpdateWords(word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut):
    if word != "":
        if slash + word in words:
            words[slash + word][0] += 1
            if hexcode:
                words[slash + word][1] += 1
        elif slash == "/" and allNames:
            words[slash + word] = [1, 0]
            if hexcode:
                words[slash + word][1] += 1
        if slash == "/":
            lastName = slash + word
        if slash == "":
            if word == "stream":
                insideStream = True
            if word == "endstream":
                if insideStream and oEntropy is not None:
                    for char in "endstream":
                        oEntropy.removeInsideStream(ord(char))
                insideStream = False
        if fOut is not None:
            if slash == "/" and "/" + word in ("/JS", "/JavaScript", "/AA", "/OpenAction", "/JBIG2Decode", "/RichMedia", "/Launch"):
                wordExactSwapped = HexcodeName2String(SwapName(wordExact))
                fOut.write(C2BIP3(wordExactSwapped))
                print("/%s -> /%s" % (HexcodeName2String(wordExact), wordExactSwapped))
            else:
                fOut.write(C2BIP3(HexcodeName2String(wordExact)))
    return ("", [], False, lastName, insideStream)


class cCVE_2009_3459:
    def __init__(self):
        self.count = 0

    def Check(self, lastName, word):
        # decided to alert when the number of colors is expressed with more than 3 bytes
        if lastName == "/Colors" and word.isdigit() and int(word) > 2**24:
            self.count += 1


def XMLAddAttribute(xmlDoc, name, value=None):
    att = xmlDoc.createAttribute(name)
    xmlDoc.documentElement.setAttributeNode(att)
    if value is not None:
        att.nodeValue = value
    return att


def GetScriptPath():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    else:
        return os.path.dirname(sys.argv[0])


def ParseINIFile():
    oConfigParser = ConfigParser.ConfigParser(allow_no_value=True)
    oConfigParser.optionxform = str
    oConfigParser.read(os.path.join(GetScriptPath(), "pdfid.ini"))
    keywords = []
    if oConfigParser.has_section("keywords"):
        for key, value in oConfigParser.items("keywords"):
            if key not in keywords:
                keywords.append(key)
    return keywords


def PDFiD(file, allNames=False, extraData=False, disarm=False, force=False):
    """Example of XML output:
    <PDFiD ErrorOccured="False" ErrorMessage="" Filename="test.pdf" Header="%PDF-1.1" IsPDF="True" Version="0.0.4" Entropy="4.28">
            <Keywords>
                    <Keyword Count="7" HexcodeCount="0" Name="obj"/>
                    <Keyword Count="7" HexcodeCount="0" Name="endobj"/>
                    <Keyword Count="1" HexcodeCount="0" Name="stream"/>
                    <Keyword Count="1" HexcodeCount="0" Name="endstream"/>
                    <Keyword Count="1" HexcodeCount="0" Name="xref"/>
                    <Keyword Count="1" HexcodeCount="0" Name="trailer"/>
                    <Keyword Count="1" HexcodeCount="0" Name="startxref"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/Page"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/Encrypt"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/JS"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/JavaScript"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/AA"/>
                    <Keyword Count="1" HexcodeCount="0" Name="/OpenAction"/>
                    <Keyword Count="0" HexcodeCount="0" Name="/JBIG2Decode"/>
            </Keywords>
            <Dates>
                    <Date Value="D:20090128132916+01'00" Name="/ModDate"/>
            </Dates>
    </PDFiD>
    """

    word = ""
    wordExact = []
    hexcode = False
    lastName = ""
    insideStream = False
    keywords = [
        "obj",
        "endobj",
        "stream",
        "endstream",
        "xref",
        "trailer",
        "startxref",
        "/Page",
        "/Encrypt",
        "/ObjStm",
        "/JS",
        "/JavaScript",
        "/AA",
        "/OpenAction",
        "/AcroForm",
        "/JBIG2Decode",
        "/RichMedia",
        "/Launch",
        "/EmbeddedFile",
        "/XFA",
    ]
    words = {}
    dates = []
    for extrakeyword in ParseINIFile():
        if extrakeyword not in keywords:
            keywords.append(extrakeyword)
    for keyword in keywords:
        words[keyword] = [0, 0]
    slash = ""
    xmlDoc = xml.dom.minidom.getDOMImplementation().createDocument(None, "PDFiD", None)
    XMLAddAttribute(xmlDoc, "Version", __version__)
    XMLAddAttribute(xmlDoc, "Filename", file)
    attErrorOccured = XMLAddAttribute(xmlDoc, "ErrorOccured", "False")
    attErrorMessage = XMLAddAttribute(xmlDoc, "ErrorMessage", "")

    oPDFDate = None
    oEntropy = None
    oPDFEOF = None
    oCVE_2009_3459 = cCVE_2009_3459()
    try:
        attIsPDF = xmlDoc.createAttribute("IsPDF")
        xmlDoc.documentElement.setAttributeNode(attIsPDF)
        oBinaryFile = cBinaryFile(file)
        if extraData:
            oPDFDate = cPDFDate()
            oEntropy = cEntropy()
            oPDFEOF = cPDFEOF()
        (bytesHeader, pdfHeader) = FindPDFHeaderRelaxed(oBinaryFile)
        if disarm:
            (pathfile, extension) = os.path.splitext(file)
            fOut = open(pathfile + ".disarmed" + extension, "wb")
            for byteHeader in bytesHeader:
                fOut.write(C2BIP3(chr(byteHeader)))
        else:
            fOut = None
        if oEntropy is not None:
            for byteHeader in bytesHeader:
                oEntropy.add(byteHeader, insideStream)
        if pdfHeader is None and not force:
            attIsPDF.nodeValue = "False"
            return xmlDoc
        else:
            if pdfHeader is None:
                attIsPDF.nodeValue = "False"
                pdfHeader = ""
            else:
                attIsPDF.nodeValue = "True"
            att = xmlDoc.createAttribute("Header")
            att.nodeValue = repr(pdfHeader[0:10]).strip("'")
            xmlDoc.documentElement.setAttributeNode(att)
        byte = oBinaryFile.byte()
        while byte is not None:
            char = chr(byte)
            charUpper = char.upper()
            if charUpper >= "A" and charUpper <= "Z" or charUpper >= "0" and charUpper <= "9":
                word += char
                wordExact.append(char)
            elif slash == "/" and char == "#":
                d1 = oBinaryFile.byte()
                if d1 is not None:
                    d2 = oBinaryFile.byte()
                    if (
                        d2 is not None
                        and (chr(d1) >= "0" and chr(d1) <= "9" or chr(d1).upper() >= "A" and chr(d1).upper() <= "F")
                        and (chr(d2) >= "0" and chr(d2) <= "9" or chr(d2).upper() >= "A" and chr(d2).upper() <= "F")
                    ):
                        word += chr(int(chr(d1) + chr(d2), 16))
                        wordExact.append(int(chr(d1) + chr(d2), 16))
                        hexcode = True
                        if oEntropy is not None:
                            oEntropy.add(d1, insideStream)
                            oEntropy.add(d2, insideStream)
                        if oPDFEOF is not None:
                            oPDFEOF.parse(d1)
                            oPDFEOF.parse(d2)
                    else:
                        oBinaryFile.unget(d2)
                        oBinaryFile.unget(d1)
                        (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(
                            word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut
                        )
                        if disarm:
                            fOut.write(C2BIP3(char))
                else:
                    oBinaryFile.unget(d1)
                    (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(
                        word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut
                    )
                    if disarm:
                        fOut.write(C2BIP3(char))
            else:
                oCVE_2009_3459.Check(lastName, word)

                (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(
                    word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut
                )
                if char == "/":
                    slash = "/"
                else:
                    slash = ""
                if disarm:
                    fOut.write(C2BIP3(char))

            if oPDFDate is not None and oPDFDate.parse(char) is not None:
                dates.append([oPDFDate.date, lastName])

            if oEntropy is not None:
                oEntropy.add(byte, insideStream)

            if oPDFEOF is not None:
                oPDFEOF.parse(char)

            byte = oBinaryFile.byte()
        (word, wordExact, hexcode, lastName, insideStream) = UpdateWords(
            word, wordExact, slash, words, hexcode, allNames, lastName, insideStream, oEntropy, fOut
        )

        # check to see if file ended with %%EOF.  If so, we can reset charsAfterLastEOF and add one to EOF count.  This is never performed in
        # the parse function because it never gets called due to hitting the end of file.
        if byte is None and oPDFEOF is not None:
            if oPDFEOF.token == "%%EOF":
                oPDFEOF.cntEOFs += 1
                oPDFEOF.cntCharsAfterLastEOF = 0
                oPDFEOF.token = ""

    except SystemExit:
        sys.exit()
    except Exception:
        attErrorOccured.nodeValue = "True"
        attErrorMessage.nodeValue = traceback.format_exc()

    if disarm:
        fOut.close()

    attEntropyAll = xmlDoc.createAttribute("TotalEntropy")
    xmlDoc.documentElement.setAttributeNode(attEntropyAll)
    attCountAll = xmlDoc.createAttribute("TotalCount")
    xmlDoc.documentElement.setAttributeNode(attCountAll)
    attEntropyStream = xmlDoc.createAttribute("StreamEntropy")
    xmlDoc.documentElement.setAttributeNode(attEntropyStream)
    attCountStream = xmlDoc.createAttribute("StreamCount")
    xmlDoc.documentElement.setAttributeNode(attCountStream)
    attEntropyNonStream = xmlDoc.createAttribute("NonStreamEntropy")
    xmlDoc.documentElement.setAttributeNode(attEntropyNonStream)
    attCountNonStream = xmlDoc.createAttribute("NonStreamCount")
    xmlDoc.documentElement.setAttributeNode(attCountNonStream)
    if oEntropy is not None:
        (countAll, entropyAll, countStream, entropyStream, countNonStream, entropyNonStream) = oEntropy.calc()
        attEntropyAll.nodeValue = "%f" % entropyAll
        attCountAll.nodeValue = "%d" % countAll
        if entropyStream is None:
            attEntropyStream.nodeValue = "N/A     "
        else:
            attEntropyStream.nodeValue = "%f" % entropyStream
        attCountStream.nodeValue = "%d" % countStream
        attEntropyNonStream.nodeValue = "%f" % entropyNonStream
        attCountNonStream.nodeValue = "%d" % countNonStream
    else:
        attEntropyAll.nodeValue = ""
        attCountAll.nodeValue = ""
        attEntropyStream.nodeValue = ""
        attCountStream.nodeValue = ""
        attEntropyNonStream.nodeValue = ""
        attCountNonStream.nodeValue = ""
    attCountEOF = xmlDoc.createAttribute("CountEOF")
    xmlDoc.documentElement.setAttributeNode(attCountEOF)
    attCountCharsAfterLastEOF = xmlDoc.createAttribute("CountCharsAfterLastEOF")
    xmlDoc.documentElement.setAttributeNode(attCountCharsAfterLastEOF)
    if oPDFEOF is not None:
        attCountEOF.nodeValue = "%d" % oPDFEOF.cntEOFs
        if oPDFEOF.cntEOFs > 0:
            attCountCharsAfterLastEOF.nodeValue = "%d" % oPDFEOF.cntCharsAfterLastEOF
        else:
            attCountCharsAfterLastEOF.nodeValue = ""
    else:
        attCountEOF.nodeValue = ""
        attCountCharsAfterLastEOF.nodeValue = ""

    eleKeywords = xmlDoc.createElement("Keywords")
    xmlDoc.documentElement.appendChild(eleKeywords)
    for keyword in keywords:
        eleKeyword = xmlDoc.createElement("Keyword")
        eleKeywords.appendChild(eleKeyword)
        att = xmlDoc.createAttribute("Name")
        att.nodeValue = keyword
        eleKeyword.setAttributeNode(att)
        att = xmlDoc.createAttribute("Count")
        att.nodeValue = str(words[keyword][0])
        eleKeyword.setAttributeNode(att)
        att = xmlDoc.createAttribute("HexcodeCount")
        att.nodeValue = str(words[keyword][1])
        eleKeyword.setAttributeNode(att)
    eleKeyword = xmlDoc.createElement("Keyword")
    eleKeywords.appendChild(eleKeyword)
    att = xmlDoc.createAttribute("Name")
    att.nodeValue = "/Colors > 2^24"
    eleKeyword.setAttributeNode(att)
    att = xmlDoc.createAttribute("Count")
    att.nodeValue = str(oCVE_2009_3459.count)
    eleKeyword.setAttributeNode(att)
    att = xmlDoc.createAttribute("HexcodeCount")
    att.nodeValue = str(0)
    eleKeyword.setAttributeNode(att)
    if allNames:
        keys = sorted(words.keys())
        for word in keys:
            if word not in keywords:
                eleKeyword = xmlDoc.createElement("Keyword")
                eleKeywords.appendChild(eleKeyword)
                att = xmlDoc.createAttribute("Name")
                att.nodeValue = word
                eleKeyword.setAttributeNode(att)
                att = xmlDoc.createAttribute("Count")
                att.nodeValue = str(words[word][0])
                eleKeyword.setAttributeNode(att)
                att = xmlDoc.createAttribute("HexcodeCount")
                att.nodeValue = str(words[word][1])
                eleKeyword.setAttributeNode(att)
    eleDates = xmlDoc.createElement("Dates")
    xmlDoc.documentElement.appendChild(eleDates)
    dates.sort(key=lambda x: x[0])
    for date in dates:
        eleDate = xmlDoc.createElement("Date")
        eleDates.appendChild(eleDate)
        att = xmlDoc.createAttribute("Value")
        att.nodeValue = date[0]
        eleDate.setAttributeNode(att)
        att = xmlDoc.createAttribute("Name")
        att.nodeValue = date[1]
        eleDate.setAttributeNode(att)
    return xmlDoc


def PDFiD2String(xmlDoc, nozero, force):
    result = "PDFiD %s %s\n" % (xmlDoc.documentElement.getAttribute("Version"), xmlDoc.documentElement.getAttribute("Filename"))
    if xmlDoc.documentElement.getAttribute("ErrorOccured") == "True":
        return result + "***Error occured***\n%s\n" % xmlDoc.documentElement.getAttribute("ErrorMessage")
    if not force and xmlDoc.documentElement.getAttribute("IsPDF") == "False":
        return result + " Not a PDF document\n"
    result += " PDF Header: %s\n" % xmlDoc.documentElement.getAttribute("Header")
    for node in xmlDoc.documentElement.getElementsByTagName("Keywords")[0].childNodes:
        if not nozero or nozero and int(node.getAttribute("Count")) > 0:
            result += " %-16s %7d" % (node.getAttribute("Name"), int(node.getAttribute("Count")))
            if int(node.getAttribute("HexcodeCount")) > 0:
                result += "(%d)" % int(node.getAttribute("HexcodeCount"))
            result += "\n"
    if xmlDoc.documentElement.getAttribute("CountEOF") != "":
        result += " %-16s %7d\n" % ("%%EOF", int(xmlDoc.documentElement.getAttribute("CountEOF")))
    if xmlDoc.documentElement.getAttribute("CountCharsAfterLastEOF") != "":
        result += " %-16s %7d\n" % ("After last %%EOF", int(xmlDoc.documentElement.getAttribute("CountCharsAfterLastEOF")))
    for node in xmlDoc.documentElement.getElementsByTagName("Dates")[0].childNodes:
        result += " %-23s %s\n" % (node.getAttribute("Value"), node.getAttribute("Name"))
    if xmlDoc.documentElement.getAttribute("TotalEntropy") != "":
        result += " Total entropy:           %s (%10s bytes)\n" % (
            xmlDoc.documentElement.getAttribute("TotalEntropy"),
            xmlDoc.documentElement.getAttribute("TotalCount"),
        )
    if xmlDoc.documentElement.getAttribute("StreamEntropy") != "":
        result += " Entropy inside streams:  %s (%10s bytes)\n" % (
            xmlDoc.documentElement.getAttribute("StreamEntropy"),
            xmlDoc.documentElement.getAttribute("StreamCount"),
        )
    if xmlDoc.documentElement.getAttribute("NonStreamEntropy") != "":
        result += " Entropy outside streams: %s (%10s bytes)\n" % (
            xmlDoc.documentElement.getAttribute("NonStreamEntropy"),
            xmlDoc.documentElement.getAttribute("NonStreamCount"),
        )
    return result


class cCount:
    def __init__(self, count, hexcode):
        self.count = count
        self.hexcode = hexcode


class cPDFiD:
    def __init__(self, xmlDoc, force):
        self.version = xmlDoc.documentElement.getAttribute("Version")
        self.filename = xmlDoc.documentElement.getAttribute("Filename")
        self.errorOccured = xmlDoc.documentElement.getAttribute("ErrorOccured") == "True"
        self.errorMessage = xmlDoc.documentElement.getAttribute("ErrorMessage")
        self.isPDF = None
        if self.errorOccured:
            return
        self.isPDF = xmlDoc.documentElement.getAttribute("IsPDF") == "True"
        if not force and not self.isPDF:
            return
        self.header = xmlDoc.documentElement.getAttribute("Header")
        self.keywords = {}
        for node in xmlDoc.documentElement.getElementsByTagName("Keywords")[0].childNodes:
            self.keywords[node.getAttribute("Name")] = cCount(
                int(node.getAttribute("Count")), int(node.getAttribute("HexcodeCount"))
            )
        self.obj = self.keywords["obj"]
        self.endobj = self.keywords["endobj"]
        self.stream = self.keywords["stream"]
        self.endstream = self.keywords["endstream"]
        self.xref = self.keywords["xref"]
        self.trailer = self.keywords["trailer"]
        self.startxref = self.keywords["startxref"]
        self.page = self.keywords["/Page"]
        self.encrypt = self.keywords["/Encrypt"]
        self.objstm = self.keywords["/ObjStm"]
        self.js = self.keywords["/JS"]
        self.javascript = self.keywords["/JavaScript"]
        self.aa = self.keywords["/AA"]
        self.openaction = self.keywords["/OpenAction"]
        self.acroform = self.keywords["/AcroForm"]
        self.jbig2decode = self.keywords["/JBIG2Decode"]
        self.richmedia = self.keywords["/RichMedia"]
        self.launch = self.keywords["/Launch"]
        self.embeddedfile = self.keywords["/EmbeddedFile"]
        self.xfa = self.keywords["/XFA"]
        self.colors_gt_2_24 = self.keywords["/Colors > 2^24"]


def Print(lines, options):
    print(lines)
    filename = None
    if options.scan:
        filename = "PDFiD.log"
    if options.output != "":
        filename = options.output
    if filename:
        logfile = open(filename, "a")
        logfile.write(lines + "\n")
        logfile.close()


def Quote(value, separator, quote):
    if isinstance(value, str):
        if separator in value:
            return quote + value + quote
    return value


def MakeCSVLine(fields, separator=";", quote='"'):
    formatstring = separator.join([field[0] for field in fields])
    strings = [Quote(field[1], separator, quote) for field in fields]
    return formatstring % tuple(strings)


def ProcessFile(filename, options, plugins):
    xmlDoc = PDFiD(filename, options.all, options.extra, options.disarm, options.force)
    if plugins == [] and options.select == "":
        Print(PDFiD2String(xmlDoc, options.nozero, options.force), options)
        return

    oPDFiD = cPDFiD(xmlDoc, options.force)
    if options.select:
        if options.force or not oPDFiD.errorOccured and oPDFiD.isPDF:
            try:
                selected = eval(options.select)
            except Exception as e:
                Print("Error evaluating select expression: %s" % options.select, options)
                if options.verbose:
                    raise e
                return
            if selected:
                if options.csv:
                    Print(filename, options)
                else:
                    Print(PDFiD2String(xmlDoc, options.nozero, options.force), options)
    else:
        for cPlugin in plugins:
            if not cPlugin.onlyValidPDF or not oPDFiD.errorOccured and oPDFiD.isPDF:
                try:
                    oPlugin = cPlugin(oPDFiD, options.pluginoptions)
                except Exception as e:
                    Print("Error instantiating plugin: %s" % cPlugin.name, options)
                    if options.verbose:
                        raise e
                    return

                try:
                    score = oPlugin.Score()
                except Exception as e:
                    Print("Error running plugin: %s" % cPlugin.name, options)
                    if options.verbose:
                        raise e
                    return

                if options.csv:
                    if score >= options.minimumscore:
                        Print(MakeCSVLine((("%s", filename), ("%s", cPlugin.name), ("%.02f", score))), options)
                else:
                    if score >= options.minimumscore:
                        Print(PDFiD2String(xmlDoc, options.nozero, options.force), options)
                        Print("%s score:        %.02f" % (cPlugin.name, score), options)
                        try:
                            Print("%s instructions: %s" % (cPlugin.name, oPlugin.Instructions(score)), options)
                        except AttributeError:
                            pass
            else:
                if options.csv:
                    if oPDFiD.errorOccured:
                        Print(MakeCSVLine((("%s", filename), ("%s", cPlugin.name), ("%s", "Error occured"))), options)
                    if not oPDFiD.isPDF:
                        Print(MakeCSVLine((("%s", filename), ("%s", cPlugin.name), ("%s", "Not a PDF document"))), options)
                else:
                    Print(PDFiD2String(xmlDoc, options.nozero, options.force), options)


def Scan(directory, options, plugins):
    try:
        if os.path.isdir(directory):
            for entry in os.listdir(directory):
                Scan(os.path.join(directory, entry), options, plugins)
        else:
            ProcessFile(directory, options, plugins)
    except Exception as e:
        #        print directory
        print(e)


#        print(sys.exc_info()[2])
#        print traceback.format_exc()

# function derived from: http://blog.9bplus.com/pdfidpy-output-to-json


def PDFiD2JSON(xmlDoc, force):
    # Get Top Layer Data
    errorOccured = xmlDoc.documentElement.getAttribute("ErrorOccured")
    errorMessage = xmlDoc.documentElement.getAttribute("ErrorMessage")
    filename = xmlDoc.documentElement.getAttribute("Filename")
    header = xmlDoc.documentElement.getAttribute("Header")
    isPdf = xmlDoc.documentElement.getAttribute("IsPDF")
    version = xmlDoc.documentElement.getAttribute("Version")
    entropy = xmlDoc.documentElement.getAttribute("Entropy")

    # extra data
    countEof = xmlDoc.documentElement.getAttribute("CountEOF")
    countChatAfterLastEof = xmlDoc.documentElement.getAttribute("CountCharsAfterLastEOF")
    totalEntropy = xmlDoc.documentElement.getAttribute("TotalEntropy")
    streamEntropy = xmlDoc.documentElement.getAttribute("StreamEntropy")
    nonStreamEntropy = xmlDoc.documentElement.getAttribute("NonStreamEntropy")

    keywords = []
    dates = []

    # grab all keywords
    for node in xmlDoc.documentElement.getElementsByTagName("Keywords")[0].childNodes:
        name = node.getAttribute("Name")
        count = int(node.getAttribute("Count"))
        if int(node.getAttribute("HexcodeCount")) > 0:
            hexCount = int(node.getAttribute("HexcodeCount"))
        else:
            hexCount = 0
        keyword = {"count": count, "hexcodecount": hexCount, "name": name}
        keywords.append(keyword)

    # grab all date information
    for node in xmlDoc.documentElement.getElementsByTagName("Dates")[0].childNodes:
        name = node.getAttribute("Name")
        value = node.getAttribute("Value")
        date = {"name": name, "value": value}
        dates.append(date)

    data = {
        "countEof": countEof,
        "countChatAfterLastEof": countChatAfterLastEof,
        "totalEntropy": totalEntropy,
        "streamEntropy": streamEntropy,
        "nonStreamEntropy": nonStreamEntropy,
        "errorOccured": errorOccured,
        "errorMessage": errorMessage,
        "filename": filename,
        "header": header,
        "isPdf": isPdf,
        "version": version,
        "entropy": entropy,
        "keywords": {"keyword": keywords},
        "dates": {"date": dates},
    }
    complete = [{"pdfid": data}]
    result = json.dumps(complete)
    return result


def File2Strings(filename):
    try:
        f = open(filename, "r")
    except Exception:
        return None
    try:
        return list(map(lambda line: line.rstrip("\n"), f.readlines()))
    except Exception:
        return None
    finally:
        f.close()


def ProcessAt(argument):
    if argument.startswith("@"):
        strings = File2Strings(argument[1:])
        if strings is None:
            raise Exception("Error reading %s" % argument)
        else:
            return strings
    else:
        return [argument]


def AddPlugin(cClass):
    global plugins

    plugins.append(cClass)


class cExpandFilenameArguments:
    def __init__(self, filenames, literalfilenames=False, recursedir=False, checkfilenames=False, expressionprefix=None):
        self.containsUnixShellStyleWildcards = False
        self.warning = False
        self.message = ""
        self.filenameexpressions = []
        self.expressionprefix = expressionprefix
        self.literalfilenames = literalfilenames

        expression = ""
        if len(filenames) == 0:
            self.filenameexpressions = [["", ""]]
        elif literalfilenames:
            self.filenameexpressions = [[filename, ""] for filename in filenames]
        elif recursedir:
            for dirwildcard in filenames:
                if expressionprefix is not None and dirwildcard.startswith(expressionprefix):
                    expression = dirwildcard[len(expressionprefix) :]
                else:
                    if dirwildcard.startswith("@"):
                        for filename in ProcessAt(dirwildcard):
                            self.filenameexpressions.append([filename, expression])
                    elif os.path.isfile(dirwildcard):
                        self.filenameexpressions.append([dirwildcard, expression])
                    else:
                        if os.path.isdir(dirwildcard):
                            dirname = dirwildcard
                            basename = "*"
                        else:
                            dirname, basename = os.path.split(dirwildcard)
                            if dirname == "":
                                dirname = "."
                        for path, dirs, files in os.walk(dirname):
                            for filename in fnmatch.filter(files, basename):
                                self.filenameexpressions.append([os.path.join(path, filename), expression])
        else:
            for filename in list(collections.OrderedDict.fromkeys(sum(map(self.Glob, sum(map(ProcessAt, filenames), [])), []))):
                if expressionprefix is not None and filename.startswith(expressionprefix):
                    expression = filename[len(expressionprefix) :]
                else:
                    self.filenameexpressions.append([filename, expression])
            self.warning = self.containsUnixShellStyleWildcards and len(self.filenameexpressions) == 0
            if self.warning:
                self.message = "Your filename argument(s) contain Unix shell-style wildcards, but no files were matched.\nCheck your wildcard patterns or use option literalfilenames if you don't want wildcard pattern matching."
                return
        if self.filenameexpressions == [] and expression != "":
            self.filenameexpressions = [["", expression]]
        if checkfilenames:
            self.CheckIfFilesAreValid()

    def Glob(self, filename):
        if not ("?" in filename or "*" in filename or ("[" in filename and "]" in filename)):
            return [filename]
        self.containsUnixShellStyleWildcards = True
        return glob.glob(filename)

    def CheckIfFilesAreValid(self):
        valid = []
        doesnotexist = []
        isnotafile = []
        for filename, expression in self.filenameexpressions:
            hashfile = False
            # Not declared ROFL

            try:
                hashfile = FilenameCheckHash(filename, self.literalfilenames)[0] == FCH_DATA
            except Exception as e:
                print(e)

            if filename == "" or hashfile:
                valid.append([filename, expression])
            elif not os.path.exists(filename):
                doesnotexist.append(filename)
            elif not os.path.isfile(filename):
                isnotafile.append(filename)
            else:
                valid.append([filename, expression])
        self.filenameexpressions = valid
        if len(doesnotexist) > 0:
            self.warning = True
            self.message += "The following files do not exist and will be skipped: " + " ".join(doesnotexist) + "\n"
        if len(isnotafile) > 0:
            self.warning = True
            self.message += "The following files are not regular files and will be skipped: " + " ".join(isnotafile) + "\n"

    def Filenames(self):
        if self.expressionprefix is None:
            return [filename for filename, expression in self.filenameexpressions]
        else:
            return self.filenameexpressions


class cPluginParent:
    onlyValidPDF = True


def LoadPlugins(plugins, verbose):
    if plugins == "":
        return
    scriptPath = GetScriptPath()
    for plugin in sum(map(ProcessAt, plugins.split(",")), []):
        try:
            if not plugin.lower().endswith(".py"):
                plugin += ".py"
            if os.path.dirname(plugin) == "":
                if not os.path.exists(plugin):
                    scriptPlugin = os.path.join(scriptPath, plugin)
                    if os.path.exists(scriptPlugin):
                        plugin = scriptPlugin
            exec(open(plugin, "r").read())
        except Exception as e:
            print("Error loading plugin: %s" % plugin)
            if verbose:
                raise e


def PDFiDMain(filenames, options):
    global plugins
    plugins = []
    LoadPlugins(options.plugins, options.verbose)

    if options.csv:
        if plugins != []:
            Print(MakeCSVLine((("%s", "Filename"), ("%s", "Plugin-name"), ("%s", "Score"))), options)
        elif options.select != "":
            Print("Filename", options)

    for filename in filenames:
        if options.scan:
            Scan(filename, options, plugins)
        else:
            ProcessFile(filename, options, plugins)


def Main():
    moredesc = """

Arguments:
pdf-file and zip-file can be a single file, several files, and/or @file
@file: run PDFiD on each file listed in the text file specified
wildcards are supported

Source code put in the public domain by Didier Stevens, no Copyright
Use at your own risk
https://DidierStevens.com"""

    oParser = optparse.OptionParser(
        usage="usage: %prog [options] [pdf-file|zip-file|url|@file] ...\n" + __description__ + moredesc,
        version="%prog " + __version__,
    )
    oParser.add_option("-s", "--scan", action="store_true", default=False, help="scan the given directory")
    oParser.add_option("-a", "--all", action="store_true", default=False, help="display all the names")
    oParser.add_option("-e", "--extra", action="store_true", default=False, help="display extra data, like dates")
    oParser.add_option(
        "-f", "--force", action="store_true", default=False, help="force the scan of the file, even without proper %PDF header"
    )
    oParser.add_option("-d", "--disarm", action="store_true", default=False, help="disable JavaScript and auto launch")
    oParser.add_option(
        "-p", "--plugins", type=str, default="", help="plugins to load (separate plugins with a comma , ; @file supported)"
    )
    oParser.add_option("-c", "--csv", action="store_true", default=False, help="output csv data when using plugins")
    oParser.add_option("-m", "--minimumscore", type=float, default=0.0, help="minimum score for plugin results output")
    oParser.add_option("-v", "--verbose", action="store_true", default=False, help="verbose (will also raise catched exceptions)")
    oParser.add_option("-S", "--select", type=str, default="", help="selection expression")
    oParser.add_option("-n", "--nozero", action="store_true", default=False, help="supress output for counts equal to zero")
    oParser.add_option("-o", "--output", type=str, default="", help="output to log file")
    oParser.add_option("--pluginoptions", type=str, default="", help="options for the plugin")
    oParser.add_option(
        "-l", "--literalfilenames", action="store_true", default=False, help="take filenames literally, no wildcard matching"
    )
    oParser.add_option(
        "--recursedir", action="store_true", default=False, help="Recurse directories (wildcards and here files (@...) allowed)"
    )
    (options, args) = oParser.parse_args()

    if len(args) == 0:
        if options.disarm:
            print("Option disarm not supported with stdin")
            options.disarm = False
        if options.scan:
            print("Option scan not supported with stdin")
            options.scan = False
        filenames = [""]
    else:
        try:
            oExpandFilenameArguments = cExpandFilenameArguments(args, options.literalfilenames, options.recursedir, False)
            filenames = oExpandFilenameArguments.Filenames()
            if oExpandFilenameArguments.warning:
                print(oExpandFilenameArguments.message)
        except Exception as e:
            print(e)
            return
    PDFiDMain(filenames, options)


if __name__ == "__main__":
    Main()
