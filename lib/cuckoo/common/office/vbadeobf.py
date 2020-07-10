# Copyright (C) 2010-2015 Cuckoo Foundation, KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import string
from six.moves import zip

try:
    import re2 as re
except ImportError:
    import re

from itertools import chain, repeat
from lib.cuckoo.common.utils import convert_to_printable
from os.path import exists

# Regexs from Decalages olevba.py + a commonly observed path regex.
PATTERNS = (
    ("URL", re.compile(r"(http|https|ftp)\://[a-zA-Z0-9\-\.]+(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\-\._\?\,/\\\+&amp;%\$#\=~])*[^\.\,\)\(\'\s]")),
    (
        "IPv4 address",
        re.compile(r"\b(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\b"),
    ),
    ("E-mail address", re.compile(r"(?i)\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+(?:[A-Z]{2,12}|XN--[A-Z0-9]{4,18})\b")),
    (
        "Executable file name",
        re.compile(
            r"(?i)\b\w+\.(EXE|PIF|GADGET|MSI|MSP|MSC|VB|VBS|JS|VBE|JSE|WS|WSF|WSC|WSH|BAT|CMD|DLL|SCR|HTA|CPL|CLASS|JAR|PS1|PS1XML|PS2|PS2XML|PSC1|PSC2|SCF|LNK|INF|REG)\b"
        ),
    ),
    ("User Directory", re.compile(r"['\"][Cc]:\\.*Users+[^;].*['\"]")),
)

DECRYPTORS = {}


def is_printable(s):
    return all(c in string.printable for c in s)


def filter_printable(s):
    return "".join(c for c in s if c in string.printable)


def repeating_xor(s, key):
    repeating_key = chain.from_iterable(repeat(key))
    return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(s, repeating_key))


def quote(f):
    return lambda *args: '"""' + f(*args) + '"""'


def decrypt(enc_type):
    def wrapper(f):
        DECRYPTORS[enc_type] = f
        return f

    return wrapper


def normalize_code(macro):
    macro = re.sub(r"_\s*\n", " ", macro)  # Remove underscore line continuation.
    return macro


@quote
def decode_chr(m):
    ascii = re.findall(r"Chr[A-Z$]?\((\d+)\)", m.group(1))
    return "".join(chr(int(n)) for n in ascii)


@quote
def decode_base64(m):
    s = m.group(1)
    if (len(s) % 4 != 0 and not s.endswith("=")) or ("=" in s.rstrip("=")):
        return s

    try:
        decoded = s.decode("base64")
    except:
        return s

    if not is_printable(decoded):
        return s
    return decoded


@quote
def decode_hex(m):
    s = m.group(1)
    if len(s) % 2 != 0:
        return s
    try:
        result = "".join(c for c in s.decode("hex"))
    except Exception as e:
        return ""
    return result


@quote
def decode_reverse(m):
    return m.group(1)[::-1]


@quote
def concatenate(m):
    line = m.group(0)
    return "".join(re.findall(r'"""(.*?)"""', m.group(0)))


@decrypt("xor")
@quote
def decrypt_xor(m):
    return repeating_xor(m.group(1), m.group(2))


@decrypt("sub")
@quote
def decrypt_sub(m):
    try:
        first = int([c for c in m.group(1) if c.isdigit()])
        second = int([c for c in m.group(2) if c.isdigit()])
        if first and second:
            return chr(first - second)
    except:
        pass
    return m.group()


def find_enc_function(macro):
    match, type = re.search(r"(?ims)Public Function (\w+).+? Xor .+?End Function", macro), "xor"
    if not match:
        match, type = re.search(r"(?ims)Public Function (\w+).+?\d+\s*-\s*\d+.+?End Function", macro), "sub"
    return (match.group(1), type) if match else (None, None)


def handle_techniques(line, **opts):

    vb_vars = opts["vb_vars"]
    enc_func_name = opts["enc_func_name"]
    decrypt_func = opts["decrypt_func"]

    def var_substitute(m):
        var = m.group(1)

    line = line.replace('"', '"""')
    line = re.sub(r'"""([A-F0-9]{2,})"""', decode_hex, line)
    line = re.sub(r'"""([\w_+=/]{2,})"""', decode_base64, line)
    line = re.sub(r"(?i)Chr[A-Z$]\(Asc[A-Z$](.+?)\)\)", r"\1", line)
    line = re.sub(r'(?i)Asc[A-Z$]\("""(\w)\w*"""\)', lambda m: ord(m.group(1)), line)
    line = re.sub(r"(?i)((?:Chr[A-Z$]?\(\d+\)\s*&?\s*)+)", decode_chr, line)
    line = re.sub(r'(?i)\b%s\s*\(\w+\("""(.+?)"""\),\s*\w+\("""(.+?)"""' % enc_func_name, decrypt_func, line)
    line = re.sub(r'(?i)\b%s\((?:""")?(.+?)(?:""")?,\s*(?:""")?(.+?)(?:""")?\)' % enc_func_name, decrypt_func, line)
    line = re.sub(r'(?i)StrReverse\(.+?"""(.+?)"""\)', decode_reverse, line)
    line = re.sub(r'""".+?"""\s+&+\s+""".+?""".+', concatenate, line)
    while "Chr(Asc(" in line:
        lastline = line
        line = re.sub(r"(?i)Chr\(Asc\((.+?)\)\)", r"\1", line)
        if line == lastline:
            break
    # Remove quotes before regexing against them.
    line = line.replace('""" + """', "")
    line = line.replace('"""', "")
    # Remove a few concat patterns. Theres a bug with some obfuscation
    # techniques.
    line = line.replace(" + ", "")
    line = line.replace(" & ", "")
    return line


def extract_iocs(s):
    for desc, pattern in PATTERNS:
        m = pattern.findall(s)
        if m:
            # Hacked-up buxfix for multilayer Chr(Asc(Chr(Asc( which can
            # sometimes mess up our quoted string extraction / parsing.
            while "Chr(Asc(" in s:
                lastline = s
                s = re.sub(r"(?i)Chr\(Asc\((.+?)\)\)", r"\1", s)
                if s == lastline:
                    break
            # Return the line matched and not m because I prefer to have
            # context and not simply the IOC. This helps with the executable
            # file IOC, sometimes it's a save location!
            return desc, convert_to_printable(s)
    return None


def parse_macro(macro):
    opts = {}
    vb_vars = {}
    result = {}
    cleaned = ""
    strings = set()
    iocs = []
    macro = normalize_code(macro)

    enc_func_name, enc_type = find_enc_function(macro)
    if not enc_func_name:
        enc_func_name, enc_type = r"xor\w+", "xor"

    decrypt_func = DECRYPTORS.get(enc_type)

    opts = {"enc_func_name": enc_func_name, "decrypt_func": decrypt_func, "vb_vars": vb_vars}

    for line in macro.splitlines():
        line = line.strip()
        if line.startswith("'"):
            continue

        substituted = handle_techniques(line, **opts)
        # Look for variable assignments
        split = [part for part in re.split(r"^(\w+)\s*=\s*", line, maxsplit=1)[1:] if part]

        # Basic variable data find/replace.
        if len(split) == 2:
            name, val = split
            vb_vars[name] = substituted

        # Walk the deobfuscated macro and check for any IOCs
        for string in substituted.splitlines():
            ioc = extract_iocs(string)
            if ioc:
                iocs.append(ioc)

    # Dedup IOCs
    result = sorted(set(iocs), key=lambda p: p[0])

    return result
