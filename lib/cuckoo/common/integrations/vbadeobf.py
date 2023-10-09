# Copyright (C) 2010-2015 Cuckoo Foundation, KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import binascii
import contextlib
import string
from base64 import b64decode
from itertools import chain, repeat
from typing import Callable, List, Tuple

from lib.cuckoo.common.utils import convert_to_printable

try:
    import re2 as re
except ImportError:
    import re

# Regexs from Decalages olevba.py + a commonly observed path regex.
PATTERNS = (
    (
        "URL",
        re.compile(
            r"(http|https|ftp)\://[a-zA-Z0-9\-\.]+(:[a-zA-Z0-9]*)?/?([a-zA-Z0-9\-\._\?\,/\\\+&amp;%\$#\=~])*[^\.\,\)\(\'\s]"
        ),
    ),
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


def is_printable(s: str) -> bool:
    return all(c in string.printable for c in s)


def filter_printable(s: str) -> str:
    return "".join(c for c in s if c in string.printable)


def repeating_xor(s: str, key: str) -> str:
    repeating_key = chain.from_iterable(repeat(key))
    return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(s, repeating_key))


def quote(f: Callable[[re.Match], str]):
    return lambda *args: f'"""{f(*args)}"""'


def decrypt(enc_type: str) -> Callable[[Callable[[re.Match], str]], Callable[[re.Match], str]]:
    def wrapper(f: Callable[[re.Match], str]) -> Callable[[re.Match], str]:
        DECRYPTORS[enc_type] = f
        return f

    return wrapper


def normalize_code(macro: str) -> str:
    return re.sub(r"_\s*\n", " ", macro)  # Remove underscore line continuation.


@quote
def decode_chr(m: re.Match) -> str:
    ascii_chars = re.findall(r"Chr[A-Z$]?\((\d+)\)", m.group(1))
    return "".join(chr(int(n)) for n in ascii_chars)


@quote
def decode_base64(m: re.Match) -> str:
    s = m.group(1)
    if (len(s) % 4 != 0 and not s.endswith("=")) or ("=" in s.rstrip("=")):
        return s

    try:
        decoded = b64decode(s).decode()
    except (binascii.Error, UnicodeDecodeError):
        return s

    if not is_printable(decoded):
        return s
    return decoded


@quote
def decode_hex(m: re.Match) -> str:
    s = m.group(1)
    if len(s) % 2 != 0:
        return s
    try:
        result = "".join(binascii.unhexlify(s))
    except Exception:
        return ""
    return result


@quote
def decode_reverse(m: re.Match) -> str:
    return m.group(1)[::-1]


@quote
def concatenate(m: re.Match) -> str:
    return "".join(re.findall(r'"""(.*?)"""', m.group(0)))


@decrypt("xor")
@quote
def decrypt_xor(m: re.Match) -> str:
    return repeating_xor(m.group(1), m.group(2))


@decrypt("sub")
@quote
def decrypt_sub(m: re.Match):
    with contextlib.suppress(Exception):
        # TODO: Needs a relook, will likely error
        first = int([c for c in m.group(1) if c.isdigit()])
        second = int([c for c in m.group(2) if c.isdigit()])
        if first and second:
            return chr(first - second)
    return m.group()


def find_enc_function(macro) -> Tuple[str, str]:
    match, type = re.search(r"(?ims)Public Function (\w+).+? Xor .+?End Function", macro), "xor"
    if not match:
        match, type = re.search(r"(?ims)Public Function (\w+).+?\d+\s*-\s*\d+.+?End Function", macro), "sub"
    return (match.group(1), type) if match else (None, None)


def handle_techniques(line: str, **opts) -> str:
    enc_func_name = opts["enc_func_name"]
    decrypt_func = opts["decrypt_func"]

    line = line.replace('"', '"""')
    line = re.sub(r'"""([A-F0-9]{2,})"""', decode_hex, line)
    line = re.sub(r'"""([\w_+=/]{2,})"""', decode_base64, line)
    line = re.sub(r"(?i)Chr[A-Z$]\(Asc[A-Z$](.+?)\)\)", r"\1", line)
    line = re.sub(r'(?i)Asc[A-Z$]\("""(\w)\w*"""\)', lambda m: ord(m.group(1)), line)
    line = re.sub(r"(?i)((?:Chr[A-Z$]?\(\d+\)\s*&?\s*)+)", decode_chr, line)
    line = re.sub(rf'(?i)\b{enc_func_name}\s*\(\w+\("""(.+?)"""\),\s*\w+\("""(.+?)"""', decrypt_func, line)
    line = re.sub(rf'(?i)\b{enc_func_name}\((?:""")?(.+?)(?:""")?,\s*(?:""")?(.+?)(?:""")?\)', decrypt_func, line)
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


def extract_iocs(s: str) -> Tuple[str, str]:
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


def parse_macro(macro: str) -> List[Tuple[str, str]]:
    opts = {}
    vb_vars = {}
    result = {}
    iocs = set()
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
        for line in substituted.splitlines():
            ioc = extract_iocs(line)
            if ioc:
                iocs.add(ioc)

    # Dedup IOCs
    result = sorted(iocs, key=lambda p: p[0])

    return result
