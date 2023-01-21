#!/usr/bin/env python3
"""
By Daniel Mayer (Daniel@Stairwell.com), @dan__mayer
"""

import re
import struct

DESCRIPTION = "Cobalt Strike Stager Configuration Extractor"
AUTHOR = "@dan__mayer <daniel@stairwell.com>"

INET_CONSTANTS = {
    "INTERNET_FLAG_IDN_DIRECT": 0x00000001,
    "INTERNET_FLAG_IDN_PROXY": 0x00000002,
    "INTERNET_FLAG_RELOAD": 0x80000000,
    "INTERNET_FLAG_RAW_DATA": 0x40000000,
    "INTERNET_FLAG_EXISTING_CONNECT": 0x20000000,
    "INTERNET_FLAG_ASYNC": 0x10000000,
    "INTERNET_FLAG_PASSIVE": 0x08000000,
    "INTERNET_FLAG_NO_CACHE_WRITE": 0x04000000,
    "INTERNET_FLAG_MAKE_PERSISTENT": 0x02000000,
    "INTERNET_FLAG_FROM_CACHE": 0x01000000,
    "INTERNET_FLAG_SECURE": 0x00800000,
    "INTERNET_FLAG_KEEP_CONNECTION": 0x00400000,
    "INTERNET_FLAG_NO_AUTO_REDIRECT": 0x00200000,
    "INTERNET_FLAG_READ_PREFETCH": 0x00100000,
    "INTERNET_FLAG_NO_COOKIES": 0x00080000,
    "INTERNET_FLAG_NO_AUTH": 0x00040000,
    "INTERNET_FLAG_RESTRICTED_ZONE": 0x00020000,
    "INTERNET_FLAG_CACHE_IF_NET_FAIL": 0x00010000,
    "INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP": 0x00008000,
    "INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTPS": 0x00004000,
    "INTERNET_FLAG_IGNORE_CERT_DATE_INVALID": 0x00002000,
    "INTERNET_FLAG_IGNORE_CERT_CN_INVALID": 0x00001000,
    "INTERNET_FLAG_RESYNCHRONIZE": 0x00000800,
    "INTERNET_FLAG_HYPERLINK": 0x00000400,
    "INTERNET_FLAG_NO_UI": 0x00000200,
    "INTERNET_FLAG_PRAGMA_NOCACHE": 0x00000100,
    "INTERNET_FLAG_CACHE_ASYNC": 0x00000080,
    "INTERNET_FLAG_FORMS_SUBMIT": 0x00000040,
    "INTERNET_FLAG_FWD_BACK": 0x00000020,
    "INTERNET_FLAG_NEED_FILE": 0x00000010,
}

SMB_TEMPLATE = re.compile(
    b"""
                                   # Arguments to call API-Hashed CreateNamedPipeA
   \x68\x00\xB0\x04\x00            # push   4B000h
   \x68\x00\xB0\x04\x00            # push   4B000h
   \x6A\x01                        # push   1
   \x6A\x06                        # push   6
   \x6A\x03                        # push   3
   \x52                            # push   edx
   \x68\x45\x70\xDF\xD4            # push   0D4DF7045h
   .{110,180}
   \xE8.\xFF\xFF\xFF               # Call to listen on the named pipe that uses the
                                   # return address to pass the pipe name as an argument

   (?P<pipe_name>.{3,140})         # Name of pipe
   \x00                            # Null terminator at the end of the pipe string
   (?P<watermark>.{4})?            # Watermark
""",
    re.DOTALL | re.VERBOSE,
)

DNS_TEMPLATE = re.compile(
    b"""
    \x69\x50\x68\x64\x6E           # DNS api import
    .{100,160}
    \xE8.\xFF\xFF\xFF              # Call to perform DNS stager requests that uses the
                                   # return address to pass the stager domain as an argument

    \x00                           # Null byte at the beginning of the domain string
    (?P<netloc>.{63})              # Domain string
    (                              # CS 4.0 stager-specific
        .{90,130}
        \x89\xD7\x81\xC7
        .{4}
        \xFF\xE7
        (?P<watermark>.{4})?       # Watermark
    )?
""",
    re.DOTALL | re.VERBOSE,
)

HTTP_TEMPLATE = re.compile(
    b"""
    (?:\xC1\x41\xB8|\x51\x51\x68)
    (?P<port>.{4})                  # Specified port
    .{10,50}\x68
    (?P<inet_flags>....)            # HttpOpenRequestA flags
    \x52\x52.{40,140}

    \xE8.\xFF\xFF\xFF               # Call to perform HttpOpenRequestA and HttpSendRequestA
                                    # that uses the return address to pass the path
                                    # and headers as an argument

    (?P<path>.{79})                 # URL path string
    \x00                            # Null terminator ending the path string
    (?P<headers>.{303})             # Header strings, separated by CLRF
    \x00                            # Null terminator ending the header string
    .{60,120}

    \xE8.\xFD\xFF\xFF               # Call to perform InternetOpenA, which uses the return
                                    # address to pass the netloc as an argument.

    (?P<netloc>.+?)                 # Netloc string
    \x00                            # Null terminator ending the netloc string
    (?P<watermark>.{4})?            # Watermark
""",
    re.DOTALL | re.VERBOSE,
)


class StagerConfig:
    def __init__(self, data):
        """
        f: file path
        """
        self.data = data
        self.config = {}
        self._parse_config()

    def _clean(self, s, data_type):
        """
        s: bytestring to clean
        data_type: string determining which cleaning method is appropriate

        Converts the bytes of the various stager fields into human-readable settings
        """
        result = None
        if data_type == "string":
            result = s.split(b"\x00")[0].decode("utf-8")
        elif data_type == "headers":
            headers = self._clean(s, "string")
            lines = headers.split("\r\n")[:-1]
            result = {k: v for k, v in (line.split(": ") for line in lines)}
        elif data_type == "port":
            result = struct.unpack("<I", s)[0]
        elif data_type == "watermark":
            result = struct.unpack(">I", s)[0]
        elif data_type == "inet_flags":
            n = struct.unpack("<I", s)[0]
            constants = [flag for flag, value in INET_CONSTANTS.items() if n & value == value]
            result = constants
        else:
            raise Exception(f"Unknown type {data_type} passed to _clean()")

        return result

    def _parse_config(self):
        """
        Attempts to parse stager config data from a bytes-like object.
        The three types of stagers' (HTTP, SMB, DNS) templates
        can be found in resources.py
        """
        for i, pattern in enumerate([HTTP_TEMPLATE, DNS_TEMPLATE, SMB_TEMPLATE]):
            match = pattern.search(self.data)
            if match:
                # order results correctly and filter out None values
                gd = match.groupdict()
                order = ["netloc", "path", "pipe_name", "port", "headers", "inet_flags", "watermark"]
                filtered = {k: gd[k] for k in order if gd.get(k) is not None}
                # clean each field appropiately
                operations = {
                    "netloc": lambda x: self._clean(x, "string"),
                    "path": lambda x: self._clean(x, "string"),
                    "pipe_name": lambda x: self._clean(x, "string"),
                    "port": lambda x: self._clean(x, "port"),
                    "headers": lambda x: self._clean(x, "headers"),
                    "inet_flags": lambda x: self._clean(x, "inet_flags"),
                    "watermark": lambda x: self._clean(x, "watermark"),
                }
                # set the settings to contain the cleaned data
                for k, v in filtered.items():
                    self.config[k] = operations[k](v)
                # logic for determining type
                self.config["type"] = ["HTTP", "DNS", "SMB"][i]
                if self.config["type"] == "HTTP":
                    if "INTERNET_FLAG_SECURE" in self.config["inet_flags"]:
                        self.config["type"] = "HTTPS"

    def get_config(self):
        """Returns the settings as a JSON object, or None if none exist"""
        return self.config or None


def extract_config(data):
    """Config extraction function for CapeV2"""
    return StagerConfig(data).get_config()
