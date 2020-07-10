# Copyright (C) 2015 KillerInstinct, Cuckoo Foundation
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import logging
import re
import string
from gzip import GzipFile
from io import StringIO
from itertools import chain, repeat
from six.moves import zip

log = logging.getLogger(__name__)


class DridexDecode_v1(object):
    """ (4/10/2015)
    Decoder class for Dridex payloads. This exchange happens after the first
    POST it beacons. The binary blob that is downloaded in the response
    should be captured by suricata. The Dridex signature will pass that data
    to this class to be decoded.
    """

    def __init__(self):
        self.NODES = re.compile(r"<nodes>(.+?)</nodes>")
        self.data = None

    def is_printable(self, data):
        """Get all printable characters
        @param s: string
        @return string of printable characters
        """
        return all(buf in string.printable for buf in data)

    def xor(self, key):
        """Key based XOR decoder
        @param buf: string of data to be decoded
        @param key: string of key used to XOR
        @return XORed string
        """
        rkey = chain.from_iterable(repeat(key))
        return "".join(chr(ord(c) ^ ord(k)) for c, k in zip(self.data, rkey))

    def extract_nodes(self):
        """Second XOR+gzip loop to extract nodes from decoded config
        @param buf: encoded blob
        @return string of IPs
        """
        # Don't XOR first chunk of random bytes used to mess up file magic
        self.data = self.xor("\x55\xAA")[0x80:]
        try:
            gzfile = GzipFile(fileobj=StringIO(self.data))
            decoded = gzfile.read()
            gzfile.close()

        except IOError:
            log.warning("DridexDecode_v1: Unable to decode <nodes> element: " "data is not gzip")
            return None

        if not self.is_printable(decoded):
            log.warning("DridexDecode_v1: Unable to decode <nodes> element: " "data is not valid")
            return None

        tmp = self.NODES.search(decoded)
        if tmp:
            return self.NODES.search(decoded).group(1)
        else:
            log.warning("DridexDecode_v1: Unable to decode <nodes> element: " "<nodes> not found")
            return None

    def extract_config(self):
        """First XOR loop to extract the full config
        @param data: encoded blob
        @return string or None
        """
        # Key is first 4 bytes
        key = self.data[:4]
        self.data = self.data[4:]

        self.data = self.xor(key)
        try:
            self.data = self.NODES.search(self.data).group(1).decode("base64")
        except:
            log.warning("DridexDecode_v1: Could not extract XML elements")
            return None

        tmp = self.extract_nodes()
        if tmp:
            return tmp
        else:
            return None

    def run(self, payloadpath):
        """Run the decoder
        @param payloadpath: Path to payload blob
        @return list of strings or None
        """
        with open(payloadpath, "rb") as fh:
            self.data = fh.read()

        ip_list = self.extract_config()
        if ip_list:
            return ip_list.split(",")
        else:
            return None
