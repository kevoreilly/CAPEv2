# This file is part of CAPE Sandbox - https://github.com/ctxis/CAPE
# See the file 'docs/LICENSE' for copying permission.
#
# This decoder is based on:
# Decryptor POC for Remcos RAT version 2.0.5 and earlier
# By Talos July 2018 - https://github.com/Cisco-Talos/remcos-decoder
#
from __future__ import absolute_import
from mwcp.parser import Parser
import string
import pefile
import array
import re

MAX_STRING_SIZE = 16


def get_C2(d):

    try:
        a = array.array('b')
        a.extend(d)
        d_str = a.tobytes().decode('utf8')
        fields = d_str.split("|")
        C2 = []
        for field in fields:
            if bool(re.search('.*:.*(:.*)*', field)):
                C2.append(field)
    except Exception as e:
        C2 = None

    return(C2)


def get_mutex(d):

    try:
        a = array.array('b')
        a.extend(d)
        d_str = a.tobytes().decode('utf8')

        offset = 98
        mutex = d_str[offset:offset+MAX_STRING_SIZE].split("\x1e")[0]
    except:
        mutex = None

    return mutex


def get_named_resource_from_PE(filedata, ResourceName):

    pe = pefile.PE(data=filedata)

    ResourceData = ""
    offset = 0x0
    size = 0x0

    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for entry in rsrc.directory.entries:
            if entry.name is not None:
                if entry.name.__str__() == ResourceName:
                    offset = entry.directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].data.struct.Size

    ResourceData = pe.get_data(offset, size)

    return ResourceData


def RC4_build_S_array(key, keylen):

    S = list(range(256))
    b = 0
    for counter in range(256):
        a = key[counter % keylen] + S[counter]
        b = (a + b) % 256

        S[counter], S[b] = S[b], S[counter]

    return S


def RC4_stream_generator(PlainBytes, S):

    plainLen = len(PlainBytes)
    cipherList = []

    i = 0
    j = 0
    for m in range(plainLen):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        cipherList.append(k ^ PlainBytes[m])

    return cipherList


def check_version(filedata):

    printable = set(string.printable)

    s = ""
    slist = []
    # find strings in binary file
    for c in filedata:
        if len(s) > 4 and c == 0: # no strings <= 4
            slist.append(s)
            s = ""
            continue

        if chr(c) in printable:
            s += chr(c)

    # find and extract version string e.g. "2.0.5 Pro", "1.7 Free" or "1.7 Light"
    for s in slist:
        if bool(re.search('^[12]\.\d+\d{0,1}.*[FLP].*', s)):
            return s
    return

class Remcos(Parser):
    DESCRIPTION = 'Remcos configuration parser.'
    AUTHOR = 'kevoreilly'

    def run(self):
        filedata = self.file_object.file_data

        version = check_version(filedata)
        if version:
            self.reporter.add_metadata('other', {'Version': version})

        # Get data from the PE resource section
        ResourceData = get_named_resource_from_PE(filedata, "SETTINGS")

        # Extract the key from the PE resource section data
        keylen = ResourceData[0]
        key = list(ResourceData[1:keylen+1])

        # Convert encrypted data from the resource section into an list
        encrypted = list(ResourceData[keylen+1:])

        # Generate S
        S = RC4_build_S_array(key, keylen)

        # Decode the encrypted data
        clear_text = RC4_stream_generator(encrypted, S)

        C2 = get_C2(clear_text)
        if C2:
            for C2_server in C2:
                host, port, password = C2_server.split(':')
                self.reporter.add_metadata('address', host + ':' + port)
                self.reporter.add_metadata('password', password)

        mutex = get_mutex(clear_text)
        if mutex:
            self.reporter.add_metadata('mutex', mutex)
