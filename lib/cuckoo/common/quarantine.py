# Copyright (C) 2015 KillerInstinct, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
from __future__ import print_function
import os
import struct
import hashlib
import logging
from binascii import crc32
import six

try:
    import olefile

    HAVE_OLEFILE = True
except ImportError:
    HAVE_OLEFILE = False
    print("Missed olefile dependency: pip3 install olefile")

from lib.cuckoo.common.utils import store_temp_file


def bytearray_xor(data, key):
    for i in range(len(data)):
        data[i] ^= key
    return data


def read_trend_tag(data, offset):
    """ @return a code byte and data tuple
    """
    code, length = struct.unpack("<BH", data[offset : offset + 3])
    return code, bytes(data[offset + 3 : offset + 3 + length])


log = logging.getLogger(__name__)

# Never before published in an accurate form; reversed & developed by Optiv, Inc.
# 95% black box inference from quarantine samples, 5% information obtained from
# avhostplugin.dll (mainly the format of the initial 0x1290/0xe68/0xd10 header,
# which we'll mostly ignore for this quarantine extraction)
# The SEP quarantine format is capable of storing alternate data streams, but
# we'll chop those off.
#
# Format summary:
# First dword: size of main header
# If the main header size is 0x1290, remaining file after that offset is XORed with 0x5A ('Z')
# At that offset will be the second-level header containing additional information
# about the file, original unicode path, detection name, security descriptor string, etc
#
# For older versions of the VBN format (where the first dword is 0xe68 or 0xd10) the
# original binary will be located at the offset specified as the first dword, XORed with 0x5A
# An ASCII form of the original pathname is located directly after the first dword.
#
# Similar to the Trend format, SEP uses a series of tags involving one byte codes and an associated
# value which can then describe some subsequent data (if any)
#  Code    Value Length   Extra Data
#  0x01         1            None
#  0x0A         1            None
#  0x03         4            None
#  0x06         4            None
#  0x04         8            None
#  0x08         4            NUL-terminated Unicode String (of length controlled by dword following 0x08 code)
#  0x09         4            Container (of length controlled by dword following 0x09 code)
#
# Presumably there's more "meta-meaning" behind combinations of these tags, for instance
# the container tags with extra data length of 32 preceding another container seem to be
# a hash-based ID for the information contained in the later container.  For our purposes
# we don't need to be concerned with this (for the most part).
#
# When we find a container which isn't one of the 32-byte ones preceding, we can continue our
# parsing in its contained data.
#
# When we eventually find a container with a value of 0x8 (describing the length of its contained data),
# its contained data will be the total length of its contained data, which will often itself include
# a number of containers (as large files are broken up into chunks).  Naive parsers have assumed
# some "dirty bytes" were inserted into large binaries (uncoincidentally these arose from naively
# xoring with 0xFF, mutating the container code and its associated dword length), or that "0x0900100000" was
# some magic flag.  Instead, as we walk the tags, we should only be XORing with 0xFF the contained data.
#
# To properly parse the container containing the original image, we first have to deal with its variable-length
# header.  The meaning of most of the fields are unknown, but they're unimportant for our purposes.
# At offset 8 in the header is a dword that when added to 0x1c (the initial part of the header that doesn't
# appear to change across quarantine files) brings us to the size of the original file we'll be extracting.
# The end of the header is located 12 bytes after the offset of this size.  We will walk the tags as normal,
# this header essentially just results in the initial chunk of data (if chunked) being header length smaller
# than the subsequent equal-sized chunks.  Subsequent chunks will not have any header.
#
# The total length of contained data after the header can be larger than the length of the original binary
# listed in the header.  This will happen when alternate data streams were appended to the end of the binary.
# The streams will have their own header, which we won't bother to parse as we'll just cut off the contained
# data after we reach the original file size.
#
# In the case where we find a tag of 0x04 prior to the final container containing the original binary, the
# subsequent container will have no header.  This can happen in cases where SEP quarantines files present
# in archive formats.


def read_sep_tag(data, offset):
    """ @return a code byte, metalength, metaval, and extra data tuple
    """
    code = struct.unpack("B", data[offset : offset + 1])[0]
    codeval = 0
    retdata = ""
    length = 0

    if code == 1 or code == 10:
        length = 2
        codeval = struct.unpack("B", data[offset + 1 : offset + 2])[0]
    elif code == 3 or code == 6:
        length = 5
        codeval = struct.unpack("<I", data[offset + 1 : offset + 5])[0]
    elif code == 4:
        length = 9
        codeval = struct.unpack("<Q", data[offset + 1 : offset + 9])[0]
    else:
        length = 5
        codeval = struct.unpack("<I", data[offset + 1 : offset + 5])[0]
        retdata = bytes(data[offset + 5 : offset + 5 + codeval])
    return code, length, codeval, retdata


def sep_unquarantine(f):
    filesize = os.path.getsize(f)
    with open(f, "rb") as quarfile:
        qdata = quarfile.read()

    data = bytearray(qdata)

    dataoffset = struct.unpack("<I", data[:4])[0]

    if dataoffset != 0x1290:
        # supporting older, simpler formats is trivial, will add
        # in a future commit
        return None

    # Space exists in the header for up to 384 characters of the original ASCII filename
    origname = str(bytes(data[4:388])).rstrip("\0")
    origname = os.path.basename(origname)

    data = bytearray_xor(data, 0x5A)

    dataoffset += 0x28
    offset = dataoffset
    decode_next_container = False
    xor_next_container = False
    has_header = True
    binsize = 0
    collectedsize = 0
    bindata = bytearray()
    iters = 0
    lastlen = 0

    while iters < 20000:  # prevent infinite loop on malformed files
        iters += 1
        code, length, codeval, tagdata = read_sep_tag(data, offset)
        extralen = len(tagdata)
        if code == 9:
            if xor_next_container:
                for i in range(len(tagdata)):
                    data[offset + 5 + i] ^= 0xFF
                if has_header:
                    headerlen = 12 + struct.unpack_from("<I", data[offset + 5 + 8 : offset + 5 + 12])[0] + 28
                    binsize = struct.unpack_from("<I", data[offset + 5 + headerlen - 12 : offset + 5 + headerlen - 8])[0]
                    collectedsize += len(tagdata) - headerlen
                    if collectedsize > binsize:
                        binlen = binsize
                    else:
                        binlen = collectedsize
                    bindata += data[offset + 5 + headerlen : offset + 5 + headerlen + binlen]
                    has_header = False
                else:
                    binlen = len(tagdata)
                    collectedsize += binlen
                    if collectedsize > binsize:
                        binlen -= collectedsize - binsize
                    bindata += data[offset + 5 : offset + 5 + binlen]
            else:
                if decode_next_container:
                    extralen = 0
                    decode_next_container = False
                elif codeval == 0x10 or codeval == 0x8:
                    if codeval == 0x8:
                        xor_next_container = True
                        lastlen = struct.unpack_from("<Q", data[offset + 5 : offset + 5 + 8])[0]
                    else:
                        xor_next_container = False
                    decode_next_container = True
        elif code == 4:
            if xor_next_container and lastlen == codeval:
                binsize = codeval
                has_header = False

        offset += length + extralen
        if offset == filesize:
            break

    return store_temp_file(bindata, origname)


# Never before published; reversed & developed by Optiv, Inc.


def mse_ksa():
    # hardcoded key obtained from mpengine.dll
    key = [
        0x1E,
        0x87,
        0x78,
        0x1B,
        0x8D,
        0xBA,
        0xA8,
        0x44,
        0xCE,
        0x69,
        0x70,
        0x2C,
        0x0C,
        0x78,
        0xB7,
        0x86,
        0xA3,
        0xF6,
        0x23,
        0xB7,
        0x38,
        0xF5,
        0xED,
        0xF9,
        0xAF,
        0x83,
        0x53,
        0x0F,
        0xB3,
        0xFC,
        0x54,
        0xFA,
        0xA2,
        0x1E,
        0xB9,
        0xCF,
        0x13,
        0x31,
        0xFD,
        0x0F,
        0x0D,
        0xA9,
        0x54,
        0xF6,
        0x87,
        0xCB,
        0x9E,
        0x18,
        0x27,
        0x96,
        0x97,
        0x90,
        0x0E,
        0x53,
        0xFB,
        0x31,
        0x7C,
        0x9C,
        0xBC,
        0xE4,
        0x8E,
        0x23,
        0xD0,
        0x53,
        0x71,
        0xEC,
        0xC1,
        0x59,
        0x51,
        0xB8,
        0xF3,
        0x64,
        0x9D,
        0x7C,
        0xA3,
        0x3E,
        0xD6,
        0x8D,
        0xC9,
        0x04,
        0x7E,
        0x82,
        0xC9,
        0xBA,
        0xAD,
        0x97,
        0x99,
        0xD0,
        0xD4,
        0x58,
        0xCB,
        0x84,
        0x7C,
        0xA9,
        0xFF,
        0xBE,
        0x3C,
        0x8A,
        0x77,
        0x52,
        0x33,
        0x55,
        0x7D,
        0xDE,
        0x13,
        0xA8,
        0xB1,
        0x40,
        0x87,
        0xCC,
        0x1B,
        0xC8,
        0xF1,
        0x0F,
        0x6E,
        0xCD,
        0xD0,
        0x83,
        0xA9,
        0x59,
        0xCF,
        0xF8,
        0x4A,
        0x9D,
        0x1D,
        0x50,
        0x75,
        0x5E,
        0x3E,
        0x19,
        0x18,
        0x18,
        0xAF,
        0x23,
        0xE2,
        0x29,
        0x35,
        0x58,
        0x76,
        0x6D,
        0x2C,
        0x07,
        0xE2,
        0x57,
        0x12,
        0xB2,
        0xCA,
        0x0B,
        0x53,
        0x5E,
        0xD8,
        0xF6,
        0xC5,
        0x6C,
        0xE7,
        0x3D,
        0x24,
        0xBD,
        0xD0,
        0x29,
        0x17,
        0x71,
        0x86,
        0x1A,
        0x54,
        0xB4,
        0xC2,
        0x85,
        0xA9,
        0xA3,
        0xDB,
        0x7A,
        0xCA,
        0x6D,
        0x22,
        0x4A,
        0xEA,
        0xCD,
        0x62,
        0x1D,
        0xB9,
        0xF2,
        0xA2,
        0x2E,
        0xD1,
        0xE9,
        0xE1,
        0x1D,
        0x75,
        0xBE,
        0xD7,
        0xDC,
        0x0E,
        0xCB,
        0x0A,
        0x8E,
        0x68,
        0xA2,
        0xFF,
        0x12,
        0x63,
        0x40,
        0x8D,
        0xC8,
        0x08,
        0xDF,
        0xFD,
        0x16,
        0x4B,
        0x11,
        0x67,
        0x74,
        0xCD,
        0x0B,
        0x9B,
        0x8D,
        0x05,
        0x41,
        0x1E,
        0xD6,
        0x26,
        0x2E,
        0x42,
        0x9B,
        0xA4,
        0x95,
        0x67,
        0x6B,
        0x83,
        0x98,
        0xDB,
        0x2F,
        0x35,
        0xD3,
        0xC1,
        0xB9,
        0xCE,
        0xD5,
        0x26,
        0x36,
        0xF2,
        0x76,
        0x5E,
        0x1A,
        0x95,
        0xCB,
        0x7C,
        0xA4,
        0xC3,
        0xDD,
        0xAB,
        0xDD,
        0xBF,
        0xF3,
        0x82,
        0x53,
    ]
    sbox = range(256)
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp

    return sbox


def rc4_decrypt(sbox, data):
    out = bytearray(len(data))
    i = 0
    j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp
        val = sbox[(sbox[i] + sbox[j]) % 256]
        out[k] = val ^ data[k]

    return out


def mse_unquarantine(f):
    with open(f, "rb") as quarfile:
        data = bytearray(quarfile.read())

    fsize = len(data)
    if fsize < 12 or data[0] != 0x0B or data[1] != 0xAD or data[2] != 0x00:
        return None

    sbox = mse_ksa()
    outdata = rc4_decrypt(sbox, data)

    headerlen = 0x28 + struct.unpack("<I", outdata[8:12])[0]

    origlen = struct.unpack("<I", outdata[headerlen - 12 : headerlen - 8])[0]

    if origlen + headerlen != fsize:
        return None

    # MSE stores metadata like the original filename in a separate file,
    # so due to our existing interface, we can't restore the original name
    # from just the ResourceData file.  Later we may allow uploading pairs
    # of files, match them up by name, and then associate that data here
    # for the final submission

    return store_temp_file(outdata[headerlen:], "MSEDequarantineFile")


# Never before published; reversed & developed by Optiv, Inc.
# Simple RC4 based on an MD5 of a hardcoded string in mbamcore.dll
# Quarantine files are split into data and metadata, so like MSE we
# can't recover the original filename with the data file alone.
# The original binary is in the .quar file and the metadata in the .data file
# Both files use the same key.  The original filename can be obtained from
# the decrypted metadata file from the line beginning with "ObjectName:"


def mbam_ksa():
    # hardcoded key obtained from mbamcore.dll
    m = hashlib.md5()
    m.update("XBXM8362QIXD9+637HCB02/VN0JF6Z3)cB9UFZMdF3I.*c.,c5SbO7)WNZ8CY1(XMUDb")
    key = bytearray(m.digest())
    sbox = range(256)
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i % len(key)]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp

    return sbox


def mbam_unquarantine(f):
    with open(f, "rb") as quarfile:
        data = bytearray(quarfile.read())

    sbox = mbam_ksa()
    outdata = rc4_decrypt(sbox, data)

    return store_temp_file(outdata, "MBAMDequarantineFile")


# Never before published in an accurate form; reversed & developed by Optiv, Inc.
# http://forensicswiki.org/wiki/Kaspersky_Quarantine_File was close, but missed the
# length/value encoding on metadata.  Mostly based on black-box reversing of the file
# format, partially on reversing qb.ppl


def kav_unquarantine(file):
    with open(file, "rb") as quarfile:
        data = bytearray(quarfile.read())

    # check for KLQB header
    magic = struct.unpack("<I", data[0:4])[0]
    if magic != 0x42514C4B:
        return None

    fsize = len(data)

    headerlen = struct.unpack("<I", data[8:12])[0]
    metaoffset = struct.unpack("<I", data[0x10:0x14])[0]
    metalen = struct.unpack("<I", data[0x20:0x24])[0]
    origlen = struct.unpack("<I", data[0x30:0x34])[0]

    if fsize < headerlen + origlen + metalen:
        return None
    if metaoffset < headerlen + origlen:
        return None

    origname = "KAVDequarantineFile"
    key = [0xE2, 0x45, 0x48, 0xEC, 0x69, 0x0E, 0x5C, 0xAC]

    curoffset = metaoffset
    length = struct.unpack("<I", data[curoffset : curoffset + 4])[0]
    while length:
        for i in range(length):
            data[curoffset + 4 + i] ^= key[i % len(key)]
        idlen = struct.unpack("<I", data[curoffset + 4 : curoffset + 8])[0]
        idname = str(data[curoffset + 8 : curoffset + 8 + idlen]).rstrip("\0")
        if idname == "cNP_QB_FULLNAME":
            vallen = length - idlen
            origname = (
                six.text_type(data[curoffset + 8 + idlen : curoffset + 4 + length]).decode("utf-16").encode("utf8", "ignore").rstrip("\0")
            )
        curoffset += 4 + length
        if curoffset >= metaoffset + metalen:
            break
        length = struct.unpack("<I", data[curoffset : curoffset + 4])[0]

    for i in range(origlen):
        data[headerlen + i] ^= key[i % len(key)]

    return store_temp_file(data[headerlen : headerlen + origlen], origname)


# Never before published; reversed & developed by Optiv, Inc.
# We don't need most of the header fields but include them here
# for the sake of documentation


def trend_unquarantine(f):
    with open(f, "rb") as quarfile:
        qdata = quarfile.read()

    data = bytearray_xor(bytearray(qdata), 0xFF)

    magic, dataoffset, numtags = struct.unpack("<IIH", data[:10])
    if magic != 0x58425356:  # VSBX
        return None
    origpath = "C:\\"
    origname = "UnknownTrendFile.bin"
    platform = "Unknown"
    attributes = 0x00000000
    unknownval = 0
    basekey = 0x00000000
    encmethod = 0

    if numtags > 15:
        return None

    dataoffset += 10
    offset = 10
    for i in range(numtags):
        code, tagdata = read_trend_tag(data, offset)
        if code == 1:  # original pathname
            origpath = six.text_type(tagdata, encoding="utf16").encode("utf8", "ignore").rstrip("\0")
        elif code == 2:  # original filename
            origname = six.text_type(tagdata, encoding="utf16").encode("utf8", "ignore").rstrip("\0")
        elif code == 3:  # platform
            platform = str(tagdata)
        elif code == 4:  # file attributes
            attributes = struct.unpack("<I", tagdata)[0]
        elif code == 5:  # unknown, generally 1
            unknownval = struct.unpack("<I", tagdata)[0]
        elif code == 6:  # base key
            basekey = struct.unpack("<I", tagdata)[0]
        elif code == 7:  # encryption method: 1 == xor FF, 2 = CRC method
            encmethod = struct.unpack("<I", tagdata)[0]
        offset += 3 + len(tagdata)

    if encmethod != 2:
        return store_temp_file(data[dataoffset:], origname)

    bytesleft = len(data) - dataoffset
    unaligned = dataoffset % 4
    firstiter = True
    curoffset = dataoffset
    while bytesleft:
        off = curoffset
        if firstiter:
            off = curoffset - unaligned
            firstiter = False
        keyval = basekey + off
        buf = struct.pack("<I", keyval)
        crc = crc32(buf) & 0xFFFFFFFF
        crcbuf = bytearray(struct.pack("<I", crc))

        for i in range(unaligned, 4):
            if not bytesleft:
                break
            data[curoffset] ^= crcbuf[i]
            curoffset += 1
            bytesleft -= 1

        unaligned = 0

    return store_temp_file(data[dataoffset:], origname)


def mcafee_unquarantine(f):
    if not HAVE_OLEFILE:
        log.info("Missed olefile dependency: pip3 install olefile")
        return None

    if not olefile.isOleFile(f):
        return None

    with open(f, "rb") as quarfile:
        qdata = quarfile.read()

    oledata = olefile.OleFileIO(qdata)
    olefiles = oledata.listdir()
    quarfiles = list()
    for item in olefiles:
        if "Details" in item:
            details = bytearray_xor(bytearray(oledata.openstream("Details").read()), 0x6A)
        else:
            # Parse for quarantine files
            for fileobj in item:
                if "File_" in fileobj:
                    quarfiles.append(fileobj)
            decoded = dict()
            # Try and decode quarantine files (sometimes there are none)
            for item in quarfiles:
                try:
                    decoded[item] = bytearray_xor(bytearray(oledata.openstream(item).read()), 0x6A)
                except:
                    pass
            # Try and get original file name from details
            if list(decoded.keys()):
                config = details.splitlines()
                malname = ""
                for item in decoded.keys():
                    parseit = False
                    for check in config:
                        if check.startswith("["):
                            if item in check:
                                parseit = True
                        if check == "":
                            parseit = False
                        if parseit and check.startswith("OriginalName="):
                            malname = str(check.split("\\")[-1])
                    if not malname:
                        malname = "McAfeeDequarantineFile"
                    # currently we're only returning the first found file in the quarantine file
                    return store_temp_file(decoded[item], malname)


def xorff_unquarantine(f):
    """
       sentinelone
       forefront
    """
    base = os.path.basename(f)
    realbase, ext = os.path.splitext(base)

    with open(f, "rb") as quarfile:
        qdata = bytearray_xor(bytearray(quarfile.read()), 0xFF)
        # can't do much about the name for this case
        return store_temp_file(qdata, base)


func_map = {
    ".quar": mbam_unquarantine,
    ".mal": xorff_unquarantine,
    ".but": mcafee_unquarantine,
}


def unquarantine(f):
    f = f.decode("utf8")
    base = os.path.basename(f)
    realbase, ext = os.path.splitext(base)

    if not HAVE_OLEFILE:
        log.info("Missed olefile dependency: pip3 install olefile")
    if ext.lower() == ".bup" or (HAVE_OLEFILE and olefile.isOleFile(f)):
        try:
            return mcafee_unquarantine(f)
        except:
            pass

    if ext.lower() in func_map:
        try:
            return func_map[ext.lower()](f)
        except Exception as e:
            print(e)

    for func in (kav_unquarantine, trend_unquarantine, sep_unquarantine, mse_unquarantine, xorff_unquarantine):
        try:
            quarfile = func(f)
            if quarfile:
                return quarfile
        except:
            pass
