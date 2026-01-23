# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from ctypes import POINTER, Structure, byref, cast, create_string_buffer, pointer, sizeof, string_at
from ctypes import c_ubyte as BYTE
from ctypes import c_uint as DWORD
from ctypes import c_ushort as WORD


class GRPICONDIR(Structure):
    _pack_ = 1
    _fields_ = [
        ("idReserved", WORD),  # must be 0
        ("idType", WORD),
        ("idCount", WORD),  # no. of images
        # follows with idCount GRPICONDIRENTRY structs
    ]


class GRPICONDIRENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("bWidth", BYTE),
        ("bHeight", BYTE),
        ("bColorCount", BYTE),
        ("bReserved", BYTE),
        ("wPlanes", WORD),
        ("wBitCount", WORD),
        ("dwBytesInRes", DWORD),
        ("nID", WORD),
    ]


class ICONDIR(Structure):
    _pack_ = 1
    _fields_ = [
        ("idReserved", WORD),  # must be 0
        ("idType", WORD),
        ("idCount", WORD),  # no. of images
        # follows with idCount ICONDIRENTRY structs
    ]


class ICONDIRENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ("bWidth", BYTE),
        ("bHeight", BYTE),
        ("bColorCount", BYTE),
        ("bReserved", BYTE),
        ("wPlanes", WORD),
        ("wBitCount", WORD),
        ("dwBytesInRes", DWORD),
        ("dwImageOffset", DWORD),
    ]


class PEGroupIconDir:
    def __init__(self, data):
        self.data = data
        self.icondir = None
        self.icons = None
        if len(self.data) >= sizeof(GRPICONDIR):
            cstring = create_string_buffer(bytes(self.data[: sizeof(GRPICONDIR)]))
            self.icondir = cast(pointer(cstring), POINTER(GRPICONDIR)).contents
            if len(self.data) >= sizeof(GRPICONDIR) + self.icondir.idCount * sizeof(GRPICONDIRENTRY):
                self.icons = []
                for i in range(self.icondir.idCount):
                    startoff = sizeof(GRPICONDIR) + (i * sizeof(GRPICONDIRENTRY))
                    # cstring = create_string_buffer(self.data[startoff:startoff+sizeof(GRPICONDIRENTRY)])
                    cstring = create_string_buffer(bytes(self.data[startoff : startoff + sizeof(GRPICONDIRENTRY)]))
                    self.icons.append(cast(pointer(cstring), POINTER(GRPICONDIRENTRY)).contents)

    def get_icon_file(self, idx, data):
        retstr = b""
        icodir = ICONDIR()
        icodir.idReserved = 0
        icodir.idType = 1
        icodir.idCount = 1
        retstr += string_at(byref(icodir), sizeof(ICONDIR))
        icodirentry = ICONDIRENTRY()
        ourico = self.icons[idx]
        icodirentry.bWidth = ourico.bWidth
        icodirentry.bHeight = ourico.bHeight
        icodirentry.bColorCount = ourico.bColorCount
        icodirentry.bReserved = ourico.bReserved
        icodirentry.wPlanes = ourico.wPlanes
        icodirentry.wBitCount = ourico.wBitCount
        icodirentry.dwBytesInRes = ourico.dwBytesInRes
        icodirentry.dwImageOffset = sizeof(ICONDIR) + sizeof(ICONDIRENTRY)
        retstr += string_at(byref(icodirentry), sizeof(ICONDIRENTRY))
        retstr += data
        return retstr
