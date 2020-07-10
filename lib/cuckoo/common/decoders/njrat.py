# Copyright (C) 2014-2015 Kevin Breen (http://techanarchy.net)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import sys
import base64
import string

try:
    import pype32

    HAVE_PYPE32 = True
except ImportError:
    HAVE_PYPE32 = False

# Confirm if there is Net MetaData in the File
def getStream(pe):
    rawConfig = None
    for counter, dir in enumerate(pe.ntHeaders.optionalHeader.dataDirectory):
        if dir.name.value == "NET_METADATA_DIRECTORY" and dir.rva.value and dir.size.value:
            pe.fullLoad()
            rawConfig = findUSStream(pe, counter)
    return rawConfig


# I only want to extract the User Strings Section
def findUSStream(pe, dir):
    for i in range(0, 4):
        name = pe.ntHeaders.optionalHeader.dataDirectory[dir].info.netMetaDataStreams[i].name.value
        if name.startswith("#US"):
            return pe.ntHeaders.optionalHeader.dataDirectory[dir].info.netMetaDataStreams[i].info
    return None


# Walk the User Strings and create a list of individual strings
def parseStrings(rawConfig):
    stringList = []
    offset = 1
    config = bytearray(rawConfig)
    while offset < len(config):
        length = int(config[offset])
        that = config[offset + 1 : offset + int(length)]
        stringList.append(str(that.replace("\x00", "")))
        offset += int(length + 1)
    return stringList


# Turn the strings in to a python Dict
def parseConfig(stringList):
    dict = {}
    if "0.3.5" in stringList:
        dict["Campaign ID"] = base64.b64decode(stringList[3])
        dict["version"] = stringList[4]
        dict["Install Name"] = stringList[0]
        dict["Install Dir"] = stringList[1]
        dict["Registry Value"] = stringList[2]
        dict["Domain"] = stringList[6]
        dict["Port"] = stringList[7]
        dict["Network Separator"] = stringList[8]
        dict["Install Flag"] = stringList[5]
    elif "0.3.6" in stringList:
        index = stringList.index("[endof]")
        dict["Campaign ID"] = base64.b64decode(stringList[index + 4])
        dict["version"] = stringList[index + 5]
        dict["Install Name"] = stringList[index + 1]
        dict["Install Dir"] = stringList[index + 2]
        dict["Registry Value"] = stringList[index + 3]
        dict["Domain"] = stringList[index + 7]
        dict["Port"] = stringList[index + 8]
        dict["Network Separator"] = stringList[index + 9]
        dict["Install Flag"] = stringList[index + 10]
    elif "0.4.1a" in stringList:
        index = stringList.index("[endof]")
        dict["Campaign ID"] = base64.b64decode(stringList[index + 1])
        dict["version"] = stringList[index + 2]
        dict["Install Name"] = stringList[index + 4]
        dict["Install Dir"] = stringList[index + 5]
        dict["Registry Value"] = stringList[index + 6]
        dict["Domain"] = stringList[index + 7]
        dict["Port"] = stringList[index + 8]
        dict["Network Separator"] = stringList[index + 10]
        dict["Install Flag"] = stringList[index + 3]
    elif "0.5.0E" in stringList:
        index = stringList.index("[endof]")
        dict["Campaign ID"] = base64.b64decode(stringList[index - 8])
        dict["version"] = stringList[index - 7]
        dict["Install Name"] = stringList[index - 6]
        dict["Install Dir"] = stringList[index - 5]
        dict["Registry Value"] = stringList[index - 4]
        dict["Domain"] = stringList[index - 3]
        dict["Port"] = stringList[index - 2]
        dict["Network Separator"] = stringList[index - 1]
        dict["Install Flag"] = stringList[index + 3]
    elif "0.6.4" in stringList:
        dict["Campaign ID"] = base64.b64decode(stringList[0])
        dict["version"] = stringList[1]
        dict["Install Name"] = stringList[2]
        dict["Install Dir"] = stringList[3]
        dict["Registry Value"] = stringList[4]
        dict["Domain"] = stringList[5]
        dict["Port"] = stringList[6]
        dict["Network Separator"] = stringList[7]
        dict["Install Flag"] = stringList[8]
    elif "0.7d" in stringList:
        dict["Campaign ID"] = base64.b64decode(stringList[0])
        dict["version"] = stringList[1]
        dict["Install Name"] = stringList[2]
        dict["Install Dir"] = stringList[3]
        dict["Registry Value"] = stringList[4]
        dict["Domain"] = stringList[5]
        dict["Port"] = stringList[6]
        dict["Network Separator"] = stringList[7]
        dict["Install Flag"] = stringList[8]
    else:
        return None

    # Really hacky test to check for a valid config.
    if dict["Install Flag"] == "True" or dict["Install Flag"] == "False" or dict["Install Flag"] == "":
        return dict
    else:
        return None


def extract_config(file_path):
    if not HAVE_PYPE32:
        return None
    data = open(file_path, "rb").read()

    try:
        pe = pype32.PE(data=data, fastLoad=True)
        rawConfig = getStream(pe)
        if rawConfig:
            # Get a list of strings
            stringList = parseStrings(rawConfig)
            # parse the string list
            dict = parseConfig(stringList)
            return dict
    except:
        pass

    return None
