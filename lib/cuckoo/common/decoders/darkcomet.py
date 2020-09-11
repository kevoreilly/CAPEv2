# Copyright (C) 2014-2015 Kevin Breen (http://techanarchy.net)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import sys
import string
from struct import unpack

try:
    import pefile
except:
    pass
from binascii import unhexlify


def rc4crypt(data, key):
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

    return "".join(out)


def v51_data(data, enckey):
    config = {
        "FWB": "",
        "GENCODE": "",
        "MUTEX": "",
        "NETDATA": "",
        "OFFLINEK": "",
        "SID": "",
        "FTPUPLOADK": "",
        "FTPHOST": "",
        "FTPUSER": "",
        "FTPPASS": "",
        "FTPPORT": "",
        "FTPSIZE": "",
        "FTPROOT": "",
        "PWD": "",
    }
    dec = rc4crypt(unhexlify(data), enckey)
    dec_list = dec.split("\n")
    for entries in dec_list[1:-1]:
        key, value = entries.split("=")
        key = key.strip()
        value = value.rstrip()[1:-1]
        clean_value = [x for x in value if x in string.printable]
        config[key] = clean_value
        config["Version"] = enckey[:-4]
    return config


def v3_data(data, key):
    config = {
        "FWB": "",
        "GENCODE": "",
        "MUTEX": "",
        "NETDATA": "",
        "OFFLINEK": "",
        "SID": "",
        "FTPUPLOADK": "",
        "FTPHOST": "",
        "FTPUSER": "",
        "FTPPASS": "",
        "FTPPORT": "",
        "FTPSIZE": "",
        "FTPROOT": "",
        "PWD": "",
    }
    dec = rc4crypt(unhexlify(data), key)
    #config[str(entry.name)] = dec
    #config["Version"] = key[:-4]

    return config


def versionCheck(rawData):
    if "#KCMDDC2#" in rawData:
        return "#KCMDDC2#-890"
    elif "#KCMDDC4#" in rawData:
        return "#KCMDDC4#-890"
    elif "#KCMDDC42#" in rawData:
        return "#KCMDDC42#-890"
    elif "#KCMDDC42F#" in rawData:
        return "#KCMDDC42F#-890"
    elif "#KCMDDC5#" in rawData:
        return "#KCMDDC5#-890"
    elif "#KCMDDC51#" in rawData:
        return "#KCMDDC51#-890"
    else:
        return None


def configExtract(pe, key):
    config = {
        "FWB": "",
        "GENCODE": "",
        "MUTEX": "",
        "NETDATA": "",
        "OFFLINEK": "",
        "SID": "",
        "FTPUPLOADK": "",
        "FTPHOST": "",
        "FTPUSER": "",
        "FTPPASS": "",
        "FTPPORT": "",
        "FTPSIZE": "",
        "FTPROOT": "",
        "PWD": "",
    }

    rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE["RT_RCDATA"])
    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
    for entry in rt_string_directory.directory.entries:
        if str(entry.name) == "DCDATA":
            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
            config = v51_data(data, key)
        elif str(entry.name) in list(config.keys()):
            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
            dec = rc4crypt(unhexlify(data), key)
            config[str(entry.name)] = [x for x in dec if x in string.printable]
            config["Version"] = key[:-4]
    return config


def configClean(config):
    try:
        newConf = {}
        newConf["FireWallBypass"] = config["FWB"]
        newConf["FTPHost"] = config["FTPHOST"]
        newConf["FTPPassword"] = config["FTPPASS"]
        newConf["FTPPort"] = config["FTPPORT"]
        newConf["FTPRoot"] = config["FTPROOT"]
        newConf["FTPSize"] = config["FTPSIZE"]
        newConf["FTPKeyLogs"] = config["FTPUPLOADK"]
        newConf["FTPUserName"] = config["FTPUSER"]
        newConf["Gencode"] = config["GENCODE"]
        newConf["Mutex"] = config["MUTEX"]
        newConf["Domains"] = config["NETDATA"]
        newConf["OfflineKeylogger"] = config["OFFLINEK"]
        newConf["Password"] = config["PWD"]
        newConf["CampaignID"] = config["SID"]
        newConf["Version"] = config["Version"]
        return newConf
    except:
        return config


def extract_config(file_path, pe):
    data = open(file_path, "rb").read()
    versionKey = versionCheck(data)
    if versionKey != None:
        config = configExtract(pe, versionKey)
        config = configClean(config)

        return config
    else:
        return None
