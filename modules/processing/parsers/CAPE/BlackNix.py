from __future__ import absolute_import
import os
import sys
import pefile


def extract_config(raw_data):
    try:
        pe = pefile.PE(data=raw_data)

        try:
            rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE["RT_RCDATA"])
        except:
            return None

        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]

        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "SETTINGS":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                config = data.split("}")
                return config
    except:
        return None


def decode(line):
    result = ""
    for i in range(0, len(line)):
        a = ord(line[i])
        result += chr(a - 1)
    return result


def domain_parse(config):
    domain_list = []
    raw_domains = config["Domains"]

    for domain in raw_domains.split(";"):
        domain_list.append(domain.split(":")[0])
    return domain_list


def config(data):
    try:
        conf_dict = {}
        config_raw = extract_config(data)
        if config_raw:
            conf_dict["Mutex"] = decode(config_raw[1])[::-1]
            conf_dict["Anti Sandboxie"] = decode(config_raw[2])[::-1]
            conf_dict["Max Folder Size"] = decode(config_raw[3])[::-1]
            conf_dict["Delay Time"] = decode(config_raw[4])[::-1]
            conf_dict["Password"] = decode(config_raw[5])[::-1]
            conf_dict["Kernel Mode Unhooking"] = decode(config_raw[6])[::-1]
            conf_dict["User More Unhooking"] = decode(config_raw[7])[::-1]
            conf_dict["Melt Server"] = decode(config_raw[8])[::-1]
            conf_dict["Offline Screen Capture"] = decode(config_raw[9])[::-1]
            conf_dict["Offline Keylogger"] = decode(config_raw[10])[::-1]
            conf_dict["Copy To ADS"] = decode(config_raw[11])[::-1]
            conf_dict["Domain"] = decode(config_raw[12])[::-1]
            conf_dict["Persistence Thread"] = decode(config_raw[13])[::-1]
            conf_dict["Active X Key"] = decode(config_raw[14])[::-1]
            conf_dict["Registry Key"] = decode(config_raw[15])[::-1]
            conf_dict["Active X Run"] = decode(config_raw[16])[::-1]
            conf_dict["Registry Run"] = decode(config_raw[17])[::-1]
            conf_dict["Safe Mode Startup"] = decode(config_raw[18])[::-1]
            conf_dict["Inject winlogon.exe"] = decode(config_raw[19])[::-1]
            conf_dict["Install Name"] = decode(config_raw[20])[::-1]
            conf_dict["Install Path"] = decode(config_raw[21])[::-1]
            conf_dict["Campaign Name"] = decode(config_raw[22])[::-1]
            conf_dict["Campaign Group"] = decode(config_raw[23])[::-1]
            return conf_dict
        else:
            return None
    except:
        return None
