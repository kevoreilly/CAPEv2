from __future__ import absolute_import
import string
import pefile


def get_config(data):
    try:
        pe = pefile.PE(data=data)
        try:
            rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE["RT_RCDATA"])
        except ValueError as e:
            return
        except AttributeError as e:
            return
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "GREAME":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                raw_config = data.split("####@####")
                return raw_config
    except:
        return None


def xor_decode(data):
    key = 0xBC
    encoded = bytearray(data)
    for i in range(len(encoded)):
        encoded[i] ^= key
    return [x for x in str(encoded) if x in string.printable]


def parse_config(raw_config):
    if len(raw_config) > 20:
        domains = ""
        ports = ""
        # Config sections 0 - 19 contain a list of Domains and Ports
        for x in range(0, 19):
            if len(raw_config[x]) > 1:
                domains += xor_decode(raw_config[x]).split(":")[0]
                domains += "|"
                ports += xor_decode(raw_config[x]).split(":")[1]
                ports += "|"
        config_dict = {}
        config_dict["Domain"] = domains[:-1]
        config_dict["Port"] = ports[:-1]
        config_dict["ServerID"] = xor_decode(raw_config[20])
        config_dict["Password"] = xor_decode(raw_config[21])
        config_dict["Install Flag"] = xor_decode(raw_config[22])
        config_dict["Install Directory"] = xor_decode(raw_config[25])
        config_dict["Install File Name"] = xor_decode(raw_config[26])
        config_dict["Active X Startup"] = xor_decode(raw_config[27])
        config_dict["REG Key HKLM"] = xor_decode(raw_config[28])
        config_dict["REG Key HKCU"] = xor_decode(raw_config[29])
        config_dict["Enable Message Box"] = xor_decode(raw_config[30])
        config_dict["Message Box Icon"] = xor_decode(raw_config[31])
        config_dict["Message Box Button"] = xor_decode(raw_config[32])
        config_dict["Install Message Title"] = xor_decode(raw_config[33])
        config_dict["Install Message Box"] = xor_decode(raw_config[34]).replace("\r\n", " ")
        config_dict["Activate Keylogger"] = xor_decode(raw_config[35])
        config_dict["Keylogger Backspace = Delete"] = xor_decode(raw_config[36])
        config_dict["Keylogger Enable FTP"] = xor_decode(raw_config[37])
        config_dict["FTP Address"] = xor_decode(raw_config[38])
        config_dict["FTP Directory"] = xor_decode(raw_config[39])
        config_dict["FTP UserName"] = xor_decode(raw_config[41])
        config_dict["FTP Password"] = xor_decode(raw_config[42])
        config_dict["FTP Port"] = xor_decode(raw_config[43])
        config_dict["FTP Interval"] = xor_decode(raw_config[44])
        config_dict["Persistance"] = xor_decode(raw_config[59])
        config_dict["Hide File"] = xor_decode(raw_config[60])
        config_dict["Change Creation Date"] = xor_decode(raw_config[61])
        config_dict["Mutex"] = xor_decode(raw_config[62])
        config_dict["Melt File"] = xor_decode(raw_config[63])
        config_dict["Startup Policies"] = xor_decode(raw_config[69])
        config_dict["USB Spread"] = xor_decode(raw_config[70])
        config_dict["P2P Spread"] = xor_decode(raw_config[71])
        config_dict["Google Chrome Passwords"] = xor_decode(raw_config[73])
        if xor_decode(raw_config[57]) == 0:
            config_dict["Process Injection"] = "Disabled"
        elif xor_decode(raw_config[57]) == 1:
            config_dict["Process Injection"] = "Default Browser"
        elif xor_decode(raw_config[57]) == 2:
            config_dict["Process Injection"] = xor_decode(raw_config[58])
        else:
            config_dict["Process Injection"] = "None"
    else:
        return None
    return config_dict


def config(data):
    raw_config = get_config(data)
    if raw_config:
        config_dict = parse_config(raw_config)
        return config_dict
