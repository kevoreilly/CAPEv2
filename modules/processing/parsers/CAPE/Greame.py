import string

import pefile


def get_config(data):
    try:
        pe = pefile.PE(data=data)
        rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE["RT_RCDATA"])
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "GREAME":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                return data.split("####@####")
    except Exception:
        return None


def xor_decode(data):
    key = 0xBC
    encoded = bytearray(data)
    for i in range(len(encoded)):
        encoded[i] ^= key
    return [x for x in str(encoded) if x in string.printable]


def parse_config(raw_config):
    if len(raw_config) <= 20:
        return None
    domains = ""
    ports = ""
    # Config sections 0 - 19 contain a list of Domains and Ports
    for x in range(19):
        if len(raw_config[x]) > 1:
            domains += xor_decode(raw_config[x]).split(":", 1)[0]
            domains += "|"
            ports += xor_decode(raw_config[x]).split(":", 2)[1]
            ports += "|"
    config_dict = {
        "Domain": domains[:-1],
        "Port": ports[:-1],
        "ServerID": xor_decode(raw_config[20]),
        "Password": xor_decode(raw_config[21]),
        "Install Flag": xor_decode(raw_config[22]),
        "Install Directory": xor_decode(raw_config[25]),
        "Install File Name": xor_decode(raw_config[26]),
        "Active X Startup": xor_decode(raw_config[27]),
        "REG Key HKLM": xor_decode(raw_config[28]),
        "REG Key HKCU": xor_decode(raw_config[29]),
        "Enable Message Box": xor_decode(raw_config[30]),
        "Message Box Icon": xor_decode(raw_config[31]),
        "Message Box Button": xor_decode(raw_config[32]),
        "Install Message Title": xor_decode(raw_config[33]),
        "Install Message Box": xor_decode(raw_config[34]).replace("\r\n", " "),
        "Activate Keylogger": xor_decode(raw_config[35]),
        "Keylogger Backspace = Delete": xor_decode(raw_config[36]),
        "Keylogger Enable FTP": xor_decode(raw_config[37]),
        "FTP Address": xor_decode(raw_config[38]),
        "FTP Directory": xor_decode(raw_config[39]),
        "FTP UserName": xor_decode(raw_config[41]),
        "FTP Password": xor_decode(raw_config[42]),
        "FTP Port": xor_decode(raw_config[43]),
        "FTP Interval": xor_decode(raw_config[44]),
        "Persistance": xor_decode(raw_config[59]),
        "Hide File": xor_decode(raw_config[60]),
        "Change Creation Date": xor_decode(raw_config[61]),
        "Mutex": xor_decode(raw_config[62]),
        "Melt File": xor_decode(raw_config[63]),
        "Startup Policies": xor_decode(raw_config[69]),
        "USB Spread": xor_decode(raw_config[70]),
        "P2P Spread": xor_decode(raw_config[71]),
        "Google Chrome Passwords": xor_decode(raw_config[73]),
    }
    if xor_decode(raw_config[57]) == 0:
        config_dict["Process Injection"] = "Disabled"
    elif xor_decode(raw_config[57]) == 1:
        config_dict["Process Injection"] = "Default Browser"
    elif xor_decode(raw_config[57]) == 2:
        config_dict["Process Injection"] = xor_decode(raw_config[58])
    else:
        config_dict["Process Injection"] = "None"
    return config_dict


def extract_config(data):
    raw_config = get_config(data)
    if raw_config:
        return parse_config(raw_config)
