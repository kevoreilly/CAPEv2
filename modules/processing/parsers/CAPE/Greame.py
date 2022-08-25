import os
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
    config = {"family": "Greame"}
    if len(raw_config) <= 20:
        return None
    # Config sections 0 - 19 contain a list of Domains and Ports
    for x in range(19):
        if len(raw_config[x]) > 1:
            domain, port = xor_decode(raw_config[x]).split(":", 2)
            config.setdefault("tcp", []).append({"server_domain": domain, "server_port": port})
    config["identifier"] = xor_decode(raw_config[20])  # Server ID
    config["passwords"] = [xor_decode(raw_config[n]) for n in [21, 73]]  # Password, Google Chrome Passwords
    config["ftp"] = (
        [
            {
                "username": xor_decode(raw_config[41]),
                "password": xor_decode(raw_config[42]),
                "hostname": xor_decode(raw_config[38]),
                "port": xor_decode(raw_config[43]),
                "path": xor_decode(raw_config[39]),
            }
        ],
    )
    config["paths"] = [{"path": os.path.join(xor_decode(raw_config[25]), xor_decode(raw_config[26])), "usage": "install"}]
    config["mutex"] = [xor_decode(raw_config[62])]
    config["registry"] = [
        {"key": xor_decode(raw_config[28])},  # "REG Key HKLM"
        {"key": xor_decode(raw_config[29])},  # "REG Key HKLU"
    ]
    config["binary"] = [
        {"data": xor_decode(raw_config[31])},  # "Message Box Icon"
        {"data": xor_decode(raw_config[32])},  # "Message Box Button"
    ]

    # Below sound like capabilities but unsure of values..
    config["other"] = {
        "Install Flag": xor_decode(raw_config[22]),
        "Active X Startup": xor_decode(raw_config[27]),
        "Enable Message Box": xor_decode(raw_config[30]),
        "Install Message Title": xor_decode(raw_config[33]),
        "Install Message Box": xor_decode(raw_config[34]).replace("\r\n", " "),
        "Activate Keylogger": xor_decode(raw_config[35]),
        "Keylogger Backspace = Delete": xor_decode(raw_config[36]),
        "Keylogger Enable FTP": xor_decode(raw_config[37]),
        "FTP Interval": xor_decode(raw_config[44]),
        "Persistance": xor_decode(raw_config[59]),
        "Hide File": xor_decode(raw_config[60]),
        "Change Creation Date": xor_decode(raw_config[61]),
        "Melt File": xor_decode(raw_config[63]),
        "Startup Policies": xor_decode(raw_config[69]),
        "USB Spread": xor_decode(raw_config[70]),
        "P2P Spread": xor_decode(raw_config[71]),
    }
    if xor_decode(raw_config[57]) == 0:
        config["other"]["Process Injection"] = "Disabled"
    elif xor_decode(raw_config[57]) == 1:
        config["other"]["Process Injection"] = "Default Browser"
    elif xor_decode(raw_config[57]) == 2:
        config["other"]["Process Injection"] = xor_decode(raw_config[58])
    else:
        config["other"]["Process Injection"] = "None"

    return config


def extract_config(data):
    raw_config = get_config(data)
    if raw_config:
        return parse_config(raw_config)
