import struct


def extract_config(data):
    config_dict = {}
    magic = struct.unpack("I", data[:4])[0]
    if magic == 0x59485221:
        config_dict["C2"] = data[24:].split(b"\0", 1)[0].decode()
        return config_dict
