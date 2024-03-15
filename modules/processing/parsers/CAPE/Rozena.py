import re


def extract_config(data: bytes):
    patternIP_PORT = re.compile(rb"\x68(....)\x68..(..)\x89", re.DOTALL)
    config_dict = {}

    matches = patternIP_PORT.findall(data)
    if matches:
        ip = "".join(".".join(f"{c}" for c in matches[0][0]))
        port = int.from_bytes(matches[0][1], byteorder="big")

        config_dict["C2"] = ip
        config_dict["Port"] = port

    return config_dict
