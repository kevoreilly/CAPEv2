import base64
import re
import sys
from contextlib import suppress

import dnfile


class Parser:
    def __init__(self, data: bytes):
        self.dotnet_file = dnfile.dnPE(data=data)

    # ex: 72 9F 00 00 70 ldstr foo, the index is what comes after 0x72 opcode -> 0x9F
    def get_user_string_from_index(self, index):
        return self.dotnet_file.net.user_strings.get(index).value

    # in little-endian token is: 12 00 00 04 (0x40000012), where 0x04 is field table index, and 0x12 is the field index
    def get_field_name_from_index(self, index):
        return self.dotnet_file.net.mdtables.Field.get_with_row_index(index).Name

    def close(self):
        self.dotnet_file.close()


CONFIG_MAPPING = {
    "DR": "directory",
    "EXE": "executable",
    "H": "domain",
    "P": "port",
    "VN": "campaign_id",
    "VR": "version",
    "RG": "registry_value",
    "x": "port",
    "ss": "domain",
}

REPLACES_MAPPING = {
    "विनी": "M",
    "蒂": "T",
    "मे": "A",
    "बीपी": "Z",
    "粹": "M",
    "ता": "T",
    "의도": "A",
    "에": "e",
    "!": "=",
    "FRANSESCO": "M",
    "Strik": "=",
}


def get_patterns():
    # ldstr, stsfld
    pattern_1 = re.compile(
        Rb"""(?x)
    \x72(...)\x70
    \x80(...)\x04
    """
    )

    # ldstr, call Conversions.ToBoolean, stsfld
    pattern_2 = re.compile(
        Rb"""(?x)
    \x72(...)\x70
    \x28\x04\x00\x00\x0A
    \x80(...)\x04
    """
    )

    return [pattern_1, pattern_2]


def get_matches(data, patterns):
    matches = []

    for pattern in patterns:
        matches.extend(pattern.findall(data))

    return matches


def get_config_dict(parser, data):
    patterns = get_patterns()
    matches = get_matches(data, patterns)

    if matches:

        config_dict = {}

        for match in matches:
            string_index = int.from_bytes(match[0], "little")
            field_index = int.from_bytes(match[1], "little")

            # get each string variable name and value
            field_name = parser.get_field_name_from_index(field_index).__str__()
            field_value = parser.get_user_string_from_index(string_index).__str__()
            config_dict[field_name] = field_value

        return config_dict


def normalize_config(config_dict):
    normalized_config_dict = {}

    # get only the interesting configs and normalize names
    for key in config_dict:
        if key in CONFIG_MAPPING:
            normalized_key = CONFIG_MAPPING[key]
            normalized_config_dict[normalized_key] = config_dict[key]

    return normalized_config_dict


def decode_b64_values(config):
    if "campaign_id" in config:
        config["campaign_id"] = base64.b64decode(config["campaign_id"]).decode()

    return config


def do_string_replaces(s):
    for key in REPLACES_MAPPING:
        if key in s:
            s = s.replace(key, REPLACES_MAPPING[key])

    return s


def replaces_and_b6d_decode(config):
    clean_domain = do_string_replaces(config["domain"])
    clean_port = do_string_replaces(config["port"])

    config["domain"] = base64.b64decode(clean_domain).decode()
    config["port"] = base64.b64decode(clean_port).decode()

    return config


def clean_https_reversed_port_and_domain(config):
    if "https" in config["port"]:
        config["port"] = config["port"].replace("https://", "")[::-1]
        config["domain"] = config["domain"].replace("https://", "")[::-1]

    return config


def decode_domain_and_port(config):
    try:
        if "port" in config and int(config["port"]):
            pass
    except ValueError:
        config = replaces_and_b6d_decode(config)

    return config


def decode_reversed_ss_and_x(config):
    return config


def get_clean_config(config_dict):
    with suppress(Exception):
        config = normalize_config(config_dict)
        config = decode_b64_values(config)
        config = clean_https_reversed_port_and_domain(config)
        config = decode_domain_and_port(config)
        config = decode_reversed_ss_and_x(config)

        return config


def extract_config(data):
    conf = {}
    dotnet_file_parser = Parser(data=data)
    config_dict = get_config_dict(dotnet_file_parser, data)
    config = get_clean_config(config_dict)

    if config.get("domain") and config.get("port"):
        conf["cncs"] = [f"{config['domain']}:{config['port']}"]

    if config.get("campaign_id"):
        conf["campaign id"] = config["campaign_id"]

    if config.get("version"):
        conf["version"] = config["version"]

    dotnet_file_parser.close()
    return conf


if "__main__" == __name__:
    with open(sys.argv[1], "rb") as f:
        print(extract_config(f.read()))
