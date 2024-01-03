# Derived from https://github.com/RussianPanda95/Configuration_extractors/blob/main/aurora_config_extractor.py
# A huge thank you to RussianPanda95

import base64
import json
import logging
import re

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

patterns = [
    rb"[A-Za-z0-9+/]{4}(?:[A-Za-z0-9+/]{4})*(?=[0-9]+)",
    rb"(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)",
]


def extract_config(data):
    config_dict = {}
    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, data))

    matches = [match for match in matches if len(match) > 90]

    # Search for the configuration module in the binary
    config_match = re.search(rb"eyJCdWlsZElEI[^&]{0,400}", data)
    if config_match:
        matched_string = config_match.group(0).decode("utf-8")
        decoded_str = base64.b64decode(matched_string).decode()
        for item in decoded_str.split(","):
            key = item.split(":")[0].strip("{").strip('"')
            value = item.split(":")[1].strip('"')
            if key == "IP":
                key = "C2"
            if value:
                config_dict[key] = value

    grabber_found = False

    # Extracting the modules
    for match in matches:
        match_str = match.decode("utf-8")
        decoded_str = base64.b64decode(match_str)

        if b"DW" in decoded_str:
            data_dict = json.loads(decoded_str)
            for elem in data_dict:
                if elem["Method"] == "DW":
                    config_dict["Loader module"] = elem

        if b"PS" in decoded_str:
            data_dict = json.loads(decoded_str)
            for elem in data_dict:
                if elem["Method"] == "PS":
                    config_dict["PowerShell module"] = elem

        if b"Path" in decoded_str:
            grabber_found = True
            break
        else:
            grabber_match = re.search(b"W3siUGF0aCI6.{116}", data)
            if grabber_match:
                encoded_string = grabber_match.group(0)
                decoded_str = base64.b64decode(encoded_string)
                grabber_str = decoded_str[:95].decode("utf-8", errors="ignore")
                cleanup_str = grabber_str.split("[")[-1].split("]")[0]

                if not grabber_found:
                    grabber_found = True
                    config_dict["Grabber"] = cleanup_str

    return config_dict
