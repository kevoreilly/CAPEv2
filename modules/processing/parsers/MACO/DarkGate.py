import os
from copy import deepcopy

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.DarkGate import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="DarkGate", other=raw_config)

    # Create a copy of the raw configuration for parsing
    config = deepcopy(raw_config)

    # Go through capabilities/settings that are boolean in nature
    for k, v in list(config.items()):
        if v not in ["Yes", "No"]:
            continue

        if v == "Yes":
            parsed_result.capability_enabled.append(k)
        else:
            parsed_result.capability_disabled.append(k)

        # Remove key from raw config
        config.pop(k)

    # C2
    c2_port = config.pop("c2_port", None)
    for c2_url in config.pop("C2", []):
        parsed_result.http.append(MACOModel.Http(uri=c2_url, port=c2_port, usage="c2"))

    # Mutex
    if config.get("internal_mutex"):
        parsed_result.mutex.append(config.pop("internal_mutex"))

    return parsed_result


class DarkGate(Extractor):
    author = "kevoreilly"
    family = "DarkGate"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
