from copy import deepcopy

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.NanoCore import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="NanoCore", other=raw_config)

    config_copy = deepcopy(raw_config)
    capabilities = {k: config_copy.pop(k) for k in list(config_copy.keys()) if config_copy[k] in ["True", "False"]}

    if "Version" in config_copy:
        parsed_result.version = config_copy.pop("Version")

    if "Mutex" in config_copy:
        parsed_result.mutex.append(config_copy.pop("Mutex"))

    for capability, enabled in capabilities.items():
        if enabled.lower() == "true":
            parsed_result.capability_enabled.append(capability)
        else:
            parsed_result.capability_disabled.append(capability)

    for address in config_copy.pop("cncs", []):
        host, port = address.split(":")
        parsed_result.http.append(MACOModel.Http(hostname=host, port=port, usage="c2"))

    return parsed_result


class NanoCore(Extractor):
    author = "kevoreilly"
    family = "NanoCore"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
