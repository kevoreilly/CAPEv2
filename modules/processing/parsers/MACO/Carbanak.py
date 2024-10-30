from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.Carbanak import extract_config, rule_source


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="Carbanak", other=raw_config)

    # Version
    if raw_config.get("Version"):
        parsed_result.version = raw_config["Version"]

    # Unknown strings
    for i in [1, 2]:
        if raw_config.get(f"Unknown {i}"):
            parsed_result.decoded_strings.append(raw_config[f"Unknown {i}"])

    # C2
    if raw_config.get("C2"):
        if isinstance(raw_config["C2"], str):
            parsed_result.http.append(MACOModel.Http(hostname=raw_config["C2"], usage="c2"))
        else:
            for c2 in raw_config["C2"]:
                parsed_result.http.append(MACOModel.Http(hostname=c2, usage="c2"))

    # Campaign Id
    if raw_config.get("Campaign Id"):
        parsed_result.campaign_id.append(raw_config["Campaign Id"])

    return parsed_result


class Carbanak(Extractor):
    author = "kevoreilly"
    family = "Carbanak"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
