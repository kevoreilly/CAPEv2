from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.DridexLoader import extract_config, rule_source


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="DridexLoader", other=raw_config)

    for c2_address in raw_config.get("address", []):
        parsed_result.http.append(MACOModel.Http(uri=c2_address, usage="c2"))

    if "RC4 key" in raw_config:
        parsed_result.encryption.append(MACOModel.Encryption(algorithm="RC4", key=raw_config["RC4 key"]))

    if "Botnet ID" in raw_config:
        parsed_result.identifier.append(raw_config["Botnet ID"])

    return parsed_result


class DridexLoader(Extractor):
    author = "kevoreilly"
    family = "DridexLoader"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
