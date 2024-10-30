from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.BitPaymer import extract_config, rule_source


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="BitPaymer", other=raw_config)

    # Extracted strings
    parsed_result.decoded_strings = raw_config["strings"]

    # Encryption details
    parsed_result.encryption.append(MACOModel.Encryption(algorithm="rsa", public_key=raw_config["RSA public key"]))
    return parsed_result


class BitPaymer(Extractor):
    author = "kevoreilly"
    family = "BitPaymer"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
