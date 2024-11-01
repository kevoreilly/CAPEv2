from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.BackOffPOS import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="BackOffPOS", other=raw_config)

    # Version
    parsed_result.version = raw_config["Version"]

    # Encryption details
    parsed_result.encryption.append(
        MACOModel.Encryption(algorithm="rc4", key=raw_config["EncryptionKey"], seed=raw_config["RC4Seed"])
    )
    for url in raw_config["URLs"]:
        parsed_result.http.append(MACOModel.Http(url=url))

    return parsed_result


class BackOffPOS(Extractor):
    author = "kevoreilly"
    family = "BackOffPOS"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
