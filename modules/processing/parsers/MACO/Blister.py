import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.Blister import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="Blister", other=raw_config)

    for capa in ["Persistence", "Sleep after injection"]:
        if raw_config[capa]:
            parsed_result.capability_enabled.append(capa)
        else:
            parsed_result.capability_disabled.append(capa)

    # Rabbit encryption
    parsed_result.encryption.append(
        MACOModel.Encryption(algorithm="rabbit", key=raw_config["Rabbit key"], iv=raw_config["Rabbit IV"])
    )
    return parsed_result


class Blister(Extractor):
    author = "kevoreilly"
    family = "Blister"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
