from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.Stealc import RULE_SOURCE, extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(
        family="Stealc", other=raw_config, http=[MACOModel.Http(uri=c2, usage="c2") for c2 in raw_config["C2"]]
    )

    return parsed_result


class Stealc(Extractor):
    author = "kevoreilly"
    family = "Stealc"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = RULE_SOURCE

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
