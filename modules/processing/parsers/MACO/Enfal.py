from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.Enfal import extract_config, rule_source


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    # TODO: Assign fields to MACO model
    parsed_result = MACOModel(family="Enfal", other=raw_config)

    return parsed_result


class Enfal(Extractor):
    author = "kevoreilly"
    family = "Enfal"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
