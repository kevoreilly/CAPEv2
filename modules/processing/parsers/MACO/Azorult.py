from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.Azorult import extract_config, rule_source


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    return MACOModel(family="Azorult", http=[MACOModel.Http(hostname=raw_config["address"])], other=raw_config)


class Azorult(Extractor):
    author = "kevoreilly"
    family = "Azorult"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
