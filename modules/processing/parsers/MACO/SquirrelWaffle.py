from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.SquirrelWaffle import extract_config, rule_source


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(
        family="SquirrelWaffle", other=raw_config, http=[MACOModel.Http(uri=c2, usage="c2") for c2 in raw_config["URLs"]]
    )

    return parsed_result


class SquirrelWaffle(Extractor):
    author = "kevoreilly"
    family = "SquirrelWaffle"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
