from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.SmallNet import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="SmallNet", other=raw_config)

    return parsed_result


class SmallNet(Extractor):
    author = "kevoreilly"
    family = "SmallNet"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"

    def run(self, stream, matches):
        output = extract_config(stream.read())
        if output:
            config = output if isinstance(output, dict) else output[0]
            return convert_to_MACO(config)
