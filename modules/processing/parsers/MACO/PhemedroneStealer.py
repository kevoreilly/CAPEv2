from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.PhemedroneStealer import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="PhemedroneStealer", other=raw_config)

    return parsed_result


class PhemedroneStealer(Extractor):
    author = "kevoreilly"
    family = "PhemedroneStealer"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
