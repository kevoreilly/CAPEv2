import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.BuerLoader import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="BuerLoader", other=raw_config)

    for c2 in raw_config["address"]:
        parsed_result.http.append(MACOModel.Http(hostname=c2, usage="c2"))
    return parsed_result


class BuerLoader(Extractor):
    author = "kevoreilly"
    family = "BuerLoader"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
