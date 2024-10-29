import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.GuLoader import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="GuLoader", other=raw_config)

    for url in raw_config.get("URLs", []):
        parsed_result.http.append(MACOModel.Http(uri=url, usage="download"))

    return parsed_result


class GuLoader(Extractor):
    author = "kevoreilly"
    family = "GuLoader"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], "data/yara/CAPE/Guloader.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
