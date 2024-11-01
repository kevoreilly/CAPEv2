import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.Hancitor import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="Hancitor", other=raw_config)

    for url in raw_config.get("address", []):
        parsed_result.http.append(MACOModel.Http(uri=url, usage="c2"))

    if "Build ID" in raw_config:
        parsed_result.identifier.append(raw_config["Build ID"])

    return parsed_result


class Hancitor(Extractor):
    author = "kevoreilly"
    family = "Hancitor"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
