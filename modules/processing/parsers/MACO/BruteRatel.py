import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.BruteRatel import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="BruteRatel", other=raw_config)

    for url in raw_config["C2"]:
        for path in raw_config["URI"]:
            parsed_result.http.append(
                MACOModel.Http(uri=url, user_agent=raw_config["User Agent"], port=raw_config["Port"], path=path, usage="c2")
            )

    return parsed_result


class BruteRatel(Extractor):
    author = "kevoreilly"
    family = "BruteRatel"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
