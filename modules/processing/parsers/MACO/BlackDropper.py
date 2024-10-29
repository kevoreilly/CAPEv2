import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.BlackDropper import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="BlackDropper", campaign_id=[raw_config["campaign"]], other=raw_config)

    for dir in raw_config.get("directories", []):
        parsed_result.paths.append(MACOModel.Path(path=dir))

    for url in raw_config.get("urls", []):
        parsed_result.http.append(MACOModel.Http(uri=url))

    return parsed_result


class BlackDropper(Extractor):
    author = "kevoreilly"
    family = "BlackDropper"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
