import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.SparkRAT import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="SparkRAT", other=raw_config)

    url = f"http{'s' if raw_config['secure'] else ''}://{raw_config['host']}:{raw_config['port']}{raw_config['path']}"

    parsed_result.http.append(
        MACOModel.Http(uri=url, hostname=raw_config["host"], port=raw_config["port"], path=raw_config["path"])
    )

    parsed_result.identifier.append(raw_config["uuid"])

    return parsed_result


class SparkRAT(Extractor):
    author = "kevoreilly"
    family = "SparkRAT"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
