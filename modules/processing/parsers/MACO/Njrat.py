from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.Njrat import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="Njrat", other=raw_config)

    if "version" in raw_config:
        parsed_result.version = raw_config["version"]

    if "campaign_id" in raw_config:
        parsed_result.campaign_id.append(raw_config["campaign_id"])

    for c2 in raw_config.get("cncs", []):
        host, port = c2.split(":")
        parsed_result.http.append(MACOModel.Http(hostname=host, port=port, usage="c2"))

    return parsed_result


class Njrat(Extractor):
    author = "kevoreilly"
    family = "Njrat"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
