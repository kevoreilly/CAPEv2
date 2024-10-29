from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.EvilGrab import extract_config, rule_source


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="EvilGrab", other=raw_config)

    if "mutex" in raw_config:
        parsed_result.mutex.append(raw_config["mutex"])

    if "missionid" in raw_config:
        parsed_result.campaign_id.append(raw_config["missionid"])

    if "version" in raw_config:
        parsed_result.version = raw_config["version"]

    if "c2_address" in raw_config:
        parsed_result.http.append(
            parsed_result.Http(uri=raw_config["c2_address"], port=raw_config["port"][0] if "port" in raw_config else None)
        )

    return parsed_result


class EvilGrab(Extractor):
    author = "kevoreilly"
    family = "EvilGrab"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
