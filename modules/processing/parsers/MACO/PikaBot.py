from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.PikaBot import extract_config, rule_source


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="PikaBot", other=raw_config)

    if "C2" in raw_config:
        [parsed_result.http.append(MACOModel.Http(uri=c2, usage="c2")) for c2 in raw_config["C2"]]
        parsed_result.binaries.append(MACOModel.Binary(datatype="payload", data=raw_config["Powershell"]))
    elif "C2s" in raw_config:
        parsed_result.version = raw_config["Version"]
        parsed_result.campaign_id.append(raw_config["Campaign Name"])
        parsed_result.registry.append(MACOModel.Registry(key=raw_config["Registry Key"]))
        for c2 in raw_config["C2s"]:
            host, port = c2.split(":")
            parsed_result.http.append(MACOModel.Http(hostname=host, port=port, user_agent=raw_config["User Agent"]))

    return parsed_result


class PikaBot(Extractor):
    author = "kevoreilly"
    family = "PikaBot"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
