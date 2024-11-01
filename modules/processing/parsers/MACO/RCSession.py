from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.RCSession import extract_config, rule_source


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="RCSession", other=raw_config)

    for address in raw_config.get("c2_address", []):
        parsed_result.http.append(MACOModel.Http(hostname=address, usage="c2"))

    if "directory" in raw_config:
        parsed_result.paths.append(MACOModel.Path(path=raw_config["directory"], usage="install"))

    service = {}

    if "servicename" in raw_config:
        service["name"] = raw_config["servicename"]
    if "servicedisplayname" in raw_config:
        service["display_name"] = raw_config["servicedisplayname"]
    if "servicedescription" in raw_config:
        service["description"] = raw_config["servicedescription"]
    if "filename" in raw_config:
        service["dll"] = raw_config["filename"]

    if service:
        parsed_result.service.append(MACOModel.Service(**service))

    return parsed_result


class RCSession(Extractor):
    author = "kevoreilly"
    family = "RCSession"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
