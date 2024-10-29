from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.PoisonIvy import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="PoisonIvy", other=raw_config)

    if "Campaign ID" in raw_config:
        parsed_result.campaign_id.append(raw_config["Campaign ID"])
    if "Group ID" in raw_config:
        parsed_result.identifier.append(raw_config["Group ID"])
    if "Domains" in raw_config:
        for domain_port in raw_config["Domains"].split("|"):
            host, port = domain_port.split(":")
            parsed_result.http.append(MACOModel.Http(hostname=host, port=port))
    if "Password" in raw_config:
        parsed_result.password.append(raw_config["Password"])
    if "Mutex" in raw_config:
        parsed_result.mutex.append(raw_config["Mutex"])

    for field in list(raw_config.keys()):
        value = raw_config[field]
        if value.lower() == "true":
            parsed_result.capability_enabled.append(field)
        elif value.lower() == "false":
            parsed_result.capability_disabled.append(field)

    return parsed_result


class PoisonIvy(Extractor):
    author = "kevoreilly"
    family = "PoisonIvy"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"

    def run(self, stream, matches):
        output = extract_config(stream.read())
        if output:
            return convert_to_MACO(output[0])
