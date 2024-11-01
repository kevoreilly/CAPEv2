import os
from copy import deepcopy

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.Punisher import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    config_copy = deepcopy(raw_config)
    parsed_result = MACOModel(
        family="Punisher",
        campaign_id=config_copy["Campaign Name"],
        password=[config_copy["Password"]],
        registry=[MACOModel.Registry(key=config_copy["Registry Key"])],
        paths=[MACOModel.Path(path=os.path.join(config_copy["Install Path"], config_copy["Install Name"]))],
        http=[MACOModel.Http(hostname=config_copy["Domain"], port=config_copy["Port"])],
        other=raw_config,
    )

    for field in raw_config.keys():
        value = raw_config[field]
        if value.lower() == "true":
            parsed_result.capability_enabled.append(field)
        elif value.lower() == "false":
            parsed_result.capability_disabled.append(field)
        else:
            parsed_result.other[field] = value

    return parsed_result


class Punisher(Extractor):
    author = "kevoreilly"
    family = "Punisher"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"

    def run(self, stream, matches):
        output = extract_config(stream.read())
        if output:
            return convert_to_MACO(output[0])
