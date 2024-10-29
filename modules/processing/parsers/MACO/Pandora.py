import os
from copy import deepcopy

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.Pandora import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    config_copy = deepcopy(raw_config)
    parsed_result = MACOModel(
        family="Pandora",
        mutex=[config_copy.pop("Mutex")],
        campaign_id=[config_copy.pop("Campaign ID")],
        version=config_copy.pop("Version"),
        http=[dict(hostname=config_copy.pop("Domain"), port=config_copy.pop("Port"), password=config_copy.pop("Password"))],
        other=raw_config,
    )

    parsed_result.paths.append(
        MACOModel.Path(path=os.path.join(config_copy.pop("Install Path"), config_copy.pop("Install Name")), usage="install")
    )

    parsed_result.registry.append(MACOModel.Registry(key=config_copy.pop("HKCU Key")))
    parsed_result.registry.append(MACOModel.Registry(key=config_copy.pop("ActiveX Key")))

    for field in list(config_copy.keys()):
        # TODO: Unsure what's the value of the remaining fields
        if config_copy[field].lower() in ["true", "false"]:
            enabled = config_copy.pop(field).lower() == "true"
            if enabled:
                parsed_result.capability_enabled.append(field)
            else:
                parsed_result.capability_disabled.append(field)

    return parsed_result


class Pandora(Extractor):
    author = "kevoreilly"
    family = "Pandora"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
