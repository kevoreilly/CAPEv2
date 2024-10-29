import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.CobaltStrikeBeacon import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="CobaltStrikeBeacon", other=raw_config)

    clean_config = {k: v for k, v in raw_config.items() if v != "Not Found"}
    capabilities = {k[1:]: clean_config.pop(k) for k in list(clean_config.keys()) if clean_config[k] in ["True", "False"]}

    for capability, enabled in capabilities.items():
        if enabled.lower() == "true":
            parsed_result.capability_enabled.append(capability)
        else:
            parsed_result.capability_disabled.append(capability)

    if "C2Server" in clean_config:
        host, get_path = clean_config.pop("C2Server").split(",")
        port = clean_config.pop("Port")
        parsed_result.http.append(MACOModel.Http(hostname=host, port=port, method="GET", path=get_path, usage="c2"))
        parsed_result.http.append(
            MACOModel.Http(hostname=host, port=port, method="POST", path=clean_config.pop("HttpPostUri"), usage="c2")
        )

    parsed_result.sleep_delay = clean_config.pop("SleepTime")
    parsed_result.sleep_delay_jitter = clean_config.pop("Jitter")

    for path_key in ["Spawnto_x86", "Spawnto_x64"]:
        if path_key in clean_config:
            parsed_result.paths.append(MACOModel.Path(path=clean_config.pop(path_key)))

    return parsed_result


class CobaltStrikeBeacon(Extractor):
    author = "kevoreilly"
    family = "CobaltStrikeBeacon"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
