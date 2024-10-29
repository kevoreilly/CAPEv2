import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.BlackNix import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="BlackNix", other=raw_config)

    # Mutex
    parsed_result.mutex.append(raw_config["Mutex"])

    # Capabilities that are enabled/disabled
    # TODO: Review if these are all capabilities set by a boolean flag
    for capa in [
        "Anti Sandboxie",
        "Kernel Mode Unhooking",
        "User Mode Unhooking",
        "Melt Server",
        "Offline Screen Capture",
        "Offline Keylogger",
        "Copy to ADS",
        "Safe Mode Startup",
        "Inject winlogon.exe",
        "Active X Run",
        "Registry Run",
    ]:
        if raw_config[capa].lower() == "true":
            parsed_result.capability_enabled.append(capa)
        else:
            parsed_result.capability_disabled.append(capa)

    # Delay Time
    parsed_result.sleep_delay = raw_config["Delay Time"]

    # Password
    parsed_result.password.append(raw_config["Password"])

    # C2 Domain
    parsed_result.http.append(MACOModel.Http(hostname=raw_config["Domain"], usage="c2"))
    # Registry
    parsed_result.registry.append(MACOModel.Registry(key=raw_config["Registry Key"]))

    # Install Path
    parsed_result.paths.append(
        MACOModel.Path(path=os.path.join(raw_config["Install Path"], raw_config["Install Name"]), usage="install")
    )

    # Campaign Group/Name
    parsed_result.campaign_id = [raw_config["Campaign Name"], raw_config["Campaign Group"]]
    return parsed_result


class BlackNix(Extractor):
    author = "kevoreilly"
    family = "BlackNix"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
