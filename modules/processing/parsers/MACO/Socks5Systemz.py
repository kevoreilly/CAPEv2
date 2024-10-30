import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.Socks5Systemz import extract_config


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(
        family="Socks5Systemz",
        other=raw_config,
        http=[MACOModel.Http(hostname=c2, usage="c2") for c2 in raw_config.get("C2s", [])]
        + [MACOModel.Http(hostname=decoy, usage="decoy") for decoy in raw_config.get("Dummy domain", [])],
    )

    return parsed_result


class Socks5Systemz(Extractor):
    author = "kevoreilly"
    family = "Socks5Systemz"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
