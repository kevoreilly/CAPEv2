from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.ChChes import extract_config, rule_source


def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="ChChes", other=raw_config)

    # C2 URLs
    for c2_url in raw_config.get("c2_url", []):
        parsed_result.http.append(MACOModel.Http(uri=c2_url, usage="c2"))

    return parsed_result


class ChChes(Extractor):
    author = "kevoreilly"
    family = "ChChes"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = rule_source

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
