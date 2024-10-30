import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.AsyncRAT import extract_config


def convert_to_MACO(raw_config: dict) -> MACOModel:
    if not raw_config:
        return

    parsed_result = MACOModel(family="AsyncRAT", other=raw_config)

    # Mutex
    parsed_result.mutex.append(raw_config["Mutex"])

    # Version
    parsed_result.version = raw_config["Version"]

    # Was persistence enabled?
    if raw_config["Install"] == "true":
        parsed_result.capability_enabled.append("persistence")
    else:
        parsed_result.capability_disabled.append("persistence")

    # Installation Path
    if raw_config.get("Folder"):
        parsed_result.paths.append(MACOModel.Path(path=os.path.join(raw_config["Folder"], raw_config["Filename"]), usage="install"))

    # C2s
    for i in range(len(raw_config.get("C2s", []))):
        parsed_result.http.append(MACOModel.Http(hostname=raw_config["C2s"][i], port=int(raw_config["Ports"][i]), usage="c2"))
    # Pastebin
    if raw_config.get("Pastebin") not in ["null", None]:
        # TODO: Is it used to download the C2 information if not embedded?
        # Ref: https://www.netskope.com/blog/asyncrat-using-fully-undetected-downloader
        parsed_result.http.append(MACOModel.Http(uri=raw_config["Pastebin"], usage="download"))

    return parsed_result


class AsyncRAT(Extractor):
    author = "kevoreilly"
    family = "AsyncRAT"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
