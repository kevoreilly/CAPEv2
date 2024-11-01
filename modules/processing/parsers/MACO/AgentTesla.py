import os

from maco.extractor import Extractor
from maco.model import ExtractorModel as MACOModel

from modules.processing.parsers.CAPE.AgentTesla import extract_config


def convert_to_MACO(raw_config: dict) -> MACOModel:
    if not raw_config:
        return

    protocol = raw_config.get("Protocol")
    if not protocol:
        return

    parsed_result = MACOModel(family="AgentTesla", other=raw_config)
    if protocol == "Telegram":
        parsed_result.http.append(MACOModel.Http(uri=raw_config["C2"], password=raw_config["Password"], usage="c2"))

    elif protocol in ["HTTP(S)", "Discord"]:
        parsed_result.http.append(MACOModel.Http(uri=raw_config["C2"], usage="c2"))

    elif protocol == "FTP":
        parsed_result.ftp.append(
            MACOModel.FTP(
                username=raw_config["Username"],
                password=raw_config["Password"],
                hostname=raw_config["C2"].replace("ftp://", ""),
                usage="c2",
            )
        )

    elif protocol == "SMTP":
        smtp = dict(
            username=raw_config["Username"],
            password=raw_config["Password"],
            hostname=raw_config["C2"],
            mail_to=[raw_config["EmailTo"]],
            usage="c2",
        )
        if "Port" in raw_config:
            smtp["port"] = raw_config["Port"]
        parsed_result.smtp.append(MACOModel.SMTP(**smtp))

    if "Persistence_Filename" in raw_config:
        parsed_result.paths.append(MACOModel.Path(path=raw_config["Persistence_Filename"], usage="storage"))

    if "ExternalIPCheckServices" in raw_config:
        for service in raw_config["ExternalIPCheckServices"]:
            parsed_result.http.append(MACOModel.Http(uri=service, usage="other"))

    return parsed_result


class AgentTesla(Extractor):
    author = "kevoreilly"
    family = "AgentTesla"
    last_modified = "2024-10-20"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split("/modules", 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
