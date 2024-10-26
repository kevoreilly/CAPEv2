import os
from maco.model import ExtractorModel as MACOModel
from maco.extractor import Extractor
from modules.processing.parsers.CAPE.AuroraStealer import extract_config

def convert_to_MACO(raw_config: dict):
    if not raw_config:
        return None

    parsed_result = MACOModel(family="AuroraStealer")
    if raw_config.get('C2'):
        # IP related to C2
        parsed_result.http.append(MACOModel.Http(hostname=raw_config['C2'],
                                                 usage="c2"))

    # TODO: We may want to update MACO to account for these?
    # Ref: https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-aurora-stealer
    #parsed_result.other = {k: raw_config[k] for k in ['Loader module', 'Powershell module', 'Grabber'] if raw_config.get(k)}

    # TODO: Unsure what the other possible keys might be and how they should be organized (line 54)
    # For now we'll assign the entirety of the raw config to other
    parsed_result.other = raw_config

    return parsed_result

class AuroraStealer(Extractor):
    author = "kevoreilly"
    family = "AuroraStealer"
    last_modified = "2024-10-26"
    sharing = "TLP:CLEAR"
    yara_rule = open(os.path.join(os.path.dirname(__file__).split('/modules', 1)[0], f"data/yara/CAPE/{family}.yar")).read()

    def run(self, stream, matches):
        return convert_to_MACO(extract_config(stream.read()))
