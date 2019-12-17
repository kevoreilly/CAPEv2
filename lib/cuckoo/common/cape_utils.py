from __future__ import absolute_import
import os
import imp
import sys
import glob
import logging
import tempfile
import hashlib
import subprocess
from io import BytesIO
from collections import Mapping, Iterable

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import CAPE_YARA_RULEPATH, File

malware_parsers = {}
#Import All config parsers
try:
    import mwcp
    mwcp.register_parser_directory(os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "mwcp"))
    malware_parsers = {block.name.split(".")[-1]:block.name for block in mwcp.get_parser_descriptions(config_only=False)}
    HAS_MWCP = True

    #disable logging
    #[mwcp.parser] WARNING: Missing identify() function for: a35a622d01f83b53d0407a3960768b29.Emotet.Emotet
except ImportError:
    HAS_MWCP = False
    print("Missed MWCP -> pip3 install git+https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP")

try:
    from malwareconfig import fileparser
    from malwareconfig.modules import __decoders__, __preprocessors__
    HAS_MALWARECONFIGS = True
except ImportError:
    HAS_MALWARECONFIGS = False
    print("Missed RATDecoders -> pip3 install git+https://github.com/kevthehermit/RATDecoders")

cape_decoders = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "malwareconfig")
CAPE_DECODERS = [
    os.path.basename(decoder)[:-3]
    for decoder in glob.glob(cape_decoders + "/[!_]*.py")
]

for name in CAPE_DECODERS:
    try:
        file, pathname, description = imp.find_module(name, [CAPE_DECODERS])
        module = imp.load_module(name, file, pathname, description)
        malware_parsers[name] = module
    except (ImportError, IndexError) as e:
        print("CAPE parser: No module named %s - %s", (name, e))

parser_path = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers")
if parser_path not in sys.path:
    sys.path.append(parser_path)

try:
    from plugxconfig import plugx
except ImportError as e:
    print(e)

suppress_parsing_list = ["Cerber", "Emotet_Payload", "Ursnif", "QakBot"]

log = logging.getLogger(__name__)

pe_map = {
    "PE32+": ": 64-bit ",
    "PE32": ": 32-bit ",
}


cfg = Config()
BUFSIZE = int(cfg.processing.analysis_size_limit)

def hash_file(method, path):
    """Calculates an hash on a file by path.
    @param method: callable hashing method
    @param path: file path
    @return: computed hash string
    """
    f = open(path, "rb")
    h = method()
    while True:
        buf = f.read(BUFSIZE)
        if not buf:
            break
        h.update(buf)
    return h.hexdigest()

def upx_harness(raw_data):
    upxfile = tempfile.NamedTemporaryFile(delete=False)
    upxfile.write(raw_data)
    upxfile.close()
    try:
        ret = subprocess.call("(upx -d %s)" % upxfile.name, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        log.error("CAPE: UPX Error %s", e)
        os.unlink(upxfile.name)
        return

    if ret == 0:
        sha256 = hash_file(hashlib.sha256, upxfile.name)
        newname = os.path.join(os.path.dirname(upxfile.name), sha256)
        os.rename(upxfile.name, newname)
        log.info("CAPE: UPX - Statically unpacked binary %s.", upxfile.name)
        return newname
    elif ret == 127:
        log.error("CAPE: Error - UPX not installed.")
    elif ret == 2:
        log.error("CAPE: Error - UPX 'not packed' exception.")
    else:
        log.error("CAPE: Unknown error - check UPX is installed and working.")

    os.unlink(upxfile.name)
    return

def convert(data):
    if isinstance(data, str):
        return str(data)
    elif isinstance(data, Mapping):
        return dict(list(map(convert, data.items())))
    elif isinstance(data, Iterable):
        return type(data)(list(map(convert, data)))
    else:
        return data

def static_config_parsers(yara_hit, file_data, cape_config):
    # Process CAPE Yara hits

        cape_name = yara_hit.replace('_', ' ')
        cape_config = dict()
        parser_loaded = False
        # Attempt to import a parser for the hit
        # DC3-MWCP

        if "cape_config" not in cape_config:
            cape_config.setdefault("cape_config", dict())

        if cape_name and HAS_MWCP and cape_name in malware_parsers:
            try:
                reporter = mwcp.Reporter()
                reporter.run_parser(malware_parsers[cape_name], data=file_data)
                if reporter.errors == []:
                    log.info("CAPE: Imported DC3-MWCP parser %s", cape_name)
                    parser_loaded = True
                    try:
                        tmp_dict = dict()
                        if reporter.metadata.get("debug"):
                            del reporter.metadata["debug"]
                        if reporter.metadata.get("other"):
                            for key, value in reporter.metadata["other"].items():
                                tmp_dict.setdefault(key, [])
                                if value not in tmp_dict[key]:
                                    tmp_dict[key].append(value)
                            del reporter.metadata["other"]

                        tmp_dict.update(reporter.metadata)

                        if "cape_config" not in cape_config:
                            cape_config.setdefault("cape_config", dict())
                            #ToDo do we really need to convert it?
                            cape_config["cape_config"] = convert(tmp_dict)
                        else:
                            cape_config["cape_config"].update(convert(tmp_dict))
                    except Exception as e:
                        log.error("CAPE: DC3-MWCP config parsing error with %s: %s", cape_name, e)
                else:
                    error_lines = reporter.errors[0].split("\n")
                    for line in error_lines:
                        if line.startswith('ImportError: '):
                            log.info("CAPE: DC3-MWCP parser: %s", line.split(': ')[1])
                reporter._Reporter__cleanup()
                del reporter
            except (ImportError, IndexError) as e:
                log.error(e)

            if not parser_loaded and cape_name in malware_parsers:
                parser_loaded = True
                try:
                    cape_config = malware_parsers[cape_name].config(file_data)
                    if isinstance(cape_config, list):
                        for (key, value) in cape_config[0].items():
                            cape_config["cape_config"].update({key: [value]})
                    elif isinstance(cape_config, dict):
                        for (key, value) in cape_config.items():
                            cape_config["cape_config"].update({key: [value]})
                except Exception as e:
                    log.error("CAPE: parsing error with %s: %s", cape_name, e)

            if not parser_loaded and cape_name in __decoders__:
                try:
                    file_info = fileparser.FileParser(rawdata=file_data)
                    module = __decoders__[file_info.malware_name]['obj']()
                    module.set_file(file_info)
                    module.get_config()
                    malwareconfig_config = module.config
                    #ToDo remove
                    if isinstance(malwareconfig_config, list):
                        for (key, value) in malwareconfig_config[0].items():
                            cape_config["cape_config"].update({key: [value]})
                    elif isinstance(malwareconfig_config, dict):
                        for (key, value) in malwareconfig_config.items():
                            cape_config["cape_config"].update({key: [value]})
                except Exception as e:
                    log.error("CAPE: malwareconfig parsing error with %s: %s", cape_name, e)

            if "cape_config" in cape_config:
                if cape_config["cape_config"] == {}:
                    del cape_config["cape_config"]

        return cape_config

def static_extraction(path):
    cape_config = dict()
    try:
        hits = File(path).get_yara(CAPE_YARA_RULEPATH)
        if not hits:
            return False
        # ToDo not public
        if any([hit["name"].endswith("_TCR") for hit in hits]):
            return True
        # Get the file data
        with open(path, "r") as file_open:
            file_data = file_open.read()
        for hit in hits:
            config = static_config_parsers(hit["name"], file_data, cape_config)
            if config:
                return config
        return False
    except Exception as e:
        log.error(e)

    return False
