from __future__ import absolute_import
import os
import sys
import glob
import json
import importlib
import logging
import tempfile
import hashlib
import subprocess
from io import BytesIO
from collections import Mapping, Iterable

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File

log = logging.getLogger(__name__)

malware_parsers = dict()
cape_malware_parsers = dict()

# Config variables
cfg = Config()
repconf = Config("reporting")
processing_conf = Config("processing")

if repconf.mongodb.enabled:
    import pymongo
    results_db = pymongo.MongoClient(
        repconf.mongodb.host,
        port=repconf.mongodb.port,
        username=repconf.mongodb.get("username", None),
        password=repconf.mongodb.get("password", None),
        authSource = repconf.mongodb.get("authsource", "cuckoo")
    )[repconf.mongodb.db]

try:
    import pefile
    HAVE_PEFILE = True
except ImportError:
    print("Missed pefile library. Install it with: pip3 install pefile")
    HAVE_PEFILE = False

# Import All config parsers
try:
    import mwcp

    logging.getLogger("mwcp").setLevel(logging.CRITICAL)
    mwcp.register_parser_directory(os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "mwcp"))
    malware_parsers = {block.name.split(".")[-1]: block.name for block in mwcp.get_parser_descriptions(config_only=False)}
    HAS_MWCP = True
except ImportError as e:
    HAS_MWCP = False
    log.info("Missed MWCP -> pip3 install git+https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP\nDetails: {}".format(e))

try:
    from malwareconfig import fileparser
    from malwareconfig.modules import __decoders__, __preprocessors__

    HAS_MALWARECONFIGS = True
except ImportError:
    HAS_MALWARECONFIGS = False
    log.info("Missed RATDecoders -> pip3 install git+https://github.com/kevthehermit/RATDecoders")
except Exception as e:
    log.error(e, exc_info=True)
"""
try:
    # https://github.com/CERT-Polska/malduck/blob/master/tests/test_extractor.py
    from malduck import procmem, procmempe
    from malduck.extractor import ExtractorModules, ExtractManager
    malduck_modules = ExtractorModules(os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "malduck"))
    HAVE_MALDUCK = True
except ImportError:
    HAVE_MALDUCK = False
    log.info("Missed MalDuck -> pip3 install git+https://github.com/CERT-Polska/malduck/")
"""

cape_module_path = "modules.processing.parsers.CAPE."
cape_decoders = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "CAPE")
CAPE_DECODERS = [os.path.basename(decoder)[:-3] for decoder in glob.glob(cape_decoders + "/[!_]*.py")]

for name in CAPE_DECODERS:
    try:
        cape_malware_parsers[name] = importlib.import_module(cape_module_path + name)
    except (ImportError, IndexError) as e:
        if "datadirs" in str(e):
            log.error("You are using wrong pype32 library. pip3 uninstall pype32 && pip3 install -U pype32-py3")
        log.warning("CAPE parser: No module named {} - {}".format(name, e))

parser_path = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "CAPE")
if parser_path not in sys.path:
    sys.path.append(parser_path)

try:
    from modules.processing.parsers.plugxconfig import plugx

    plugx_parser = plugx.PlugXConfig()
except ImportError as e:
    plugx_parser = False
    log.error(e)

suppress_parsing_list = ["Cerber", "Emotet_Payload", "Ursnif", "QakBot"]

pe_map = {
    "PE32+": ": 64-bit ",
    "PE32": ": 32-bit ",
}


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
    elif ret == 1:
        log.error("CAPE: Error - UPX CantUnpackException")
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


def static_config_parsers(yara_hit, file_data):
    """Process CAPE Yara hits"""
    cape_name = yara_hit.replace("_", " ")
    cape_config = dict()
    cape_config[cape_name] = dict()
    parser_loaded = False
    # Attempt to import a parser for the hit
    # DC3-MWCP

    if cape_name and HAS_MWCP and cape_name in malware_parsers:
        try:
            reporter = mwcp.Reporter()
            reporter.run_parser(malware_parsers[cape_name], data=file_data)
            if not reporter.errors:
                parser_loaded = True
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
                cape_config[cape_name] = convert(tmp_dict)
                log.debug("CAPE: DC3-MWCP parser for %s completed", cape_name)
            else:
                error_lines = reporter.errors[0].split("\n")
                for line in error_lines:
                    if line.startswith("ImportError: "):
                        log.debug("CAPE: DC3-MWCP parser: %s", line.split(": ")[1])
            reporter._Reporter__cleanup()
            del reporter
        except pefile.PEFormatError:
            log.error("pefile PEFormatError")
        except Exception as e:
            log.error("CAPE: DC3-MWCP config parsing error with {}: {}".format(cape_name, e))

    if not parser_loaded and cape_name in cape_malware_parsers:
        try:
            # changed from cape_config to cape_configraw because of avoiding overridden. duplicated value name.
            cape_configraw = cape_malware_parsers[cape_name].config(file_data)
            if isinstance(cape_configraw, list):
                for (key, value) in cape_configraw[0].items():
                    # python3 map object returns iterator by default, not list and not serializeable in JSON.
                    if isinstance(value, map):
                        value = list(value)
                    cape_config[cape_name].update({key: [value]})
            elif isinstance(cape_configraw, dict):
                for (key, value) in cape_configraw.items():
                    # python3 map object returns iterator by default, not list and not serializeable in JSON.
                    if isinstance(value, map):
                        value = list(value)
                    cape_config[cape_name].update({key: [value]})
        except Exception as e:
            log.error("CAPE: parsing error with {}: {}".format(cape_name, e))

    elif HAS_MALWARECONFIGS and not parser_loaded and cape_name in __decoders__:
        try:
            file_info = fileparser.FileParser(rawdata=file_data)
            module = __decoders__[file_info.malware_name]["obj"]()
            module.set_file(file_info)
            module.get_config()
            malwareconfig_config = module.config
            # ToDo remove
            if isinstance(malwareconfig_config, list):
                for (key, value) in malwareconfig_config[0].items():
                    cape_config[cape_name].update({key: [value]})
            elif isinstance(malwareconfig_config, dict):
                for (key, value) in malwareconfig_config.items():
                    cape_config[cape_name].update({key: [value]})
        except Exception as e:
            log.warning("malwareconfig parsing error with %s: %s, you should submit issue/fix to https://github.com/kevthehermit/RATDecoders/", cape_name, e,)

        if cape_name in cape_config and cape_config[cape_name] == {}:
            return {}

    return cape_config

def static_config_lookup(file_path, sha256=False):
    if not sha256:
        sha256 = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
    cape_tasks = results_db.analysis.find({"target.file.sha256": sha256}, {"CAPE.cape_config":1, "info.id": 1, "_id":0})
    for task in cape_tasks or []:
        if task.get("cape_config") and task["cape_config"]:
            return task

def static_extraction(path):
    try:
        hits = File(path).get_yara(category="CAPE")
        if not hits:
            return False
        # Get the file data
        with open(path, "rb") as file_open:
            file_data = file_open.read()
        for hit in hits:
            config = static_config_parsers(hit["name"], file_data)
            if config:
                return config
        return False
    except Exception as e:
        log.error(e)

    return False

def cape_name_from_yara(details, pid, results):
    for hit in details.get("cape_yara", []) or []:
        if "meta" in hit and any([file_type in hit["meta"].get("cape_type", "").lower() for file_type in ("payload", "config", "loader")]):
            if "detections2pid" not in results:
                results.setdefault("detections2pid", {})
            results["detections2pid"].setdefault(str(pid), list())
            name = hit["name"].replace("_", " ")
            if name not in results["detections2pid"][str(pid)]:
                results["detections2pid"][str(pid)].append(name)
            return name
