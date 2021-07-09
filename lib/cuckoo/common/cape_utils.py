from __future__ import absolute_import
import os
import logging
import tempfile
import hashlib
import subprocess
from collections.abc import Mapping, Iterable

from lib.cuckoo.common.objects import File
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT

malware_parsers = dict()
cape_malware_parsers = dict()

# Config variables
cfg = Config()
repconf = Config("reporting")
process_cfg = Config("processing")

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

HAS_MWCP = False
if process_cfg.mwcp.enabled:
# Import All config parsers
    try:
        import mwcp
        logging.getLogger("mwcp").setLevel(logging.CRITICAL)
        mwcp.register_parser_directory(os.path.join(CUCKOO_ROOT, process_cfg.mwcp.modules_path))
        malware_parsers = {block.name.split(".")[-1]: block.name for block in mwcp.get_parser_descriptions(config_only=False)}
        HAS_MWCP = True
    except ImportError as e:
        logging.info("Missed MWCP -> pip3 install git+https://github.com/Defense-Cyber-Crime-Center/DC3-MWCP\nDetails: {}".format(e))

HAS_MALWARECONFIGS = False
if process_cfg.ratdecoders.enabled:
    try:
        from malwareconfig import fileparser
        from malwareconfig.modules import __decoders__, __preprocessors__
        HAS_MALWARECONFIGS = True
        if process_cfg.ratdecoders.modules_path:
            from lib.cuckoo.common.load_extra_modules import ratdecodedr_load_decoders
            ratdecoders_local_modules = ratdecodedr_load_decoders([process_cfg.ratdecoders.modules_path])
            if ratdecoders_local_modules:
                __decoders__.update(ratdecoders_local_modules)
    except ImportError:
        logging.info("Missed RATDecoders -> pip3 install git+https://github.com/kevthehermit/RATDecoders")
    except Exception as e:
        logging.error(e, exc_info=True)

HAVE_MALDUCK = False
if process_cfg.malduck.enabled:
    try:
        from malduck.extractor import ExtractorModules, ExtractManager
        from malduck.extractor.extractor import Extractor
        from malduck.extractor.loaders import load_modules
        from malduck.yara import Yara
        malduck_rules = Yara.__new__(Yara)
        malduck_modules = ExtractorModules.__new__(ExtractorModules)
        tmp_modules = load_modules(process_cfg.malduck.modules_path)
        malduck_modules_names = dict((k.split(".")[-1], v) for k, v in tmp_modules.items())
        malduck_rules.rules = File.yara_rules["CAPE"]
        malduck_modules.rules = malduck_rules
        malduck_modules.extractors = Extractor.__subclasses__()
        HAVE_MALDUCK = True
        del tmp_modules
    except ImportError:
        logging.info("Missed MalDuck -> pip3 install git+https://github.com/CERT-Polska/malduck/")

HAVE_CAPE_EXTRACTORS = False
if process_cfg.CAPE_extractors.enabled:
    from lib.cuckoo.common.load_extra_modules import cape_load_decoders
    cape_malware_parsers = cape_load_decoders(process_cfg.CAPE_extractors.modules_path)
    HAVE_CAPE_EXTRACTORS = True

try:
    from modules.processing.parsers.plugxconfig import plugx

    plugx_parser = plugx.PlugXConfig()
except ImportError as e:
    plugx_parser = False
    logging.error(e)

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
        logging.error("CAPE: UPX Error %s", e)
        os.unlink(upxfile.name)
        return

    if ret == 0:
        sha256 = hash_file(hashlib.sha256, upxfile.name)
        newname = os.path.join(os.path.dirname(upxfile.name), sha256)
        os.rename(upxfile.name, newname)
        logging.info("CAPE: UPX - Statically unpacked binary %s.", upxfile.name)
        return newname
    elif ret == 127:
        logging.error("CAPE: Error - UPX not installed.")
    elif ret == 1:
        logging.error("CAPE: Error - UPX CantUnpackException")
    elif ret == 2:
        logging.error("CAPE: Error - UPX 'not packed' exception.")
    else:
        logging.error("CAPE: Unknown error - check UPX is installed and working.")

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

    if HAS_MWCP and cape_name and cape_name in malware_parsers:
        logging.debug("Running MWCP")
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
                logging.debug("CAPE: DC3-MWCP parser for %s completed", cape_name)
            else:
                error_lines = reporter.errors[0].split("\n")
                for line in error_lines:
                    if line.startswith("ImportError: "):
                        logging.debug("CAPE: DC3-MWCP parser: %s", line.split(": ")[1])
            reporter._Reporter__cleanup()
            del reporter
        except pefile.PEFormatError:
            logging.error("pefile PEFormatError")
        except Exception as e:
            logging.error("CAPE: DC3-MWCP config parsing error with {}: {}".format(cape_name, e))

    if HAVE_CAPE_EXTRACTORS and not parser_loaded and cape_name in cape_malware_parsers:
        logging.debug("Running CAPE")
        try:
            # changed from cape_config to cape_configraw because of avoiding overridden. duplicated value name.
            cape_configraw = cape_malware_parsers[cape_name].config(file_data)
            if isinstance(cape_configraw, list):
                for (key, value) in cape_configraw[0].items():
                    # python3 map object returns iterator by default, not list and not serializeable in JSON.
                    if isinstance(value, map):
                        value = list(value)
                    cape_config[cape_name].update({key: [value]})
                parser_loaded = True
            elif isinstance(cape_configraw, dict):
                for (key, value) in cape_configraw.items():
                    # python3 map object returns iterator by default, not list and not serializeable in JSON.
                    if isinstance(value, map):
                        value = list(value)
                    cape_config[cape_name].update({key: [value]})
                parser_loaded = True
        except Exception as e:
            logging.error("CAPE: parsing error with {}: {}".format(cape_name, e))

    elif HAS_MALWARECONFIGS and not parser_loaded and cape_name in __decoders__:
        logging.debug("Running Malwareconfigs")
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
            logging.warning("malwareconfig parsing error with %s: %s, you should submit issue/fix to https://github.com/kevthehermit/RATDecoders/", cape_name, e,)

        if cape_name in cape_config and cape_config[cape_name] == {}:
            return {}

    elif HAVE_MALDUCK and not parser_loaded and cape_name.lower() in malduck_modules_names:
        logging.debug("Running Malduck")
        ext = ExtractManager.__new__(ExtractManager)
        ext.configs = {}
        ext.modules = malduck_modules
        tmp_file = tempfile.NamedTemporaryFile(delete=False)
        tmp_file.write(file_data)
        ext.push_file(tmp_file.name)
        tmp_file.close()

        tmp_config = ext.config
        del ext
        if tmp_config:
            for (key, value) in tmp_config[0].items():
                cape_config[cape_name].update({key: [value]})

    return cape_config

def static_config_lookup(file_path, sha256=False):
    if not sha256:
        sha256 = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
    cape_tasks = results_db.analysis.find_one({"target.file.sha256": sha256}, {"CAPE.configs":1, "info.id": 1, "_id":0}, sort=[("_id", pymongo.DESCENDING)])
    if not cape_tasks:
        return
    for task in cape_tasks.get("CAPE", {}).get("configs", []) or []:
        return task["info"]

def static_extraction(path):
    try:
        hits = File(path).get_yara(category="CAPE")
        if not hits:
            return False
        # Get the file data
        with open(path, "rb") as file_open:
            file_data = file_open.read()
        for hit in hits:
            config = static_config_parsers(hit, file_data)
            if config:
                return config
        return False
    except Exception as e:
        logging.error(e)

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
