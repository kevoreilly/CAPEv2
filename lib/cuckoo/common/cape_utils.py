import hashlib
import logging
import os
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path
from types import ModuleType
from typing import Dict, Tuple

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists, path_read_file

try:
    import yara

    HAVE_YARA = True
except ImportError:
    HAVE_YARA = False

try:
    import pydeep

    ssdeep_threshold = 95
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False


cape_malware_parsers = {}

# Config variables
cfg = Config()
repconf = Config("reporting")
process_cfg = Config("processing")

log = logging.getLogger(__name__)


if repconf.mongodb.enabled:
    from dev_utils.mongodb import mongo_find_one

if repconf.elasticsearchdb.enabled:
    from dev_utils.elasticsearchdb import elastic_handler, get_analysis_index

    es = elastic_handler

try:
    import pefile

    HAVE_PEFILE = True
except ImportError:
    print("Missed pefile library. Install it with: pip3 install pefile")
    HAVE_PEFILE = False


def load_mwcp_parsers() -> Tuple[Dict[str, str], ModuleType]:
    if not process_cfg.mwcp.enabled:
        return {}, False
    # Import All config parsers
    try:
        import mwcp

        logging.getLogger("mwcp").setLevel(logging.CRITICAL)
        mwcp.register_parser_directory(os.path.join(CUCKOO_ROOT, process_cfg.mwcp.modules_path))
        _malware_parsers = {block.name.rsplit(".", 1)[-1]: block.name for block in mwcp.get_parser_descriptions(config_only=False)}
        assert "MWCP_TEST" in _malware_parsers
        return _malware_parsers, mwcp
    except ImportError as e:
        log.info("Missed MWCP -> pip3 install mwcp\nDetails: %s", e)
        return {}, False


malware_parsers, mwcp = load_mwcp_parsers()
HAS_MWCP = bool(malware_parsers)


def load_malwareconfig_parsers() -> Tuple[bool, dict, ModuleType]:
    if not process_cfg.ratdecoders.enabled:
        return False, False, False
    try:
        from malwareconfig import fileparser
        from malwareconfig.modules import __decoders__

        if process_cfg.ratdecoders.modules_path:
            from lib.cuckoo.common.load_extra_modules import ratdecodedr_load_decoders

            ratdecoders_local_modules = ratdecodedr_load_decoders([os.path.join(CUCKOO_ROOT, process_cfg.ratdecoders.modules_path)])
            if ratdecoders_local_modules:
                __decoders__.update(ratdecoders_local_modules)
            assert "TestRats" in __decoders__
        return True, __decoders__, fileparser
    except ImportError:
        log.info("Missed RATDecoders -> pip3 install malwareconfig")
    except Exception as e:
        log.error(e, exc_info=True)
    return False, False, False


HAS_MALWARECONFIGS, __decoders__, fileparser = load_malwareconfig_parsers()

HAVE_MALDUCK = False
if process_cfg.malduck.enabled:
    try:
        # from malduck.extractor.loaders import load_modules
        from malduck.extractor import ExtractManager, ExtractorModules
        from malduck.extractor.extractor import Extractor
        from malduck.yara import Yara

        from lib.cuckoo.common.load_extra_modules import malduck_load_decoders

        malduck_rules = Yara.__new__(Yara)
        malduck_modules = ExtractorModules.__new__(ExtractorModules)
        # tmp_modules = load_modules(os.path.join(CUCKOO_ROOT, process_cfg.malduck.modules_path))
        # malduck_modules_names = dict((k.rsplit(".", 1)[-1], v) for k, v in tmp_modules.items())
        malduck_modules_names = malduck_load_decoders(CUCKOO_ROOT)
        malduck_modules.extractors = Extractor.__subclasses__()
        HAVE_MALDUCK = True
        # del tmp_modules
        assert "test_malduck" in malduck_modules_names
    except ImportError:
        log.info("Missed MalDuck -> pip3 install git+https://github.com/CERT-Polska/malduck/")

HAVE_CAPE_EXTRACTORS = False
if process_cfg.CAPE_extractors.enabled:
    from lib.cuckoo.common.load_extra_modules import cape_load_decoders

    cape_malware_parsers = cape_load_decoders(CUCKOO_ROOT)
    if cape_malware_parsers:
        HAVE_CAPE_EXTRACTORS = True
    assert "test cape" in cape_malware_parsers

suppress_parsing_list = ["Cerber", "Emotet_Payload", "Ursnif", "QakBot"]

pe_map = {
    "PE32+": ": 64-bit ",
    "PE32": ": 32-bit ",
}

BUFSIZE = int(cfg.processing.analysis_size_limit)


def init_yara():
    """Generates index for yara signatures."""

    categories = ("binaries", "urls", "memory", "CAPE", "macro", "monitor")

    log.debug("Initializing Yara...")

    # Generate root directory for yara rules.
    yara_root = os.path.join(CUCKOO_ROOT, "data", "yara")

    # Loop through all categories.
    for category in categories:
        # Check if there is a directory for the given category.
        category_root = os.path.join(yara_root, category)
        if not path_exists(category_root):
            log.warning("Missing Yara directory: %s?", category_root)
            continue

        rules, indexed = {}, []
        for category_root, _, filenames in os.walk(category_root, followlinks=True):
            for filename in filenames:
                if not filename.endswith((".yar", ".yara")):
                    continue
                filepath = os.path.join(category_root, filename)
                rules[f"rule_{category}_{len(rules)}"] = filepath
                indexed.append(filename)

            # Need to define each external variable that will be used in the
        # future. Otherwise Yara will complain.
        externals = {"filename": ""}

        while True:
            try:
                File.yara_rules[category] = yara.compile(filepaths=rules, externals=externals)
                File.yara_initialized = True
                break
            except yara.SyntaxError as e:
                bad_rule = f"{str(e).split('.yar', 1)[0]}.yar"
                log.debug("Trying to delete bad rule: %s", bad_rule)
                if os.path.basename(bad_rule) not in indexed:
                    break
                for k, v in rules.items():
                    if v == bad_rule:
                        del rules[k]
                        indexed.remove(os.path.basename(bad_rule))
                        print(f"Deleted broken yara rule: {bad_rule}")
                        break
            except yara.Error as e:
                log.error("There was a syntax error in one or more Yara rules: %s", e)
                break
        if category == "memory":
            try:
                mem_rules = yara.compile(filepaths=rules, externals=externals)
                mem_rules.save(os.path.join(yara_root, "index_memory.yarc"))
            except yara.Error as e:
                if "could not open file" in str(e):
                    log.inf("Can't write index_memory.yarc. Did you starting it with correct user?")
                else:
                    log.error(e)

        indexed = sorted(indexed)
        for entry in indexed:
            if (category, entry) == indexed[-1]:
                log.debug("\t `-- %s %s", category, entry)
            else:
                log.debug("\t |-- %s %s", category, entry)


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


def convert(data):
    if isinstance(data, str):
        return str(data)
    elif isinstance(data, Mapping):
        return dict(list(map(convert, data.items())))
    elif isinstance(data, Iterable):
        return type(data)(list(map(convert, data)))
    return data


def is_duplicated_binary(file_info: dict, cape_file: dict, append_file: bool) -> bool:
    if HAVE_PYDEEP:
        ssdeep_grade = pydeep.compare(file_info["ssdeep"], cape_file["ssdeep"])
        if ssdeep_grade >= ssdeep_threshold:
            log.debug("Duplicate payload skipped: ssdeep grade %d, threshold %d", ssdeep_grade, ssdeep_threshold)
            append_file = False
    if not file_info.get("pe") or not cape_file.get("pe"):
        return append_file
    if file_info["pe"].get("entrypoint") and file_info["pe"].get("ep_bytes") and cape_file["pe"].get("entrypoint"):
        if (
            file_info["pe"]["entrypoint"] == cape_file["pe"]["entrypoint"]
            and file_info["cape_type_code"] == cape_file["cape_type_code"]
            and file_info["pe"]["ep_bytes"] == cape_file["pe"]["ep_bytes"]
        ):
            log.debug("CAPE duplicate output file skipped: matching entrypoint")
            append_file = False

    return append_file


def static_config_parsers(cape_name, file_path, file_data):
    """Process CAPE Yara hits"""
    cape_config = {cape_name: {}}
    parser_loaded = False
    # CAPE - pure python parsers
    # MWCP
    # RatDecoders
    # MalDuck
    # Attempt to import a parser for the hit
    if HAVE_CAPE_EXTRACTORS and cape_name in cape_malware_parsers:
        log.debug("Running CAPE on %s", file_path)
        try:
            # changed from cape_config to cape_configraw because of avoiding overridden. duplicated value name.
            if hasattr(cape_malware_parsers[cape_name], "extract_config"):
                cape_configraw = cape_malware_parsers[cape_name].extract_config(file_data)
            else:
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
            log.error("CAPE: parsing error on %s with %s: %s", file_path, cape_name, e)

    # DC3-MWCP
    if HAS_MWCP and not parser_loaded and cape_name and cape_name in malware_parsers:
        log.debug("Running MWCP on %s", file_path)
        try:
            report = mwcp.run(malware_parsers[cape_name], data=file_data)
            reportmeta = report.as_dict_legacy()
            if not report.errors:
                parser_loaded = True
                tmp_dict = {}
                if reportmeta.get("debug"):
                    del reportmeta["debug"]
                if reportmeta.get("other"):
                    for key, value in reportmeta["other"].items():
                        tmp_dict.setdefault(key, [])
                        if value not in tmp_dict[key]:
                            tmp_dict[key].append(value)
                    del reportmeta["other"]

                tmp_dict.update(reportmeta)
                cape_config[cape_name] = convert(tmp_dict)
                log.debug("CAPE: DC3-MWCP parser for %s completed", cape_name)
            else:
                error_lines = report.errors[0].split("\n")
                for line in error_lines:
                    if line.startswith("ImportError: "):
                        log.debug("CAPE: DC3-MWCP parser: %s", line.split(": ", 2)[1])
        except pefile.PEFormatError:
            log.error("pefile PEFormatError on %s", file_path)
        except Exception as e:
            log.error(
                "CAPE: DC3-MWCP config parsing error on %s with %s: %s",
                file_path,
                cape_name,
                e,
            )

    elif HAS_MALWARECONFIGS and not parser_loaded and cape_name in __decoders__:
        log.debug("Running Malwareconfigs on %s", file_path)
        try:
            module = False
            file_info = fileparser.FileParser(rawdata=file_data)
            # Detects name by embed yara
            if file_info.malware_name in __decoders__:
                module = __decoders__[file_info.malware_name]["obj"]()
            elif cape_name in __decoders__:
                module = __decoders__[cape_name]["obj"]()
            else:
                log.warning("%s: %s wasn't matched by plugin's yara", file_path, cape_name)

            if module:
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
            if "rules" in str(e):
                log.warning("You probably need to compile yara-python with dotnet support")
            else:
                log.error(e, exc_info=True)
                log.warning(
                    "malwareconfig parsing error for %s with %s: %s, you should submit issue/fix to https://github.com/kevthehermit/RATDecoders/",
                    file_path,
                    cape_name,
                    e,
                )

        if cape_config.get(cape_name) == {}:
            return {}

    elif HAVE_MALDUCK and not parser_loaded and cape_name.lower() in malduck_modules_names:
        log.debug("Running Malduck on %s", file_path)
        if not File.yara_initialized:
            init_yara()
        # placing here due to not load yara in not related tools
        malduck_rules.rules = File.yara_rules["CAPE"]
        malduck_modules.rules = malduck_rules
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

    if not cape_config[cape_name]:
        return {}

    return cape_config


def static_config_lookup(file_path, sha256=False):
    if not sha256:
        sha256 = hashlib.sha256(open(file_path, "rb").read()).hexdigest()

    if repconf.mongodb.enabled:
        document_dict = mongo_find_one(
            "analysis", {"target.file.sha256": sha256}, {"CAPE.configs": 1, "info.id": 1, "_id": 0}, sort=[("_id", -1)]
        )
    elif repconf.elasticsearchdb.enabled:
        document_dict = es.search(
            index=get_analysis_index(),
            body={"query": {"match": {"target.file.sha256": sha256}}},
            _source=["CAPE.configs", "info.id"],
            sort={"_id": {"order": "desc"}},
        )["hits"]["hits"][0]["_source"]
    else:
        document_dict = None

    if not document_dict:
        return

    has_config = document_dict.get("CAPE", {}).get("configs", [])
    if has_config:
        return document_dict["info"]


# add your families here, should match file name as in cape yara
named_static_extractors = []


def static_extraction(path):
    config = False
    try:
        if not File.yara_initialized:
            init_yara()
        hits = File(path).get_yara(category="CAPE")
        path_name = Path(path).name
        if not hits and path_name not in named_static_extractors:
            return False
        file_data = path_read_file(path)
        if path_name in named_static_extractors:
            config = static_config_parsers(path_name, path, file_data)
        else:
            for hit in hits:
                cape_name = File.get_cape_name_from_yara_hit(hit)
                config = static_config_parsers(cape_name, path, file_data)
                if config:
                    break
    except Exception as e:
        log.error(e)

    return config


def cape_name_from_yara(details, pid, results):
    for hit in details.get("cape_yara", []) or []:
        if File.yara_hit_provides_detection(hit):
            if "detections2pid" not in results:
                results.setdefault("detections2pid", {})
            results["detections2pid"].setdefault(str(pid), [])
            name = File.get_cape_name_from_yara_hit(hit)
            if name not in results["detections2pid"][str(pid)]:
                results["detections2pid"][str(pid)].append(name)
            return name
