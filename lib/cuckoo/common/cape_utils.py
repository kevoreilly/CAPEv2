import hashlib
import logging

# import tempfile
from collections.abc import Iterable, Mapping
from contextlib import suppress
from pathlib import Path

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_read_file

try:
    import pydeep

    ssdeep_threshold = 95
    HAVE_PYDEEP = True
except ImportError:
    HAVE_PYDEEP = False

HAS_MWCP = False
HAS_MALWARECONFIGS = False
HAVE_CAPE_EXTRACTORS = False
with suppress(ImportError):
    from cape_parsers import load_cape_parsers, load_malwareconfig_parsers, load_mwcp_parsers  # load_malduck_parsers

    HAS_MWCP = True
    HAS_MALWARECONFIGS = True
    HAVE_CAPE_EXTRACTORS = True

mwcp_decoders = {}
rat_decoders = {}
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
    print("Missed pefile library. Install it with: poetry install")
    HAVE_PEFILE = False

if process_cfg.mwcp.enabled and HAS_MWCP:
    mwcp_decoders, mwcp = load_mwcp_parsers()
    HAS_MWCP = bool(mwcp_decoders)

if not process_cfg.ratdecoders.enabled and HAS_MALWARECONFIGS:
    HAS_MALWARECONFIGS, rat_decoders, fileparser = load_malwareconfig_parsers()

HAVE_MALDUCK = False
"""
# ToDo move
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
"""

if process_cfg.CAPE_extractors.enabled:
    from lib.cuckoo.common.load_extra_modules import cape_load_custom_decoders

    cape_malware_parsers = {}
    if HAVE_CAPE_EXTRACTORS:
        exclude_parsers = []
        if process_cfg.CAPE_extractors.parsers:
            exclude_parsers = [parser_name.strip() for parser_name in process_cfg.CAPE_extractors.parsers.split(",")]
        cape_malware_parsers = load_cape_parsers(load=process_cfg.CAPE_extractors.parsers, exclude_parsers=exclude_parsers)
    # Custom overwrites core
    cape_malware_parsers.update(cape_load_custom_decoders(CUCKOO_ROOT))
    if cape_malware_parsers:
        HAVE_CAPE_EXTRACTORS = True
    if "test cape" not in cape_malware_parsers:
        log.info("Missed cape-parsers! Run: poetry install")


suppress_parsing_list = ["Cerber", "Emotet_Payload", "Ursnif", "QakBot"]

pe_map = {
    "PE32+": ": 64-bit ",
    "PE32": ": 32-bit ",
}

BUFSIZE = int(cfg.processing.analysis_size_limit)


def hash_file(method, path: str) -> str:
    """Calculates an hash on a file by path.
    @param method: callable hashing method
    @param path: file path
    @return: computed hash string
    """
    h = method()
    with open(path, "rb") as f:
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
    """
    Determines if a binary file is a duplicate based on various criteria.

    Args:
        file_info (dict): Information about the file being checked.
        cape_file (dict): Information about the existing CAPE file.
        append_file (bool): Flag indicating whether to append the file.

    Returns:
        bool: False if the file is determined to be a duplicate, otherwise returns the value of append_file.
    """
    if HAVE_PYDEEP:
        ssdeep_grade = pydeep.compare(file_info["ssdeep"].encode(), cape_file["ssdeep"].encode())
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


def static_config_parsers(cape_name: str, file_path: str, file_data: bytes) -> dict:
    """
    Process CAPE Yara hits and extract configuration data using various parsers.

    This function attempts to extract configuration data from a given file using different parsers
    such as CAPE extractors, DC3-MWCP, and Malwareconfigs. The function returns a dictionary containing
    the extracted configuration data.

    Args:
        cape_name (str): The name of the CAPE parser to use.
        file_path (str): The path to the file being analyzed.
        file_data (bytes): The binary data of the file being analyzed.

    Returns:
        dict: A dictionary containing the extracted configuration data. If no configuration data is
            extracted, an empty dictionary is returned.
    """
    """Process CAPE Yara hits"""
    cape_config = {}
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
                for key, value in cape_configraw[0].items():
                    # python3 map object returns iterator by default, not list and not serializeable in JSON.
                    if isinstance(value, map):
                        value = list(value)
                    cape_config.setdefault(cape_name, {}).update({key: [value]})
                parser_loaded = True
            elif isinstance(cape_configraw, dict):
                for key, value in cape_configraw.items():
                    # python3 map object returns iterator by default, not list and not serializeable in JSON.
                    if isinstance(value, map):
                        value = list(value)
                    cape_config.setdefault(cape_name, {}).update({key: [value]})
                parser_loaded = True
        except Exception as e:
            log.exception("CAPE: parsing error on %s with %s: %s", file_path, cape_name, e)

    # DC3-MWCP
    if HAS_MWCP and not parser_loaded and cape_name and cape_name in mwcp_decoders:
        log.debug("Running MWCP on %s", file_path)
        try:
            report = mwcp.run(mwcp_decoders[cape_name], data=file_data)
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
                cape_config.setdefault(cape_name, {}).update(convert(tmp_dict))
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
                str(e),
            )

    elif HAS_MALWARECONFIGS and not parser_loaded and cape_name in rat_decoders:
        log.debug("Running Malwareconfigs on %s", file_path)
        try:
            module = False
            file_info = fileparser.FileParser(rawdata=file_data)
            # Detects name by embed yara
            if file_info.malware_name in rat_decoders:
                module = rat_decoders[file_info.malware_name]["obj"]()
            elif cape_name in rat_decoders:
                module = rat_decoders[cape_name]["obj"]()
            else:
                log.warning("%s: %s wasn't matched by plugin's yara", file_path, cape_name)

            if module:
                module.set_file(file_info)
                module.get_config()
                malwareconfig_config = module.config
                # ToDo remove
                if isinstance(malwareconfig_config, list):
                    for key, value in malwareconfig_config[0].items():
                        cape_config.setdefault(cape_name, {}).update({key: [value]})
                elif isinstance(malwareconfig_config, dict):
                    for key, value in malwareconfig_config.items():
                        cape_config.setdefault(cape_name, {}).update({key: [value]})
        except Exception as e:
            if "rules" in str(e):
                log.warning("You probably need to compile yara-python with dotnet support")
            else:
                log.exception(e)
                log.warning(
                    "malwareconfig parsing error for %s with %s: %s, you should submit issue/fix to https://github.com/kevthehermit/RATDecoders/",
                    file_path,
                    cape_name,
                    str(e),
                )
    """
    elif HAVE_MALDUCK and not parser_loaded and cape_name.lower() in malduck_modules_names:
        log.debug("Running Malduck on %s", file_path)
        if not File.yara_initialized:
            File.init_yara()
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
            for key, value in tmp_config[0].items():
                cape_config.setdefault(cape_name, {}).update({key: [value]})
    """

    return cape_config


def static_config_lookup(file_path: str, sha256: str = False) -> dict:
    """
    Look up static configuration information for a given file based on its SHA-256 hash.

    This function calculates the SHA-256 hash of the file at the specified path if not provided,
    and then queries either a MongoDB or Elasticsearch database to retrieve configuration information.

    Args:
        file_path (str): The path to the file for which to look up configuration information.
        sha256 (str, optional): The SHA-256 hash of the file. If not provided, it will be calculated.

    Returns:
        dict or None: A dictionary containing the configuration information if found, otherwise None.
    """
    if not sha256:
        with open(file_path, "rb") as f:
            sha256 = hashlib.sha256(f.read()).hexdigest()

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


def static_extraction(path: str) -> dict:
    """
    Extracts static configuration from a file using YARA rules and named static extractors.

    Args:
        path (str): The file path to be analyzed.

    Returns:
        dict or bool: The extracted configuration as a dictionary if successful,
                    False if no configuration is found or an error occurs.

    Raises:
        Exception: Logs any exceptions that occur during the extraction process.
    """
    config = {}
    try:
        hits = File(path).get_yara(category="CAPE")
        path_name = Path(path).name
        if not hits and path_name not in named_static_extractors:
            return config
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


def cape_name_from_yara(details: dict, pid: int, results: dict) -> str:
    """
    Extracts the CAPE name from YARA hit details and associates it with a process ID (pid) in the results dictionary.

    Args:
        details (dict): A dictionary containing YARA hit details, expected to have a key "cape_yara" with a list of hits.
        pid (int): The process ID to associate the CAPE name with.
        results (dict): A dictionary to store the association between detections and process IDs.

    Returns:
        str: The CAPE name extracted from the YARA hit, or None if no CAPE name is found.
    """
    for hit in details.get("cape_yara", []) or []:
        if File.yara_hit_provides_detection(hit):
            if "detections2pid" not in results:
                results.setdefault("detections2pid", {})
            results["detections2pid"].setdefault(str(pid), [])
            name = File.get_cape_name_from_yara_hit(hit)
            if name not in results["detections2pid"][str(pid)]:
                results["detections2pid"][str(pid)].append(name)
            return name
