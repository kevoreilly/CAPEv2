from __future__ import absolute_import
import os
import imp
import sys
import glob
import json
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
repconf = Config("reporting")

if repconf.mongodb.enabled:
    import pymongo
    results_db = pymongo.MongoClient(repconf.mongodb.host, port=repconf.mongodb.port, username=repconf.mongodb.get("username", None), password=repconf.mongodb.get("password", None), authSource=repconf.mongodb.db)[repconf.mongodb.db]

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

cape_decoders = os.path.join(CUCKOO_ROOT, "modules", "processing", "parsers", "CAPE")
CAPE_DECODERS = [os.path.basename(decoder)[:-3] for decoder in glob.glob(cape_decoders + "/[!_]*.py")]

for name in CAPE_DECODERS:
    try:
        file, pathname, description = imp.find_module(name, [cape_decoders])
        module = imp.load_module(name, file, pathname, description)
        cape_malware_parsers[name] = module
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

processing_conf = Config("processing")

HAVE_FLARE_CAPA = False
if processing_conf.flare_capa.enabled:
    try:
        import capa.main
        import capa.rules
        import capa.engine
        import capa.features
        from capa.render import convert_capabilities_to_result_document as capa_convert_capabilities_to_result_document
        from capa.engine import *
        import capa.render.utils as rutils
        from capa.main import  UnsupportedRuntimeError
        rules_path = os.path.join(CUCKOO_ROOT, "data", "capa-rules")
        if os.path.exists(rules_path):
            capa.main.RULES_PATH_DEFAULT_STRING = os.path.join(CUCKOO_ROOT, "data", "capa-rules")
            rules = capa.main.get_rules(capa.main.RULES_PATH_DEFAULT_STRING, disable_progress=True)
            rules = capa.rules.RuleSet(rules)
            HAVE_FLARE_CAPA = True
        else:
            print("FLARE CAPA rules missed! You can download them using python3 community.py -cr")
            HAVE_FLARE_CAPA = False
    except ImportError:
        HAVE_FLARE_CAPA = False
        print("FLARE-CAPA missed, pip3 install flare-capa")


HAVE_VBA2GRAPH = False
if processing_conf.vba2graph.enabled:
    try:
        from lib.cuckoo.common.office.vba2graph import vba2graph_from_vba_object, vba2graph_gen
        HAVE_VBA2GRAPH = True
    except ImportError:
        HAVE_VBA2GRAPH = False


suppress_parsing_list = ["Cerber", "Emotet_Payload", "Ursnif", "QakBot"]

pe_map = {
    "PE32+": ": 64-bit ",
    "PE32": ": 32-bit ",
}

cfg = Config()
BUFSIZE = int(cfg.processing.analysis_size_limit)

# ===== CAPA helpers
import collections

def render_meta(doc, ostream):

    ostream["md5"] = doc["meta"]["sample"]["md5"]
    ostream["sha1"] = doc["meta"]["sample"]["sha1"]
    ostream["sha256"] = doc["meta"]["sample"]["sha256"]
    ostream["path"] =doc["meta"]["sample"]["path"]

def find_subrule_matches(doc):
    """
    collect the rule names that have been matched as a subrule match.
    this way we can avoid displaying entries for things that are too specific.
    """
    matches = set([])

    def rec(node):
        if not node["success"]:
            # there's probably a bug here for rules that do `not: match: ...`
            # but we don't have any examples of this yet
            return

        elif node["node"]["type"] == "statement":
            for child in node["children"]:
                rec(child)

        elif node["node"]["type"] == "feature":
            if node["node"]["feature"]["type"] == "match":
                matches.add(node["node"]["feature"]["match"])

    for rule in rutils.capability_rules(doc):
        for node in rule["matches"].values():
            rec(node)

    return matches


def render_capabilities(doc, ostream):
    """
    example::
        {'CAPABILITY': {'accept command line arguments': 'host-interaction/cli',
                'allocate thread local storage (2 matches)': 'host-interaction/process',
                'check for time delay via GetTickCount': 'anti-analysis/anti-debugging/debugger-detection',
                'check if process is running under wine': 'anti-analysis/anti-emulation/wine',
                'contain a resource (.rsrc) section': 'executable/pe/section/rsrc',
                'write file (3 matches)': 'host-interaction/file-system/write'}
        }
    """
    subrule_matches = find_subrule_matches(doc)

    ostream["CAPABILITY"] = dict()
    for rule in rutils.capability_rules(doc):
        if rule["meta"]["name"] in subrule_matches:
            # rules that are also matched by other rules should not get rendered by default.
            # this cuts down on the amount of output while giving approx the same detail.
            # see #224
            continue

        count = len(rule["matches"])
        if count == 1:
            capability = rule["meta"]["name"]
        else:
            capability = "%s (%d matches)" % (rule["meta"]["name"], count)

        ostream["CAPABILITY"].setdefault(rule["meta"]["namespace"], list())
        ostream["CAPABILITY"][rule["meta"]["namespace"]].append(capability)

def render_attack(doc, ostream):
    """
    example::
        {'ATT&CK': {'COLLECTION': ['Input Capture::Keylogging [T1056.001]'],
            'DEFENSE EVASION': ['Obfuscated Files or Information [T1027]',
                                'Virtualization/Sandbox Evasion::System Checks '
                                '[T1497.001]'],
            'DISCOVERY': ['File and Directory Discovery [T1083]',
                          'Query Registry [T1012]',
                          'System Information Discovery [T1082]'],
            'EXECUTION': ['Shared Modules [T1129]']}
        }
    """
    ostream["ATTCK"] = dict()
    tactics = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("att&ck"):
            continue

        for attack in rule["meta"]["att&ck"]:
            tactic, _, rest = attack.partition("::")
            if "::" in rest:
                technique, _, rest = rest.partition("::")
                subtechnique, _, id = rest.rpartition(" ")
                tactics[tactic].add((technique, subtechnique, id))
            else:
                technique, _, id = rest.rpartition(" ")
                tactics[tactic].add((technique, id))

    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for spec in sorted(techniques):
            if len(spec) == 2:
                technique, id = spec
                inner_rows.append("%s %s" % (technique, id))
            elif len(spec) == 3:
                technique, subtechnique, id = spec
                inner_rows.append("%s::%s %s" % (technique, subtechnique, id))
            else:
                raise RuntimeError("unexpected ATT&CK spec format")
        ostream["ATTCK"].setdefault(tactic.upper(), inner_rows)


def render_mbc(doc, ostream):
    """
    example::
        {'MBC': {'ANTI-BEHAVIORAL ANALYSIS': ['Debugger Detection::Timing/Delay Check '
                                      'GetTickCount [B0001.032]',
                                      'Emulator Detection [B0004]',
                                      'Virtual Machine Detection::Instruction '
                                      'Testing [B0009.029]',
                                      'Virtual Machine Detection [B0009]'],
         'COLLECTION': ['Keylogging::Polling [F0002.002]'],
         'CRYPTOGRAPHY': ['Encrypt Data::RC4 [C0027.009]',
                          'Generate Pseudo-random Sequence::RC4 PRGA '
                          '[C0021.004]']}
        }
    """
    ostream["MBC"] = dict()
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule["meta"].get("mbc"):
            continue

        mbcs = rule["meta"]["mbc"]
        if not isinstance(mbcs, list):
            raise ValueError("invalid rule: MBC mapping is not a list")

        for mbc in mbcs:
            objective, _, rest = mbc.partition("::")
            if "::" in rest:
                behavior, _, rest = rest.partition("::")
                method, _, id = rest.rpartition(" ")
                objectives[objective].add((behavior, method, id))
            else:
                behavior, _, id = rest.rpartition(" ")
                objectives[objective].add((behavior, id))

    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for spec in sorted(behaviors):
            if len(spec) == 2:
                behavior, id = spec
                inner_rows.append("%s %s" % (behavior, id))
            elif len(spec) == 3:
                behavior, method, id = spec
                inner_rows.append("%s::%s %s" % (behavior, method, id))
            else:
                raise RuntimeError("unexpected MBC spec format")
        ostream["MBC"].setdefault(objective.upper(), inner_rows)

def render_dictionary(doc):
    ostream = dict()
    render_meta(doc, ostream)
    render_attack(doc, ostream)
    render_mbc(doc, ostream)
    render_capabilities(doc, ostream)

    return ostream


# ===== CAPA helpers END
def flare_capa_details(file_path: str, category: str, on_demand: bool=False) -> dict:
    capa_dictionary = False
    if  HAVE_FLARE_CAPA and processing_conf.flare_capa.enabled and processing_conf.flare_capa.get(category, False) and (processing_conf.flare_capa.on_demand is False or on_demand is True):
        try:
            extractor = capa.main.get_extractor(file_path, "auto", disable_progress=True)
            meta = capa.main.collect_metadata("", file_path, capa.main.RULES_PATH_DEFAULT_STRING, "auto", extractor)
            capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
            meta["analysis"].update(counts)
            doc = capa_convert_capabilities_to_result_document(meta, rules, capabilities)
            capa_dictionary = render_dictionary(doc)
        except MemoryError:
            log.warning("FLARE CAPA -> MemoryError")
        except UnsupportedRuntimeError:
            log.warning("FLARE CAPA -> UnsupportedRuntimeError")
        except Exception as e:
            log.error(e, exc_info=True)

    return capa_dictionary

def vba2graph_func(file_path: str, id: str, on_demand: bool=False):
    if HAVE_VBA2GRAPH and processing_conf.vba2graph.enabled and (processing_conf.vba2graph.on_demand is False or on_demand is True):
        try:
            vba2graph_svg_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", id, "vba2graph", "svg", "vba2graph.svg")
            if os.path.exists(vba2graph_svg_path):
                return

            vba2graph_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", id, "vba2graph")
            if not os.path.exists(vba2graph_path):
                os.makedirs(vba2graph_path)
            vba_code = vba2graph_from_vba_object(file_path)
            if vba_code:
                vba2graph_gen(vba_code, vba2graph_path)
        except Exception as e:
            log.info(e)

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
