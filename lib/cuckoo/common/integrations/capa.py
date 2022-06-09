# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import logging
import os
from typing import Any, Dict, List

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger(__name__)

processing_conf = Config("processing")

"""
from lib.cuckoo.common.integrations.capa import flare_capa_details, HAVE_FLARE_CAPA
path = "/opt/CAPEv2/storage/binaries/da034c11f0c396f6cd11d22f833f9501dc75a33047ba3bd5870ff79e479bc004"
details = flare_capa_details(path, "static", on_demand=True)
"""

HAVE_FLARE_CAPA = False
if processing_conf.flare_capa.enabled:
    try:
        from capa.version import __version__ as capa_version

        if capa_version[0] != "3":
            print("FLARE-CAPA missed, pip3 install -U flare-capa")
        else:
            import capa.main
            import capa.render.utils as rutils
            import capa.rules
            from capa.main import UnsupportedRuntimeError
            from capa.render.result_document import (
                convert_capabilities_to_result_document as capa_convert_capabilities_to_result_document,
            )
            from capa.rules import InvalidRuleSet, InvalidRuleWithPath

            rules_path = os.path.join(CUCKOO_ROOT, "data", "capa-rules")
            if os.path.exists(rules_path):
                capa.main.RULES_PATH_DEFAULT_STRING = os.path.join(CUCKOO_ROOT, "data", "capa-rules")
                try:
                    rules = capa.main.get_rules(capa.main.RULES_PATH_DEFAULT_STRING, disable_progress=True)
                    rules = capa.rules.RuleSet(rules)
                    HAVE_FLARE_CAPA = True
                except InvalidRuleWithPath:
                    print("FLARE_CAPA InvalidRuleWithPath")
                    HAVE_FLARE_CAPA = False
                except InvalidRuleSet:
                    print("FLARE_CAPA InvalidRuleSet")
                    HAVE_FLARE_CAPA = False
            else:
                print("FLARE CAPA rules missed! You can download them using python3 community.py -cr")
                HAVE_FLARE_CAPA = False

            signatures_path = os.path.join(CUCKOO_ROOT, "data", "capa-signatures")
            if os.path.exists(signatures_path):
                capa.main.SIGNATURES_PATH_DEFAULT_STRING = os.path.join(CUCKOO_ROOT, "data", "capa-signatures")
                try:
                    signatures = capa.main.get_signatures(capa.main.SIGNATURES_PATH_DEFAULT_STRING)
                    HAVE_FLARE_CAPA = True
                except IOError:
                    print("FLARE_CAPA InvalidSignatures")
            else:
                print("FLARE CAPA rules missed! You can download them using python3 community.py -cr")
                HAVE_FLARE_CAPA = False
    except ImportError as e:
        HAVE_FLARE_CAPA = False
        print(e)
        print("FLARE-CAPA missed, pip3 install -U flare-capa")


def render_meta(doc: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "md5": doc["meta"]["sample"]["md5"],
        "sha1": doc["meta"]["sample"]["sha1"],
        "sha256": doc["meta"]["sample"]["sha256"],
        "path": doc["meta"]["sample"]["path"],
    }


def find_subrule_matches(doc: Dict[str, Any]) -> set:
    """
    collect the rule names that have been matched as a subrule match.
    this way we can avoid displaying entries for things that are too specific.
    """

    def rec(node: dict) -> set:
        matches = set()
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
        return matches

    matches = set()

    for rule in rutils.capability_rules(doc):
        for node in rule["matches"].values():
            matches = matches.union(rec(node))

    return matches


def render_capabilities(doc: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    example::
        {'accept command line arguments': ['host-interaction/cli'],
            'allocate thread local storage (2 matches)': ['host-interaction/process'],
            'check for time delay via GetTickCount': ['anti-analysis/anti-debugging/debugger-detection'],
            'check if process is running under wine': ['anti-analysis/anti-emulation/wine'],
            'contain a resource (.rsrc) section': ['executable/pe/section/rsrc'],
            'write file (3 matches)': ['host-interaction/file-system/write']
        }
    """
    subrule_matches = find_subrule_matches(doc)

    capability_dict = {}
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
            capability = f"{rule['meta']['name']} ({count} matches)"

        capability_dict.setdefault(rule["meta"]["namespace"], []).append(capability)
    return capability_dict


def render_attack(doc: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    example::
        {'COLLECTION': ['Input Capture::Keylogging [T1056.001]'],
            'DEFENSE EVASION': ['Obfuscated Files or Information [T1027]',
                                'Virtualization/Sandbox Evasion::System Checks '
                                '[T1497.001]'],
            'DISCOVERY': ['File and Directory Discovery [T1083]',
                          'Query Registry [T1012]',
                          'System Information Discovery [T1082]'],
            'EXECUTION': ['Shared Modules [T1129]']
        }
    """
    attck_dict = {}
    tactics = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        for attack in rule["meta"].get("att&ck", {}):
            tactics[attack["tactic"]].add((attack["technique"], attack.get("subtechnique"), attack["id"]))

    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for technique, subtechnique, id in sorted(techniques):
            if subtechnique is None:
                inner_rows.append(f"{technique} {id}")
            else:
                inner_rows.append(f"{technique}::{subtechnique} {id}")
        attck_dict.setdefault(tactic.upper(), inner_rows)
    return attck_dict


def render_mbc(doc: Dict[str, Any]) -> Dict[str, List[str]]:
    """
    example::
        {'ANTI-BEHAVIORAL ANALYSIS': ['Debugger Detection::Timing/Delay Check '
                                      'GetTickCount [B0001.032]',
                                      'Emulator Detection [B0004]',
                                      'Virtual Machine Detection::Instruction '
                                      'Testing [B0009.029]',
                                      'Virtual Machine Detection [B0009]'],
         'COLLECTION': ['Keylogging::Polling [F0002.002]'],
         'CRYPTOGRAPHY': ['Encrypt Data::RC4 [C0027.009]',
                          'Generate Pseudo-random Sequence::RC4 PRGA '
                          '[C0021.004]']
        }
    """
    mbc_dict = {}
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        for mbc in rule["meta"].get("mbc", {}):
            objectives[mbc["objective"]].add((mbc["behavior"], mbc.get("method"), mbc["id"]))

    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for behavior, method, id in sorted(behaviors):
            if method is None:
                inner_rows.append(f"{behavior} [{id}]")
            else:
                inner_rows.append(f"{behavior}::{method} [{id}]")
        mbc_dict.setdefault(objective.upper(), inner_rows)
    return mbc_dict


def render_dictionary(doc: Dict[str, Any]) -> Dict[str, Any]:
    ostream = render_meta(doc)
    ostream["ATTCK"] = render_attack(doc)
    ostream["MBC"] = render_mbc(doc)
    ostream["CAPABILITY"] = render_capabilities(doc)

    return ostream


# ===== CAPA END
def flare_capa_details(file_path: str, category: str = False, on_demand=False, disable_progress=True) -> Dict[str, Any]:
    capa_dictionary = {}
    if (
        HAVE_FLARE_CAPA
        and processing_conf.flare_capa.enabled
        and processing_conf.flare_capa.get(category, False)
        and not processing_conf.flare_capa.on_demand
        or on_demand
    ):
        try:
            extractor = capa.main.get_extractor(
                file_path, "auto", capa.main.BACKEND_VIV, signatures, disable_progress=disable_progress
            )
            meta = capa.main.collect_metadata("", file_path, capa.main.RULES_PATH_DEFAULT_STRING, extractor)
            capabilities, counts = capa.main.find_capabilities(rules, extractor, disable_progress=True)
            meta["analysis"].update(counts)
            doc = capa_convert_capabilities_to_result_document(meta, rules, capabilities)
            capa_dictionary = render_dictionary(doc)
        except MemoryError:
            log.warning("FLARE CAPA -> MemoryError")
        except UnsupportedRuntimeError:
            log.error("FLARE CAPA -> UnsupportedRuntimeError")
        except Exception as e:
            log.error(e, exc_info=True)
    return capa_dictionary
