# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import logging
import os
# from contextlib import suppress
from typing import Any, Dict, Set

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists, path_object

log = logging.getLogger(__name__)

reporting_conf = Config("reporting")
integrations_conf = Config("integrations")

rules = False
HAVE_FLARE_CAPA = False
if integrations_conf.flare_capa.enabled:
    try:
        # from platform import python_version

        from capa.version import __version__ as capa_version
        from packaging import version

        # if version.parse(python_version()) >= version.parse("3.10.0"):
        capa_compatible_version = "9"

        # ToDo use major?
        if version.parse(capa_version).base_version.split(".")[0] != capa_compatible_version:
            print("FLARE-CAPA missed or incompatible version. Run: poetry install")
        else:
            import capa.capabilities.common
            import capa.engine
            import capa.features
            import capa.features.freeze.features as frzf
            import capa.loader
            import capa.main
            import capa.render.default
            import capa.render.json
            import capa.render.result_document as rd
            import capa.render.utils as rutils
            import capa.rules
            from capa.exceptions import EmptyReportError, UnsupportedFormatError
            from capa.features.common import FORMAT_AUTO, OS_AUTO
            from capa.rules import InvalidRule, InvalidRuleSet, InvalidRuleWithPath
            from pydantic_core._pydantic_core import ValidationError

            # Disable vivisect logging
            logging.getLogger("vivisect").setLevel(logging.NOTSET)
            logging.getLogger("vivisect.base").setLevel(logging.NOTSET)
            logging.getLogger("vivisect.impemu").setLevel(logging.NOTSET)

            rules_path = os.path.join(CUCKOO_ROOT, "data", "capa-rules")
            if path_exists(rules_path):
                try:
                    rules = capa.rules.get_rules([path_object(rules_path)])
                    HAVE_FLARE_CAPA = True
                except InvalidRuleWithPath:
                    print("FLARE_CAPA InvalidRuleWithPath")
                    HAVE_FLARE_CAPA = False
                except InvalidRuleSet:
                    print("FLARE_CAPA InvalidRuleSet")
                    HAVE_FLARE_CAPA = False
                except InvalidRule:
                    print("FLARE_CAPA InvalidRuleSet")
                    HAVE_FLARE_CAPA = False
                except TypeError:
                    print("FLARE_CAPA problems. Probably install CAPA from github")
                    HAVE_FLARE_CAPA = False
            else:
                print("FLARE CAPA rules missed! You can download them using: poetry run python utils/community.py -cr")
                HAVE_FLARE_CAPA = False

            signatures_path = os.path.join(CUCKOO_ROOT, "data", "flare-signatures")
            if path_exists(signatures_path):
                capa.main.SIGNATURES_PATH_DEFAULT_STRING = path_object(signatures_path)
                try:
                    signatures = capa.loader.get_signatures(capa.main.SIGNATURES_PATH_DEFAULT_STRING)
                    HAVE_FLARE_CAPA = True
                except IOError:
                    print("FLARE_CAPA InvalidSignatures")
            else:
                print("FLARE CAPA signature missed! You can download them using: poetry run python utils/community.py -cr")
                HAVE_FLARE_CAPA = False
    except ImportError as e:
        HAVE_FLARE_CAPA = False
        print(e)
        print("FLARE-CAPA missed: poetry install")


# == Render ddictionary helpers
def render_meta(doc, result):
    result["md5"] = doc.meta.sample.md5
    result["sha1"] = doc.meta.sample.sha1
    result["sha256"] = doc.meta.sample.sha256
    result["path"] = doc.meta.sample.path


def find_subrule_matches(doc) -> Set[str]:
    """
    collect the rule names that have been matched as a subrule match.
    this way we can avoid displaying entries for things that are too specific.
    """
    matches = set([])

    def rec(node):
        if not node.success:
            # there's probably a bug here for rules that do `not: match: ...`
            # but we don't have any examples of this yet
            return

        elif isinstance(node.node, rd.StatementNode):
            for child in node.children:
                rec(child)

        elif isinstance(node.node, rd.FeatureNode):
            if isinstance(node.node.feature, frzf.MatchFeature):
                matches.add(node.node.feature.match)

    for rule in rutils.capability_rules(doc):
        for _, node in rule.matches:
            rec(node)

    return matches


def render_capabilities(doc, result):
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

    result["CAPABILITY"] = {}
    for rule in rutils.capability_rules(doc):
        if rule.meta.name in subrule_matches:
            # rules that are also matched by other rules should not get rendered by default.
            # this cuts down on the amount of output while giving approx the same detail.
            # see #224
            continue

        count = len(rule.matches)
        if count == 1:
            capability = rule.meta.name
        else:
            capability = "%s (%d matches)" % (rule.meta.name, count)

        result["CAPABILITY"].setdefault(rule.meta.namespace, [])
        result["CAPABILITY"][rule.meta.namespace].append(capability)


def render_attack(doc, result):
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
    result["ATTCK"] = {}
    tactics = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule.meta.attack:
            continue
        for attack in rule.meta.attack:
            tactics[attack.tactic].add((attack.technique, attack.subtechnique, attack.id))

    for tactic, techniques in sorted(tactics.items()):
        inner_rows = []
        for technique, subtechnique, id in sorted(techniques):
            if subtechnique is None:
                inner_rows.append("%s %s" % (technique, id))
            else:
                inner_rows.append("%s::%s %s" % (technique, subtechnique, id))
        result["ATTCK"].setdefault(tactic.upper(), inner_rows)


def render_mbc(doc, result):
    """
    example::
        {'MBC': {'ANTI-BEHAVIORAL ANALYSIS': [
            'Debugger Detection::Timing/Delay Check '
            'GetTickCount [B0001.032]',
            'Emulator Detection [B0004]',
            'Virtual Machine Detection::Instruction '
            'Testing [B0009.029]',
            'Virtual Machine Detection [B0009]'],
        'COLLECTION': ['Keylogging::Polling [F0002.002]'],
        'CRYPTOGRAPHY': [
            'Encrypt Data::RC4 [C0027.009]',
            'Generate Pseudo-random Sequence::RC4 PRGA [C0021.004]']}
        }
    """
    result["MBC"] = {}
    objectives = collections.defaultdict(set)
    for rule in rutils.capability_rules(doc):
        if not rule.meta.mbc:
            continue

        for mbc in rule.meta.mbc:
            objectives[mbc.objective].add((mbc.behavior, mbc.method, mbc.id))

    for objective, behaviors in sorted(objectives.items()):
        inner_rows = []
        for behavior, method, id in sorted(behaviors):
            if method is None:
                inner_rows.append("%s [%s]" % (behavior, id))
            else:
                inner_rows.append("%s::%s [%s]" % (behavior, method, id))
        result["MBC"].setdefault(objective.upper(), inner_rows)


def render_dictionary(doc) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    render_meta(doc, result)
    render_attack(doc, result)
    render_mbc(doc, result)
    render_capabilities(doc, result)
    return result

# ===== CAPA END


# ==== render dictionary helpers
def flare_capa_details(
    file_path: str,
    category: str = False,
    on_demand: bool = False,
    disable_progress: bool = True,
    backend: str = "viv",
    results: dict = {},
) -> Dict[str, Any]:
    # load rules from disk
    capa_output = {}
    if (
        HAVE_FLARE_CAPA
        and integrations_conf.flare_capa.enabled
        and integrations_conf.flare_capa.get(category, False)
        and not integrations_conf.flare_capa.on_demand
        or on_demand
    ):
        # ToDo check if PE file in TYPE
        try:
            file_path_object = path_object(file_path)
            # extract features and find capabilities
            if backend == "viv":
                extractor = capa.loader.get_extractor(
                    file_path_object, FORMAT_AUTO, OS_AUTO, capa.loader.BACKEND_VIV, [], False, disable_progress=disable_progress
                )
            elif backend == "cape" and results:
                try:
                    extractor = capa.features.extractors.cape.extractor.CapeExtractor.from_report(results)
                except ValidationError as e:
                    log.debug("CAPA ValidationError %s", e)
                    return {}
            else:
                log.error("CAPA: Missed results probably")
                return {}

            capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=disable_progress)
            # collect metadata (used only to make rendering more complete)
            meta = capa.loader.collect_metadata([], file_path_object, FORMAT_AUTO, OS_AUTO, [path_object(rules_path)], extractor, capabilities)
            meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)
            capa_output: Any = False

            # ...as python dictionary, simplified as textable but in dictionary
            doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)
            capa_output = render_dictionary(doc)
        except MemoryError:
            log.warning("FLARE CAPA -> MemoryError")
        except AttributeError as e:
            log.exception(e)
            log.warning("FLARE CAPA -> Use GitHub's version. poetry install")
        except UnsupportedFormatError:
            log.error("FLARE CAPA -> UnsupportedFormatError")
        except EmptyReportError:
            log.info("FLARE CAPA -> No process data available")
        except Exception as e:
            log.exception(e)

    return capa_output


if __name__ == "__main__":
    import sys
    from lib.cuckoo.common.integrations.capa import flare_capa_details, HAVE_FLARE_CAPA
    details = flare_capa_details(sys.argv[1], "static", on_demand=True)
