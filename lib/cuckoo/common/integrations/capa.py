# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import collections
import hashlib
import importlib
import logging
import os
# from contextlib import suppress
import time
from typing import Any, Dict, Set

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists, path_object
from lib.cuckoo.common.process_timeout import (
    ResultUnavailableError,
    get_cached_task_result,
    mark_budget_warned,
    record_task_budget_elapsed,
    resolve_call_timeout,
    run_with_timeout,
    set_cached_task_result,
)

log = logging.getLogger(__name__)

reporting_conf = Config("reporting")
integrations_conf = Config("integrations")

rules: Any = False
signatures: list[Any] = []
capa_compatible_versions = {"10"}
rules_path = os.path.join(CUCKOO_ROOT, "data", "capa-rules")
signatures_path = os.path.join(CUCKOO_ROOT, "data", "flare-signatures")
HAVE_FLARE_CAPA = False
HAVE_MALCAT_CAPA = False
_CAPA_MODULES_LOADED = False
if integrations_conf.flare_capa.enabled:
    try:
        if integrations_conf.flare_capa.get("malcat_capa", False):
            from lib.cuckoo.common.integrations.malcat.capa import malcat_capa_details

            HAVE_MALCAT_CAPA = True
            HAVE_FLARE_CAPA = True
    except Exception:
        HAVE_MALCAT_CAPA = False


def _ensure_capa_loaded(force: bool = False) -> bool:
    """Import FLARE-CAPA dependencies and load rules/signatures once per process."""
    global HAVE_FLARE_CAPA
    global _CAPA_MODULES_LOADED
    global capa, frzf, rd, rutils
    global EmptyReportError, UnsupportedFormatError, FORMAT_AUTO, OS_AUTO, ValidationError
    global rules, signatures, capa_compatible_versions, rules_path, signatures_path

    if _CAPA_MODULES_LOADED and rules:
        return True
    if not force and not (
        integrations_conf.flare_capa.enabled and (not HAVE_MALCAT_CAPA or integrations_conf.flare_capa.get("behavior", False))
    ):
        return False

    try:
        # from platform import python_version

        from capa.version import __version__ as capa_version
        from packaging import version

        # if version.parse(python_version()) >= version.parse("3.10.0"):
        capa_compatible_versions = {"10"}

        # ToDo use major?
        if version.parse(capa_version).base_version.split(".")[0] not in capa_compatible_versions:
            print("FLARE-CAPA missed or incompatible version. Run: uv sync --locked --no-install-project --inexact")
            if not HAVE_MALCAT_CAPA:
                HAVE_FLARE_CAPA = False
            return False

        import capa.capabilities.common
        import capa.engine
        import capa.features
        import capa.features.extractors.cape.extractor  # capa 10 no longer imports it from capa.loader
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

        # Reduce vivisect logging verbosity
        logging.getLogger("vivisect").setLevel(logging.INFO)
        logging.getLogger("vivisect.base").setLevel(logging.CRITICAL)
        logging.getLogger("vivisect.impemu").setLevel(logging.CRITICAL)
        logging.getLogger("vivisect.parsers").setLevel(logging.CRITICAL)
        logging.getLogger("vivisect.tools").setLevel(logging.CRITICAL)
        logging.getLogger("vivisect.analysis").setLevel(logging.CRITICAL)

        rules_path = os.path.join(CUCKOO_ROOT, "data", "capa-rules")
        rules_loaded = bool(rules)
        if not rules_loaded:
            if path_exists(rules_path):
                try:
                    rules = capa.rules.get_rules([path_object(rules_path)])
                    rules_loaded = True
                    HAVE_FLARE_CAPA = True
                except InvalidRuleWithPath:
                    print("FLARE_CAPA InvalidRuleWithPath")
                    if not HAVE_MALCAT_CAPA:
                        HAVE_FLARE_CAPA = False
                except InvalidRuleSet:
                    print("FLARE_CAPA InvalidRuleSet")
                    if not HAVE_MALCAT_CAPA:
                        HAVE_FLARE_CAPA = False
                except InvalidRule:
                    print("FLARE_CAPA InvalidRuleSet")
                    if not HAVE_MALCAT_CAPA:
                        HAVE_FLARE_CAPA = False
                except TypeError:
                    print("FLARE_CAPA problems. Probably install CAPA from github")
                    if not HAVE_MALCAT_CAPA:
                        HAVE_FLARE_CAPA = False
            else:
                print("FLARE CAPA rules missed! You can download them using: uv run --no-sync python utils/community.py -cr")
                if not HAVE_MALCAT_CAPA:
                    HAVE_FLARE_CAPA = False

        signatures_path = os.path.join(CUCKOO_ROOT, "data", "flare-signatures")
        if not signatures:
            if path_exists(signatures_path):
                capa.main.SIGNATURES_PATH_DEFAULT_STRING = path_object(signatures_path)
                try:
                    signatures = capa.loader.get_signatures(capa.main.SIGNATURES_PATH_DEFAULT_STRING)
                    if rules_loaded:
                        HAVE_FLARE_CAPA = True
                except IOError:
                    print("FLARE_CAPA InvalidSignatures")
            else:
                print("FLARE CAPA signature missed! You can download them using: uv run --no-sync python utils/community.py -cr")
                if not HAVE_MALCAT_CAPA:
                    HAVE_FLARE_CAPA = False

        _CAPA_MODULES_LOADED = rules_loaded
        return rules_loaded
    except ImportError as e:
        if not HAVE_MALCAT_CAPA:
            HAVE_FLARE_CAPA = False
        print(e)
        print("FLARE-CAPA missed: uv sync --locked --no-install-project --inexact")
        return False


if integrations_conf.flare_capa.enabled and (not HAVE_MALCAT_CAPA or integrations_conf.flare_capa.get("behavior", False)):
    _ensure_capa_loaded(force=False)


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


def _file_sha256(file_path: str) -> str:
    try:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return ""


def _capa_format_errors() -> tuple[type[BaseException], ...]:
    try:
        from pefile import PEFormatError
    except ImportError:
        PEFormatError = ()

    extra_unsupported = tuple(
        cls
        for cls in (
            globals().get("UnsupportedFormatError"),
            getattr(getattr(globals().get("capa"), "exceptions", None), "UnsupportedArchError", None),
            getattr(getattr(globals().get("capa"), "exceptions", None), "UnsupportedOSError", None),
            getattr(getattr(globals().get("capa"), "loader", None), "CorruptFile", None),
        )
        if cls is not None
    )
    pe_format_errs = PEFormatError if isinstance(PEFormatError, tuple) else (PEFormatError,)
    return extra_unsupported + pe_format_errs


def _preflight_capa_static(file_path: str, skip_packed: bool) -> bool:
    """Cheap parent-side format and packed-binary pre-check to avoid spawning children unnecessarily."""
    if not _CAPA_MODULES_LOADED or not rules or "capa" not in globals():
        return True

    format_errs = _capa_format_errors()
    try:
        file_path_object = path_object(file_path)
        input_format = FORMAT_AUTO
        try:
            capa_helpers = importlib.import_module("capa.helpers")

            if hasattr(capa_helpers, "get_auto_format"):
                input_format = capa_helpers.get_auto_format(file_path_object)
        except ImportError:
            pass

        format_dotnet = getattr(capa.features.common, "FORMAT_DOTNET", "dotnet")
        static_formats = getattr(capa.features.common, "STATIC_FORMATS", set())
        if static_formats and input_format != FORMAT_AUTO and input_format not in static_formats:
            log.warning("FLARE CAPA -> non-static format %s for %s, skipping", input_format, file_path)
            return False

        backend_dotnet = getattr(capa.loader, "BACKEND_DOTNET", "dotnet")
        effective_backend = backend_dotnet if input_format == format_dotnet else capa.loader.BACKEND_VIV

        if (
            skip_packed
            and effective_backend == capa.loader.BACKEND_VIV
            and input_format in static_formats
            and hasattr(capa.loader, "get_file_extractors")
            and hasattr(capa.capabilities.common, "find_file_capabilities")
            and hasattr(capa.capabilities.common, "has_static_limitation")
        ):
            file_extractors = capa.loader.get_file_extractors(file_path_object, input_format)
            for file_extractor in file_extractors:
                pure_caps = capa.capabilities.common.find_file_capabilities(rules, file_extractor, {})
                if capa.capabilities.common.has_static_limitation(rules, pure_caps, is_standalone=False):
                    log.info(
                        "FLARE CAPA -> static limitation (packed/obfuscated) detected for %s, skipping vivisect analysis",
                        file_path,
                    )
                    return False
    except format_errs as e:
        log.warning("FLARE CAPA -> %s for %s", type(e).__name__, file_path)
        return False
    except Exception as e:
        log.debug("FLARE CAPA -> preflight check failed on %s: %s", file_path, e)
        return True

    return True


def _run_capa_static(file_path: str, disable_progress: bool = True, skip_packed: bool = True) -> Dict[str, Any]:
    """Run static FLARE-CAPA extraction in the current process (intended for isolated execution)."""
    if not _ensure_capa_loaded(force=True) or not rules:
        return {}

    format_errs = _capa_format_errors()

    # ToDo check if PE file in TYPE
    try:
        file_path_object = path_object(file_path)
        input_format = FORMAT_AUTO
        try:
            capa_helpers = importlib.import_module("capa.helpers")

            if hasattr(capa_helpers, "get_auto_format"):
                input_format = capa_helpers.get_auto_format(file_path_object)
        except ImportError:
            pass

        format_dotnet = getattr(capa.features.common, "FORMAT_DOTNET", "dotnet")
        format_pe = getattr(capa.features.common, "FORMAT_PE", "pe")
        static_formats = getattr(capa.features.common, "STATIC_FORMATS", set())
        if static_formats and input_format != FORMAT_AUTO and input_format not in static_formats:
            log.warning("FLARE CAPA -> non-static format %s for %s, skipping", input_format, file_path)
            return {}
        backend_dotnet = getattr(capa.loader, "BACKEND_DOTNET", "dotnet")
        effective_backend = backend_dotnet if input_format == format_dotnet else capa.loader.BACKEND_VIV

        if (
            skip_packed
            and effective_backend == capa.loader.BACKEND_VIV
            and input_format in static_formats
            and hasattr(capa.loader, "get_file_extractors")
            and hasattr(capa.capabilities.common, "find_file_capabilities")
            and hasattr(capa.capabilities.common, "has_static_limitation")
        ):
            file_extractors = capa.loader.get_file_extractors(file_path_object, input_format)
            for file_extractor in file_extractors:
                pure_caps = capa.capabilities.common.find_file_capabilities(rules, file_extractor, {})
                if capa.capabilities.common.has_static_limitation(rules, pure_caps, is_standalone=False):
                    log.info(
                        "FLARE CAPA -> static limitation (packed/obfuscated) detected for %s, skipping vivisect analysis",
                        file_path,
                    )
                    return {}

        sigpaths = signatures if (effective_backend == capa.loader.BACKEND_VIV and input_format == format_pe and signatures) else []

        # extract features and find capabilities
        extractor = capa.loader.get_extractor(
            file_path_object, input_format, OS_AUTO, effective_backend, sigpaths, False, disable_progress=disable_progress
        )
        capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=disable_progress)
        # collect metadata (used only to make rendering more complete)
        meta = capa.loader.collect_metadata([], file_path_object, input_format, [path_object(rules_path)], extractor, capabilities)
        meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

        # ...as python dictionary, simplified as textable but in dictionary
        doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)
        return render_dictionary(doc)
    except MemoryError:
        log.warning("FLARE CAPA -> MemoryError")
    except AttributeError as e:
        log.exception(e)
        log.warning("FLARE CAPA -> Use GitHub's version. uv sync --locked --no-install-project --inexact")
    except format_errs as e:
        log.warning("FLARE CAPA -> %s for %s", type(e).__name__, file_path)
    except EmptyReportError:
        log.info("FLARE CAPA -> No process data available")
    except Exception as e:
        log.exception(e)

    return {}


def _run_capa_report(file_path: str, results: dict, disable_progress: bool = True) -> Dict[str, Any]:
    """Run FLARE-CAPA against an in-memory behavioral report dict (in-process)."""
    if not _ensure_capa_loaded(force=True) or not rules:
        return {}
    if not results:
        log.error("CAPA: Missed results probably")
        return {}
    try:
        file_path_object = path_object(file_path)
        try:
            extractor = capa.features.extractors.cape.extractor.CapeExtractor.from_report(results)
        except ValidationError as e:
            log.debug("CAPA ValidationError %s", e)
            return {}

        capabilities = capa.capabilities.common.find_capabilities(rules, extractor, disable_progress=disable_progress)
        # collect metadata (used only to make rendering more complete)
        meta = capa.loader.collect_metadata([], file_path_object, FORMAT_AUTO, [path_object(rules_path)], extractor, capabilities)
        meta.analysis.layout = capa.loader.compute_layout(rules, extractor, capabilities.matches)

        # ...as python dictionary, simplified as textable but in dictionary
        doc = rd.ResultDocument.from_capa(meta, rules, capabilities.matches)
        return render_dictionary(doc)
    except MemoryError:
        log.warning("FLARE CAPA -> MemoryError")
    except AttributeError as e:
        log.exception(e)
        log.warning("FLARE CAPA -> Use GitHub's version. uv sync --locked --no-install-project --inexact")
    except UnsupportedFormatError:
        log.error("FLARE CAPA -> UnsupportedFormatError")
    except EmptyReportError:
        log.info("FLARE CAPA -> No process data available")
    except Exception as e:
        log.exception(e)

    return {}


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
    capa_output: Dict[str, Any] = {}
    should_run = on_demand or (
        HAVE_FLARE_CAPA
        and integrations_conf.flare_capa.enabled
        and integrations_conf.flare_capa.get(category, False)
        and not integrations_conf.flare_capa.on_demand
    )
    if not should_run:
        return capa_output

    if HAVE_MALCAT_CAPA and backend == "viv":
        return malcat_capa_details(file_path, category=category, on_demand=on_demand, results=results)

    if on_demand and not rules:
        _ensure_capa_loaded(force=True)
    if not rules:
        return {}

    if backend == "cape":
        return _run_capa_report(file_path, results, disable_progress=disable_progress)
    if backend != "viv":
        log.error("CAPA: Missed results probably")
        return {}

    cache_key = _file_sha256(file_path) if (not on_demand and path_exists(file_path)) else ""
    if cache_key:
        hit, cached = get_cached_task_result("flare_capa", cache_key)
        if hit:
            return cached

    skip_packed = bool(integrations_conf.flare_capa.get("skip_packed", True)) and not on_demand
    if not _preflight_capa_static(file_path, skip_packed=skip_packed):
        if cache_key:
            set_cached_task_result("flare_capa", cache_key, {})
        return {}

    if on_demand:
        call_timeout = float(integrations_conf.flare_capa.get("on_demand_timeout", 180) or 0)
    else:
        task_cap = integrations_conf.flare_capa.get("task_timeout", 180)
        call_timeout = resolve_call_timeout(
            "flare_capa",
            integrations_conf.flare_capa.get("timeout", 60),
            task_cap,
        )
        if call_timeout < 0:
            if mark_budget_warned("flare_capa"):
                log.warning(
                    "FLARE CAPA -> per-task budget (%ss) exhausted, skipping remaining files",
                    task_cap,
                )
            return {}

    t0 = time.monotonic()
    try:
        capa_output = run_with_timeout(
            _run_capa_static,
            call_timeout,
            file_path,
            disable_progress,
            skip_packed,
        )
    except TimeoutError:
        log.warning("FLARE CAPA -> timed out after %ss on %s, skipping (partial results)", call_timeout, file_path)
        capa_output = {}
    except ResultUnavailableError:
        log.warning("FLARE CAPA -> analysis process terminated unexpectedly on %s, skipping (partial results)", file_path)
        capa_output = {}
    except Exception as e:
        log.exception(e)
        capa_output = {}
    finally:
        if not on_demand:
            record_task_budget_elapsed("flare_capa", time.monotonic() - t0)

    if cache_key:
        set_cached_task_result("flare_capa", cache_key, capa_output)

    return capa_output


if __name__ == "__main__":
    import sys
    from lib.cuckoo.common.integrations.capa import flare_capa_details, HAVE_FLARE_CAPA
    details = flare_capa_details(sys.argv[1], "static", on_demand=True)
