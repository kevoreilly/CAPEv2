# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from collections import OrderedDict, defaultdict
from contextlib import suppress
import copy
import logging
import os
from pathlib import Path
import threading

from lib.cuckoo.common.cape_utils import pe_map, static_config_parsers
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.integrations.file_extra_info import (
    HAVE_OLETOOLS,
    HAVE_PEFILE,
    DotNETExecutable,
    Java,
    LnkShortcut,
    Office,
    PDF,
    PortableExecutable,
    WindowsScriptFile,
    detect_it_easy_info,
    magika_info,
    parse_msi,
    parse_rdp_file,
    trid_info,
)
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists, path_get_size, path_read_file
from lib.cuckoo.common.utils import get_options, is_text_file

log = logging.getLogger(__name__)

processing_conf = Config("processing")
integrations_conf = Config("integrations")
reporting_conf = Config("reporting")

HAVE_STRINGS = False
if processing_conf.strings.enabled:
    with suppress(ImportError):
        from lib.cuckoo.common.integrations.strings import extract_strings

        HAVE_STRINGS = True

HAVE_DOTNET_STRINGS = False
if processing_conf.strings.enabled and processing_conf.strings.dotnet:
    with suppress(ImportError):
        from lib.cuckoo.common.dotnet_utils import dotnet_user_strings

        HAVE_DOTNET_STRINGS = True

from dev_utils.mongodb import mongo_find_one, mongo_update_one

_CACHE_LOCK = threading.Lock()
_STATIC_PREVIEW_CACHE: "OrderedDict[str, dict]" = OrderedDict()
_MAX_CACHE_ENTRIES = 128


def _get_analysis_ui_configs():
    enabledconf = {}
    on_demand_conf = {}
    for cfile in ("integrations", "reporting", "processing", "auxiliary", "web", "distributed"):
        curconf = Config(cfile)
        confdata = curconf.get_config()
        for item in confdata:
            if "enabled" in confdata[item]:
                if confdata[item]["enabled"] == "yes":
                    enabledconf[item] = True
                    if confdata[item].get("on_demand", "no") == "yes":
                        on_demand_conf[item] = True
                else:
                    enabledconf[item] = False
    return enabledconf, on_demand_conf


def resolve_sample_file_path(task, sha256: str = "") -> str:
    """Locate the sample binary on disk for an in-progress or pending task."""
    if not sha256 and getattr(task, "sample", None):
        sha256 = getattr(task.sample, "sha256", "") or ""

    candidates = []
    if sha256:
        candidates.append(os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256))
    if getattr(task, "id", None) is not None:
        candidates.append(os.path.join(CUCKOO_ROOT, "storage", "analyses", str(task.id), "binary"))
    if getattr(task, "target", None):
        candidates.append(task.target)

    for candidate in candidates:
        if candidate and path_exists(candidate):
            return candidate
    return ""


def _extract_static_cape_configs(file_info: dict, file_path: str, file_data: bytes) -> list:
    """Run CAPE static_config_parsers against CAPE YARA hits and return malware_conf list."""
    configs = []
    if not file_info.get("cape_yara") or not file_data:
        return configs

    executed_parsers = defaultdict(set)
    for hit in file_info.get("cape_yara", []):
        cape_name = None
        try:
            if File.yara_hit_provides_detection(hit):
                file_info["cape_type"] = hit.get("meta", {}).get("cape_type", "")
                cape_name = File.get_cape_name_from_yara_hit(hit)
        except Exception as exc:
            log.debug("Static preview CAPE YARA type error: %s", exc)

        type_strings = (file_info.get("type") or "").split()
        if file_info.get("cape_type") and "-bit" not in file_info["cape_type"]:
            if any(i in type_strings for i in ("PE32+", "PE32")):
                pe_type = "PE32+" if "PE32+" in type_strings else "PE32"
                file_info["cape_type"] += pe_map[pe_type]
                file_info["cape_type"] += "DLL" if len(type_strings) > 2 and type_strings[2] == "(DLL)" else "executable"
            elif type_strings and type_strings[0] == "MS-DOS":
                file_info["cape_type"] = "DOS MZ image: executable"

        if cape_name and cape_name not in executed_parsers[file_path]:
            try:
                tmp_config = static_config_parsers(cape_name, file_path, file_data)
                if tmp_config:
                    _merge_cape_config(configs, cape_name, tmp_config, file_info)
            except Exception as exc:
                log.debug("Static preview config parser error for %s: %s", cape_name, exc)
            executed_parsers[file_path].add(cape_name)

    return configs


def _merge_cape_config(configs: list, cape_name: str, new_config: dict, file_obj: dict):
    associated_hashes = {
        hashtype: file_obj.get(hashtype, "") for hashtype in ("md5", "sha1", "sha256", "sha512", "sha3_384")
    }
    for existing in configs:
        if cape_name in existing:
            existing[cape_name].update(new_config[cape_name])
            hashes_list = existing.setdefault("_associated_config_hashes", [])
            if not any(h.get("sha256") == associated_hashes["sha256"] for h in hashes_list):
                hashes_list.append(associated_hashes)
            return

    config_copy = copy.deepcopy(new_config)
    config_copy["_associated_config_hashes"] = [associated_hashes]
    configs.append(config_copy)


def _run_read_only_static_enrichment(file_info: dict, file_path: str, task_id: str, package: str, options: str):
    """Run thread-safe, read-only static format and metadata extractors on file_path."""
    try:
        size_mb = int(path_get_size(file_path) / (1024 * 1024))
        if size_mb > int(processing_conf.CAPE.max_file_size):
            return
    except Exception:
        return

    options_dict = get_options(options)
    if options_dict.get("static_file_info", "") == "off":
        return

    ftype = file_info.get("type", "") or ""
    fname = file_info.get("name", "") or ""
    if isinstance(fname, list):
        fname = fname[0] if fname else ""

    if "MSI Installer" in ftype and "msi" not in file_info:
        with suppress(Exception):
            file_info["msi"] = parse_msi(file_path)

    if HAVE_PEFILE and ("PE32" in ftype or "MS-DOS executable" in ftype):
        if "pe" not in file_info:
            with suppress(Exception):
                with PortableExecutable(file_path) as pe:
                    file_info["pe"] = pe.run(task_id)

        if "Mono" in ftype and "dotnet" not in file_info and integrations_conf.general.dotnet:
            with suppress(Exception):
                file_info["dotnet"] = DotNETExecutable(file_path).run()
            if HAVE_DOTNET_STRINGS and "dotnet_strings" not in file_info:
                with suppress(Exception):
                    dotnet_strings = dotnet_user_strings(file_path)
                    if dotnet_strings:
                        file_info["dotnet_strings"] = dotnet_strings

    elif (HAVE_OLETOOLS and package in {"doc", "ppt", "xls", "pub"} and integrations_conf.general.office) or fname.endswith(
        (".doc", ".ppt", ".xls", ".pub")
    ):
        if "office" not in file_info:
            with suppress(Exception):
                file_info["office"] = Office(file_path, task_id, file_info.get("sha256", ""), options_dict).run()
    elif ("PDF" in ftype or file_path.endswith(".pdf") or fname.endswith(".pdf")) and integrations_conf.general.pdf:
        if "pdf" not in file_info:
            with suppress(Exception):
                file_info["pdf"] = PDF(file_path).run()
    elif (
        package in {"wsf", "hta"} or ftype == "XML document text" or file_path.endswith(".wsf") or fname.endswith((".wsf", ".hta"))
    ) and integrations_conf.general.windows_script:
        if "wsf" not in file_info:
            with suppress(Exception):
                file_info["wsf"] = WindowsScriptFile(file_path).run()
    elif (package == "lnk" or "MS Windows shortcut" in ftype) and integrations_conf.general.lnk:
        if "lnk" not in file_info:
            with suppress(Exception):
                file_info["lnk"] = LnkShortcut(file_path).run()
    elif ("Java Jar" in ftype or file_path.endswith(".jar") or fname.endswith(".jar")) and integrations_conf.general.java:
        if "java" not in file_info and (
            not integrations_conf.procyon.binary or path_exists(integrations_conf.procyon.binary)
        ):
            with suppress(Exception):
                file_info["java"] = Java(file_path, integrations_conf.procyon.binary).run()
    elif (file_path.endswith(".rdp") or fname.endswith(".rdp")) and "rdp" not in file_info:
        with suppress(Exception):
            file_info["rdp"] = parse_rdp_file(file_path)

    file_data = b""
    with suppress(Exception):
        file_data = path_read_file(file_path)

    with suppress(Exception):
        file_info["data"] = is_text_file(file_info, file_path, processing_conf.CAPE.buffer, file_data)

    if processing_conf.trid.enabled and "trid" not in file_info:
        with suppress(Exception):
            file_info["trid"] = trid_info(file_path)

    if processing_conf.die.enabled and "die" not in file_info:
        with suppress(Exception):
            file_info["die"] = detect_it_easy_info(file_path)

    magika_cfg = getattr(processing_conf, "magika", None)
    if magika_cfg and getattr(magika_cfg, "enabled", False) and "magika" not in file_info:
        with suppress(Exception):
            magika_result = magika_info(file_path)
            if magika_result:
                file_info["magika"] = magika_result

    if file_info.get("data"):
        file_info["strings"] = []
    elif (
        HAVE_STRINGS
        and processing_conf.strings.enabled
        and not processing_conf.strings.on_demand
        and "strings" not in file_info
    ):
        with suppress(Exception):
            file_info["strings"] = extract_strings(file_path, dedup=True)


def _store_in_memory_cache(sha256: str, file_info: dict, malware_conf: list, enriched: bool):
    if not sha256:
        return
    with _CACHE_LOCK:
        _STATIC_PREVIEW_CACHE[sha256] = {
            "file": copy.deepcopy(file_info),
            "malware_conf": copy.deepcopy(malware_conf),
            "enriched": bool(enriched),
        }
        _STATIC_PREVIEW_CACHE.move_to_end(sha256)
        while len(_STATIC_PREVIEW_CACHE) > _MAX_CACHE_ENTRIES:
            _STATIC_PREVIEW_CACHE.popitem(last=False)


def _persist_static_preview_to_mongo(sha256: str, task_id, file_info: dict, malware_conf: list):
    """Persist enriched static preview data into MongoDB ``files`` collection."""
    if not reporting_conf.mongodb.enabled or not sha256:
        return

    doc = {
        k: copy.deepcopy(v)
        for k, v in file_info.items()
        if k not in ("_id", "_task_ids", "path", "name")
    }
    doc["_id"] = sha256
    doc["sha256"] = sha256
    doc["yara_hash"] = file_info.get("yara_hash") or getattr(File, "yara_rules_hash", "")
    doc["static_preview_enriched"] = True
    doc["static_preview_malware_conf"] = copy.deepcopy(malware_conf)

    update_op = {"$set": doc}
    if isinstance(task_id, int) and task_id > 0:
        update_op["$addToSet"] = {"_task_ids": task_id}

    try:
        mongo_update_one("files", {"_id": sha256}, update_op, upsert=True)
    except Exception as exc:
        if "strings" in doc and isinstance(doc["strings"], list) and len(doc["strings"]) > 1000:
            log.warning("Static preview MongoDB upsert failed (%s); retrying with truncated strings.", exc)
            doc["strings"] = doc["strings"][:1000]
            with suppress(Exception):
                mongo_update_one("files", {"_id": sha256}, update_op, upsert=True)
        else:
            log.debug("Static preview MongoDB persistence skipped for %s: %s", sha256, exc)


def get_static_preview(task, run_full: bool = False) -> dict | None:
    """Build static file information and CAPE config preview for a task.

    When ``run_full=False``, returns immediately using SQL Sample metadata,
    in-memory cache, and MongoDB ``files`` cache without running heavy parsers.
    When ``run_full=True``, executes ``File.get_all()``, format parsers, DIE/TriD,
    strings, and ``static_config_parsers`` and caches/persists the result.
    """
    category = getattr(task, "category", "") or ""
    sample = getattr(task, "sample", None)
    if category == "url" or (category not in ("file", "static", "archive") and not sample):
        return None

    target_name = os.path.basename(task.target) if getattr(task, "target", None) else ""
    sha256 = getattr(sample, "sha256", "") if sample else ""
    source_url = (getattr(sample, "source_url", "") if sample else "") or ""

    file_info = {
        "name": target_name or sha256,
        "size": getattr(sample, "file_size", 0) if sample else 0,
        "crc32": getattr(sample, "crc32", "") if sample else "",
        "md5": getattr(sample, "md5", "") if sample else "",
        "sha1": getattr(sample, "sha1", "") if sample else "",
        "sha256": sha256,
        "sha512": getattr(sample, "sha512", "") if sample else "",
        "ssdeep": getattr(sample, "ssdeep", "") if sample else "",
        "type": getattr(sample, "file_type", "") if sample else "",
    }
    malware_conf = []
    static_enriched = False
    yara_already_cached = False

    # Check MongoDB files cache first if enabled (shared across all web workers & post-processing)
    if reporting_conf.mongodb.enabled and sha256:
        with suppress(Exception):
            db_file = mongo_find_one("files", {"_id": sha256}) or mongo_find_one("files", {"sha256": sha256})
            if isinstance(db_file, dict):
                if isinstance(db_file.get("static_preview_malware_conf"), list):
                    malware_conf = copy.deepcopy(db_file["static_preview_malware_conf"])
                static_enriched = bool(db_file.get("static_preview_enriched", False))
                current_yara_hash = getattr(File, "yara_rules_hash", "")
                if current_yara_hash and db_file.get("yara_hash") == current_yara_hash and "yara" in db_file:
                    yara_already_cached = True
                db_copy = {
                    k: v
                    for k, v in db_file.items()
                    if k not in ("_id", "_task_ids", "path", "static_preview_malware_conf", "static_preview_enriched")
                }
                file_info.update(db_copy)
                if target_name:
                    file_info["name"] = target_name
                if static_enriched:
                    _store_in_memory_cache(sha256, file_info, malware_conf, True)
                    return _format_preview_context(task, file_info, malware_conf, source_url, True)

    if sha256:
        with _CACHE_LOCK:
            cached_entry = _STATIC_PREVIEW_CACHE.get(sha256)
            if cached_entry is not None:
                _STATIC_PREVIEW_CACHE.move_to_end(sha256)
                cached_file = copy.deepcopy(cached_entry["file"])
                if target_name:
                    cached_file["name"] = target_name
                file_info.update(cached_file)
                malware_conf = copy.deepcopy(cached_entry.get("malware_conf", []))
                static_enriched = bool(cached_entry.get("enriched", False))
                if static_enriched or not run_full:
                    return _format_preview_context(task, file_info, malware_conf, source_url, static_enriched)

    if not run_full:
        return _format_preview_context(task, file_info, malware_conf, source_url, static_enriched)

    file_path = resolve_sample_file_path(task, sha256=sha256)
    if file_path and path_exists(file_path):
        try:
            f_obj = File(file_path)
            if not yara_already_cached:
                full_info, _ = f_obj.get_all()
                file_info.update(full_info)
                file_info["yara_hash"] = getattr(File, "yara_rules_hash", "")
            if target_name:
                file_info["name"] = target_name
            sha256 = file_info.get("sha256", sha256)

            _run_read_only_static_enrichment(
                file_info,
                file_path,
                str(task.id),
                getattr(task, "package", "") or "",
                getattr(task, "options", "") or "",
            )

            file_data = f_obj.file_data
            if file_data is None and path_exists(file_path):
                file_data = Path(file_path).read_bytes()
            malware_conf = _extract_static_cape_configs(file_info, file_path, file_data or b"")
            static_enriched = True
        except Exception as exc:
            log.warning("Static preview extraction failed for task %s: %s", getattr(task, "id", "?"), exc)

    if sha256:
        _store_in_memory_cache(sha256, file_info, malware_conf, static_enriched)
        if static_enriched:
            _persist_static_preview_to_mongo(sha256, getattr(task, "id", None), file_info, malware_conf)

    return _format_preview_context(task, file_info, malware_conf, source_url, static_enriched)


def update_static_preview_service(sha256: str, service: str, details) -> dict | None:
    """Update cached static file preview with an on-demand service result."""
    if not sha256:
        return None

    with _CACHE_LOCK:
        entry = _STATIC_PREVIEW_CACHE.get(sha256)
        if entry is None:
            entry = {"file": {"sha256": sha256}, "malware_conf": [], "enriched": False}
            _STATIC_PREVIEW_CACHE[sha256] = entry
        file_obj = entry["file"]
        if service == "xlsdeobf":
            file_obj.setdefault("office", {})["XLMMacroDeobfuscator"] = details
        else:
            file_obj[service] = details
        _STATIC_PREVIEW_CACHE.move_to_end(sha256)
        updated_file = copy.deepcopy(file_obj)

    if reporting_conf.mongodb.enabled:
        with suppress(Exception):
            update_field = "office.XLMMacroDeobfuscator" if service == "xlsdeobf" else service
            mongo_update_one("files", {"_id": sha256}, {"$set": {update_field: details}}, upsert=True)

    return updated_file


def _format_preview_context(task, file_info: dict, malware_conf: list, source_url: str, static_enriched: bool) -> dict:
    enabledconf, on_demand_conf = _get_analysis_ui_configs()
    task_id = getattr(task, "id", 0)
    analysis_stub = {
        "info": {
            "id": task_id,
            "category": getattr(task, "category", "file"),
            "tlp": getattr(task, "tlp", None),
            "has_cents_rules": False,
        },
        "target": {"category": getattr(task, "category", "file"), "file": file_info},
        "malware_conf": malware_conf,
    }
    return {
        "file": file_info,
        "analysis": analysis_stub,
        "malware_conf": malware_conf,
        "source_url": source_url,
        "static_enriched": static_enriched,
        "id": task_id,
        "tab_name": "static",
        "config": enabledconf,
        "on_demand": on_demand_conf,
        "graphs": {
            "vba2graph": {"enabled": False, "content": {}},
            "bingraph": {"enabled": False, "content": {}},
        },
    }
