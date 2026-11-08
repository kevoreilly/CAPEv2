# Copyright (C) 2010-2015 Cuckoo Foundation, 2016-2026 CAPE developers.
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

"""CAPE processing and WebGUI integration helpers for static shellcode analysis."""

from collections.abc import Callable
from contextlib import suppress
import hashlib
import json
import logging
import os
from pathlib import Path
import re
import timeit
from typing import Any

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.utils import add_family_detection, deduplicate_file_to_storage, get_options

log = logging.getLogger(__name__)

HAVE_SHELLCODE_CHECK = False
with suppress(ImportError):
    from lib.cuckoo.common.integrations.shellcode_check import HAVE_CAPSTONE as HAVE_SHELLCODE_CHECK
    from lib.cuckoo.common.integrations.shellcode_check import analyse as shellcode_analyse
    from lib.cuckoo.common.integrations.shellcode_check import framework_family

processing_conf = Config("processing")
shellcode_conf = getattr(processing_conf, "static_shellcode_check", None) or {}
SHELLCODE_ON_PAYLOADS = bool(shellcode_conf.get("enabled") and shellcode_conf.get("cape_payloads"))
SHELLCODE_ON_SUBMISSION = bool(shellcode_conf.get("enabled") and shellcode_conf.get("submitted_shellcode"))
# bytes analysed in full from the start of each payload; larger payloads are still analysed and the
# deep scan still follows code past this point (e.g. a pe2shc stub at the end of a large PE)
SHELLCODE_DEPTH = int(shellcode_conf.get("shellcode_depth", 262144) or 262144)
# identified shellcode frameworks (Donut, sRDI, pe2shc) become family detections
SHELLCODE_DETECTIONS = bool(shellcode_conf.get("framework_detections"))
# payloads recovered statically (framework modules, decoded PE/shellcode) become CAPE payloads
SHELLCODE_EXTRACT = bool(shellcode_conf.get("extract_payloads"))

# recovered statically by static_shellcode_check from a shellcode payload
SHELLCODE_CODE_MAPPING = {
    0x2001: "Donut Shellcode Payload",
    0x2002: "sRDI Shellcode Payload",
    0x2003: "pe2shc Shellcode Payload",
    0x2005: "Extracted Shellcode Payload",
}
# framework -> type code of the payload extracted from it (None: decoded from an encoder or a decoder loop)
SHELLCODE_PAYLOAD_CODES = {"Donut": 0x2001, "sRDI": 0x2002, "pe2shc": 0x2003, None: 0x2005}
# Payload types the monitor labels as shellcode; confirmed by static_shellcode_check
SHELLCODE_TYPE_CODES = (4, 9)
# extracted payloads that are themselves shellcode (checked, but not extracted from again)
DERIVED_SHELLCODE_CODES = (0x2005,)
ONDEMAND_SHELLCODE_CODES = (*SHELLCODE_TYPE_CODES, *DERIVED_SHELLCODE_CODES)
ONDEMAND_SHELLCODE_CODE_STRS = tuple(str(code) for code in ONDEMAND_SHELLCODE_CODES)
# Submission packages that run the target as raw shellcode, and the architecture they imply
SHELLCODE_PACKAGES = {"shellcode": "x86", "shellcode_x64": "x64"}

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def add_framework_detections(
    file_info: dict[str, Any],
    check: dict[str, Any],
    results: dict[str, Any],
    detect2pid: Callable[[str, str], None] | None = None,
) -> None:
    """Record identified shellcode frameworks as family detections (encoders are indicators, not families)."""
    if not SHELLCODE_DETECTIONS:
        return
    for fw in check.get("frameworks") or []:
        if fw.get("confidence") != "identified":
            continue
        family = framework_family(fw["name"])
        add_family_detection(results, family, "Shellcode", file_info["sha256"])
        if detect2pid is not None and file_info.get("pid"):
            detect2pid(str(file_info["pid"]), family)


def process_file_shellcode(
    file_info: dict[str, Any],
    file_data: bytes | None,
    *,
    category: str,
    task: dict[str, Any],
    opts: dict[str, Any],
    results: dict[str, Any],
    detect2pid: Callable[[str, str], None] | None = None,
    add_statistic: Callable[..., None] | None = None,
) -> list[dict[str, Any]]:
    """Run static_shellcode_check on eligible CAPE payloads or shellcode-package submissions.

    Returns any statically recovered child payloads to be persisted after monitor dumps.
    """
    if not HAVE_SHELLCODE_CHECK or not file_data:
        return []

    # Re-run even for cached files: it is cheap and the VA hint is per-dump
    kwargs: dict[str, Any] | None = None
    code = file_info.get("cape_type_code")
    if SHELLCODE_ON_PAYLOADS and category == "CAPE" and code in SHELLCODE_TYPE_CODES:
        kwargs = {"va": file_info.get("virtual_address"), "extract_payloads": SHELLCODE_EXTRACT}
    elif SHELLCODE_ON_PAYLOADS and category == "CAPE" and code in DERIVED_SHELLCODE_CODES and file_data[:2] != b"MZ":
        kwargs = {}
    elif SHELLCODE_ON_SUBMISSION and category in ("static", "file"):
        package = task.get("package", "")
        if package in SHELLCODE_PACKAGES:
            kwargs = {
                "arch": SHELLCODE_PACKAGES[package],
                "entry": opts.get("offset"),
                "extract_payloads": SHELLCODE_EXTRACT,
            }

    if kwargs is None:
        return []

    shellcode_payloads: list[dict[str, Any]] = []
    pretime = timeit.default_timer()
    try:
        check = shellcode_analyse(file_data, max_scan=SHELLCODE_DEPTH, **kwargs)
        shellcode_payloads = check.pop("_payloads", None) or []
        # a dump that turned out to be a complete PE (DOS header not executable) is not
        # shellcode, and CAPE's PE analysis already covers it: attach nothing
        if check.get("reason") != "PE image":
            file_info["static_shellcode_check"] = check
            add_framework_detections(file_info, check, results, detect2pid=detect2pid)
    except Exception as exc:
        log.error("static_shellcode_check failed for %s: %s", file_info.get("sha256"), exc)
    if add_statistic is not None:
        add_statistic("static_shellcode_check", "time", pretime=pretime)
    return shellcode_payloads


def extract_shellcode_payloads(
    parent_info: dict[str, Any],
    payloads: list[dict[str, Any]],
    *,
    self_extracted_dir: str,
    process_file_cb: Callable[[str, bool, dict[str, Any]], Any],
) -> None:
    """Persist statically carved shellcode child payloads into selfextracted/ and process them."""
    os.makedirs(self_extracted_dir, exist_ok=True)
    check = parent_info.get("static_shellcode_check")
    pids = [parent_info["pid"]] if parent_info.get("pid") else []
    folder_name = os.path.basename(os.path.normpath(self_extracted_dir)) or "selfextracted"
    files_json_path = os.path.join(os.path.dirname(os.path.normpath(self_extracted_dir)), "files.json")
    in_cuckoo_root = False
    with suppress(ValueError, OSError):
        cuckoo_abs = os.path.abspath(CUCKOO_ROOT)
        in_cuckoo_root = os.path.commonpath([cuckoo_abs, os.path.abspath(self_extracted_dir)]) == cuckoo_abs
    for payload in payloads:
        data = payload["data"]
        sha256 = hashlib.sha256(data).hexdigest()
        path = os.path.join(self_extracted_dir, sha256)
        dest_existed = path_exists(path)
        if not dest_existed:
            Path(path).write_bytes(data)
            if in_cuckoo_root:
                with suppress(Exception):
                    deduplicate_file_to_storage(path, sha256, path)
        code = SHELLCODE_PAYLOAD_CODES.get(payload["framework"], SHELLCODE_PAYLOAD_CODES[None])
        if check is not None:
            check.setdefault("extracted", []).append(
                {
                    "sha256": sha256,
                    "size": len(data),
                    "cape_type": SHELLCODE_CODE_MAPPING[code],
                    "framework": payload["framework"],
                    "offset": payload["offset"],
                    "description": payload["description"],
                }
            )
        metadata = {
            "metadata": f"{code};?{parent_info.get('process_path', '')};?{parent_info.get('module_path', '')};?",
            "pids": pids,
            "extracted_from": parent_info["sha256"],
        }
        if not dest_existed and path_exists(files_json_path):
            with suppress(OSError), open(files_json_path, "a", encoding="utf-8") as fh:
                fh.write(
                    json.dumps(
                        {
                            "path": os.path.join(folder_name, sha256),
                            "filepath": sha256,
                            "pids": pids,
                            "ppids": [],
                            "metadata": metadata["metadata"],
                            "category": folder_name,
                        },
                        ensure_ascii=False,
                    )
                    + "\n"
                )
        process_file_cb(path, True, metadata)


def enrich_static_preview_shellcode(
    file_info: dict[str, Any],
    file_data: bytes | None,
    *,
    package: str,
    options_dict: dict[str, Any],
    sc_cfg: Any = None,
) -> None:
    """Attach read-only static shellcode analysis on submission preview for shellcode packages."""
    if not HAVE_SHELLCODE_CHECK or not file_data or "static_shellcode_check" in file_info:
        return
    if package not in SHELLCODE_PACKAGES:
        return
    if sc_cfg is None:
        sc_cfg = getattr(Config("processing"), "static_shellcode_check", None)
    sc_cfg = sc_cfg or {}
    if not (sc_cfg.get("enabled") and sc_cfg.get("submitted_shellcode") and not sc_cfg.get("on_demand")):
        return
    depth = int(sc_cfg.get("shellcode_depth", 262144) or 262144)
    try:
        check = shellcode_analyse(
            file_data,
            arch=SHELLCODE_PACKAGES[package],
            entry=options_dict.get("offset"),
            max_scan=depth,
            extract_payloads=False,
        )
        check.pop("_payloads", None)
        if check.get("reason") != "PE image":
            file_info["static_shellcode_check"] = check
    except Exception as exc:
        log.debug("Static preview shellcode check failed for %s: %s", file_info.get("sha256"), exc)


def shellcode_on_demand_kwargs(
    task_id: str | int,
    category: str,
    sha256: str,
    *,
    db: Any,
    analysis_base_path: str,
    path_safe_fn: Callable[[str], bool],
    mongodb_enabled: bool = False,
    mongo_find_one_fn: Callable[..., Any] | None = None,
) -> dict[str, Any] | None:
    """Resolve arch/entry/va hints for on-demand shellcode analysis, or None when ineligible."""
    if not isinstance(sha256, str) or not _SHA256_RE.match(sha256):
        return None
    try:
        tid = int(task_id)
    except (TypeError, ValueError):
        return None

    if category in ("static", "target.file"):
        package = ""
        options = ""
        task = db.view_task(tid) if db is not None else None
        if task:
            sample_sha = getattr(getattr(task, "sample", None), "sha256", None)
            if sample_sha and sample_sha != sha256:
                return None
            task_dict = task.to_dict()
            package = task_dict.get("package") or ""
            options = task_dict.get("options") or ""
        elif mongodb_enabled and mongo_find_one_fn is not None:
            doc = mongo_find_one_fn(
                "analysis",
                {"info.id": tid},
                {"info.package": 1, "info.options": 1, "target.file.sha256": 1},
                no_hooks=True,
            )
            if doc:
                target_sha = (doc.get("target") or {}).get("file", {}).get("sha256")
                if target_sha and target_sha != sha256:
                    return None
                info = doc.get("info") or {}
                package = info.get("package") or ""
                options = info.get("options") or ""
        if package not in SHELLCODE_PACKAGES:
            return None
        return {"arch": SHELLCODE_PACKAGES[package], "entry": get_options(options).get("offset")}

    if category != "CAPE":
        return None

    files_json = os.path.join(analysis_base_path, "analyses", str(tid), "files.json")
    if path_safe_fn(files_json) and path_exists(files_json):
        with open(files_json, "rb") as fh:
            for line in fh:
                with suppress(ValueError):
                    entry = json.loads(line)
                    if entry.get("path", "").rsplit("/", 1)[-1] == sha256:
                        parts = str(entry.get("metadata", "")).split(";?")
                        code = parts[0] if parts else ""
                        if code in ONDEMAND_SHELLCODE_CODE_STRS:
                            va = parts[3] if code == "9" and len(parts) > 3 and parts[3] else None
                            return {"va": va} if va else {}

    if mongodb_enabled and mongo_find_one_fn is not None:
        doc = mongo_find_one_fn("analysis", {"info.id": tid}, {"CAPE.payloads": 1}, no_hooks=True)
        for payload in ((doc or {}).get("CAPE") or {}).get("payloads") or []:
            if (
                isinstance(payload, dict)
                and payload.get("sha256") == sha256
                and payload.get("cape_type_code") in ONDEMAND_SHELLCODE_CODES
            ):
                va = payload.get("virtual_address")
                return {"va": va} if va else {}

    return None


def run_shellcode_on_demand(path: str, sc_kwargs: dict[str, Any], *, max_scan: int | None = None) -> dict[str, Any]:
    """Execute static_shellcode_check on disk path for an on-demand WebGUI request."""
    if max_scan is None:
        sc_cfg = getattr(Config("processing"), "static_shellcode_check", None) or {}
        max_scan = int(sc_cfg.get("shellcode_depth", 262144) or 262144)
    data = Path(path).read_bytes()
    details = shellcode_analyse(data, max_scan=max_scan, **sc_kwargs)
    details.pop("_payloads", None)
    return details
