import concurrent.futures
import concurrent.futures.process
import functools
import hashlib
import json
import logging
import multiprocessing
import os
import re
import shlex
import shutil
import signal
import subprocess
import tempfile

# from contextlib import suppress
from typing import Any, DefaultDict, List, Optional, Set, Tuple, Union

import pebble

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.integrations.file_extra_info_modules import (
    ExtractorReturnType,
    SuccessfulExtractionReturnType,
    collect_extracted_filenames,
    extractor_ctx,
    time_tracker,
)
from lib.cuckoo.common.integrations.parse_dotnet import DotNETExecutable
from lib.cuckoo.common.integrations.parse_java import Java
from lib.cuckoo.common.integrations.parse_lnk import LnkShortcut
from lib.cuckoo.common.integrations.parse_office import HAVE_OLETOOLS, Office
from lib.cuckoo.common.integrations.parse_pdf import PDF
from lib.cuckoo.common.integrations.parse_pe import HAVE_PEFILE, PortableExecutable
from lib.cuckoo.common.integrations.parse_rdp import parse_rdp_file
from lib.cuckoo.common.integrations.parse_wsf import WindowsScriptFile  # EncodedScriptFile
from lib.cuckoo.common.integrations.parse_msi import parse_msi

# from lib.cuckoo.common.integrations.parse_elf import ELF
from lib.cuckoo.common.load_extra_modules import file_extra_info_load_modules
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import (
    path_exists,
    path_get_size,
    path_is_file,
    path_mkdir,
    path_read_file,
    path_write_file,
)
from lib.cuckoo.common.utils import deduplicate_file_to_storage, get_options, is_text_file

try:
    from sflock import unpack

    HAVE_SFLOCK = True
except ImportError:
    HAVE_SFLOCK = False

# https://github.com/volexity/threat-intel/tree/main/tools/one-extract
try:
    HAVE_ONE = True
    from lib.cuckoo.common.integrations.office_one import OneNoteExtractor, OneNoteExtractorException
except ImportError:
    HAVE_ONE = False

DuplicatesType = DefaultDict[str, Set[str]]

cfg = Config()
processing_conf = Config("processing")
integration_conf = Config("integrations")

try:
    from modules.signatures.recon_checkip import dns_indicators
except ImportError:
    dns_indicators = ()

HAVE_FLARE_CAPA = False
# required to not load not enabled dependencies
if integration_conf.flare_capa.enabled and not integration_conf.flare_capa.on_demand:
    from lib.cuckoo.common.integrations.capa import HAVE_FLARE_CAPA, flare_capa_details

HAVE_FLOSS = False
if integration_conf.floss.enabled and not integration_conf.floss.on_demand:
    from lib.cuckoo.common.integrations.floss import HAVE_FLOSS, Floss

from lib.cuckoo.common.integrations.magika import magika_info

log = logging.getLogger(__name__)

logging.getLogger("Kixtart-Detokenizer").setLevel(logging.CRITICAL)

try:
    from lib.cuckoo.common.integrations.Kixtart.detokenize import Kixtart

    HAVE_KIXTART = True
except ImportError:
    HAVE_KIXTART = False

try:
    from lib.cuckoo.common.integrations.vbe_decoder import decode_file as vbe_decode_file

    HAVE_VBE_DECODER = True
except ImportError:
    HAVE_VBE_DECODER = False

try:
    from batch_deobfuscator.batch_interpreter import BatchDeobfuscator, handle_bat_file

    batch_deobfuscator = BatchDeobfuscator()
    HAVE_BAT_DECODER = True
except ImportError:
    HAVE_BAT_DECODER = False
    print("OPTIONAL! Missed dependency: poetry run pip install -U git+https://github.com/DissectMalware/batch_deobfuscator")

unautoit_binary = ""
innoextact_binary = ""
if integration_conf.UnAutoIt_extract.binary:
    unautoit_binary = os.path.join(CUCKOO_ROOT, integration_conf.UnAutoIt_extract.binary)
if integration_conf.Inno_extract.binary:
    innoextact_binary = os.path.join(CUCKOO_ROOT, integration_conf.Inno_extract.binary)
sevenzip_binary = os.path.join(CUCKOO_ROOT, "data/7zz")
if integration_conf.SevenZip_unpack.binary:
    tmp_sevenzip_binary = os.path.join(CUCKOO_ROOT, integration_conf.SevenZip_unpack.binary)
    if path_exists(tmp_sevenzip_binary):
        sevenzip_binary = tmp_sevenzip_binary
# fallback
if not path_exists(sevenzip_binary):
    sevenzip_binary = "/usr/bin/7z"

if processing_conf.trid.enabled:
    trid_binary = os.path.join(CUCKOO_ROOT, processing_conf.trid.identifier)
    definitions = os.path.join(CUCKOO_ROOT, processing_conf.trid.definitions)

def _get_section_if_present(conf_obj, section_name: str):
    if conf_obj is None:
        return None
    if type(conf_obj).__module__.startswith("unittest.mock") and section_name not in getattr(conf_obj, "__dict__", {}):
        return None
    sec = getattr(conf_obj, section_name, None)
    if sec is not None and not isinstance(sec, dict) and not hasattr(sec, "get"):
        return None
    return sec


def _get_docker_extra_info_conf():
    """Return the docker_extra_info config section from integrations.conf (falling back to processing.conf)."""
    int_docker = _get_section_if_present(integration_conf, "docker_extra_info")
    proc_docker = _get_section_if_present(processing_conf, "docker_extra_info")
    if int_docker and int_docker.get("enabled", False):
        return int_docker
    if proc_docker and proc_docker.get("enabled", False):
        return proc_docker
    return int_docker or proc_docker or {}


exclude_startswith = ("parti_",)
excluded_extensions = (".parti",)
_default_tools_folder = os.path.join(cfg.cuckoo.get("tmppath", "/tmp"), "cape-external")
tools_folder = _get_docker_extra_info_conf().get("shared_volume_path") or _default_tools_folder

extra_info_modules = file_extra_info_load_modules(CUCKOO_ROOT)

HAVE_STRINGS = False
if processing_conf.strings.enabled and not processing_conf.strings.on_demand:
    from lib.cuckoo.common.integrations.strings import extract_strings

    HAVE_STRINGS = True

    if processing_conf.strings.dotnet:
        from lib.cuckoo.common.dotnet_utils import dotnet_user_strings

HAVE_VIRUSTOTAL = False
if processing_conf.virustotal.enabled and not processing_conf.virustotal.on_demand:
    from lib.cuckoo.common.integrations.virustotal import vt_lookup

    HAVE_VIRUSTOTAL = True


def static_file_info(
    data_dictionary: dict,
    file_path: str,
    task_id: str,
    package: str,
    options: str,
    destination_folder: str,
    results: dict,
    duplicated: DuplicatesType,
    category: str = "files",
):
    size_mb = int(path_get_size(file_path) / (1024 * 1024))
    if size_mb > int(processing_conf.CAPE.max_file_size):
        log.info("static_file_info: skipping file that exceeded max_file_size: %s: %d MB", file_path, size_mb)
        return

    options_dict = get_options(options)
    if options_dict.get("static_file_info", "") == "off":
        return

    if (
        not HAVE_OLETOOLS
        and "Zip archive data, at least v2.0" in data_dictionary.get("type", "")
        and package in {"doc", "ppt", "xls", "pub"}
    ):
        log.info("Missed dependencies: pip3 install oletools")

    if "MSI Installer" in data_dictionary.get("type", "") and "msi" not in data_dictionary:
        data_dictionary["msi"] = parse_msi(file_path)

    # ToDo we need type checking as it wont work for most of static jobs
    if HAVE_PEFILE and ("PE32" in data_dictionary.get("type", "") or "MS-DOS executable" in data_dictionary.get("type", "")):
        if "pe" not in data_dictionary:
            with PortableExecutable(file_path) as pe:
                data_dictionary["pe"] = pe.run(task_id)

        if HAVE_FLARE_CAPA and "flare_capa" not in data_dictionary:
            # https://github.com/mandiant/capa/issues/2620
            capa_details = flare_capa_details(file_path, "static")
            if capa_details:
                data_dictionary["flare_capa"] = capa_details

        if HAVE_FLOSS and integration_conf.floss.enabled and "Mono" not in data_dictionary.get("type", "") and "floss" not in data_dictionary:
            floss_strings = Floss(file_path, "static", "pe").run()
            if floss_strings:
                data_dictionary["floss"] = floss_strings

        if "Mono" in data_dictionary.get("type", "") and "dotnet" not in data_dictionary:
            if integration_conf.general.dotnet:
                data_dictionary["dotnet"] = DotNETExecutable(file_path).run()
                if processing_conf.strings.dotnet and "dotnet_strings" not in data_dictionary:
                    dotnet_strings = dotnet_user_strings(file_path)
                    if dotnet_strings:
                        data_dictionary.setdefault("dotnet_strings", dotnet_strings)

    elif (HAVE_OLETOOLS and package in {"doc", "ppt", "xls", "pub"} and integration_conf.general.office) or data_dictionary.get("name", "").endswith((".doc", ".ppt", ".xls", ".pub")):
        if "office" not in data_dictionary:
            # options is dict where we need to get pass get_options
            data_dictionary["office"] = Office(file_path, task_id, data_dictionary["sha256"], options_dict).run()
    elif ("PDF" in data_dictionary.get("type", "") or file_path.endswith(".pdf")) and integration_conf.general.pdf:
        if "pdf" not in data_dictionary:
            data_dictionary["pdf"] = PDF(file_path).run()
    elif (
        package in {"wsf", "hta"} or data_dictionary.get("type", "") == "XML document text" or file_path.endswith(".wsf")
    ) and integration_conf.general.windows_script:
        if "wsf" not in data_dictionary:
            data_dictionary["wsf"] = WindowsScriptFile(file_path).run()
    # elif package in {"js", "vbs"}:
    #    data_dictionary["js"] = EncodedScriptFile(file_path).run()
    elif (package == "lnk" or "MS Windows shortcut" in data_dictionary.get("type", "")) and integration_conf.general.lnk:
        if "lnk" not in data_dictionary:
            data_dictionary["lnk"] = LnkShortcut(file_path).run()
    elif ("Java Jar" in data_dictionary.get("type", "") or file_path.endswith(".jar")) and integration_conf.general.java:
        if "java" not in data_dictionary:
            if integration_conf.procyon.binary and not path_exists(integration_conf.procyon.binary):
                log.error("procyon_path specified in processing.conf but the file does not exist")
            else:
                data_dictionary["java"] = Java(file_path, integration_conf.procyon.binary).run()
    elif (file_path.endswith(".rdp") or data_dictionary.get("name", "").endswith(".rdp")) and "rdp" not in data_dictionary:
        data_dictionary["rdp"] = parse_rdp_file(file_path)
    # It's possible to fool libmagic into thinking our 2007+ file is a zip.
    # So until we have static analysis for zip files, we can use oleid to fail us out silently,
    # yeilding no static analysis results for actual zip files.
    # elif ("ELF" in data_dictionary.get("type", "") or file_path.endswith(".elf")) and integration_conf.general.elf:
    #    data_dictionary["elf"] = ELF(file_path).run()
    #    data_dictionary["keys"] = f.get_keys()
    # elif HAVE_OLETOOLS and package == "hwp" and integration_conf.general.hwp:
    #    data_dictionary["hwp"] = HwpDocument(file_path).run()

    data = path_read_file(file_path)

    if not file_path.startswith(exclude_startswith) and not file_path.endswith(excluded_extensions):
        data_dictionary["data"] = is_text_file(data_dictionary, file_path, processing_conf.CAPE.buffer, data)

        if processing_conf.trid.enabled and "trid" not in data_dictionary:
            data_dictionary["trid"] = trid_info(file_path)

        if processing_conf.die.enabled and "die" not in data_dictionary:
            data_dictionary["die"] = detect_it_easy_info(file_path)

        # Below the libmagic "type" already present in data_dictionary. Cached
        # in the magika integration, so this is a no-op lookup for anything
        # that already went through File.get_all().
        magika_cfg = getattr(processing_conf, "magika", None)
        if magika_cfg and getattr(magika_cfg, "enabled", False) and "magika" not in data_dictionary:
            magika_result = magika_info(file_path)
            if magika_result:
                data_dictionary["magika"] = magika_result

        if HAVE_FLOSS and processing_conf.floss.enabled and "Mono" not in data_dictionary.get("type", "") and "floss" not in data_dictionary:
            floss_strings = Floss(file_path, package).run()
            if floss_strings:
                data_dictionary["floss"] = floss_strings

        if data_dictionary["data"]:
            # Don't store "strings" for text files, but don't let the web frontend
            # think that we want to look them up on-demand (i.e. display the
            # "strings" button linking to an on_demand URL).
            data_dictionary["strings"] = []
        elif HAVE_STRINGS and "strings" not in data_dictionary:
            strings = extract_strings(file_path, dedup=True)
            data_dictionary["strings"] = strings
        else:
            # Don't store anything in data_dictionary["strings"] so that the frontend
            # will display the "strings" button and allow them to be fetched on-demand.
            pass

        # ToDo we need url support
        if HAVE_VIRUSTOTAL and processing_conf.virustotal.enabled and "virustotal" not in data_dictionary:
            vt_details = vt_lookup("file", file_path, results, file_category=category)
            if vt_details:
                data_dictionary["virustotal"] = vt_details

    generic_file_extractors(
        file_path,
        destination_folder,
        data_dictionary,
        options_dict,
        results,
        duplicated,
    )


def detect_it_easy_info(file_path: str):
    if not path_exists(processing_conf.die.binary):
        log.warning("detect-it-easy binary not found at path %s", processing_conf.die.binary)
        return []

    try:
        die_output = subprocess.check_output(
            [processing_conf.die.binary, "-j", file_path],
            stderr=subprocess.PIPE,
            universal_newlines=True,
            errors="replace",
        )

        def get_json() -> dict[str, Any]:
            """Get the JSON element from the detect it easy output.

            This is required due to non-JSON output in JSON mode.
            https://github.com/horsicq/Detect-It-Easy/issues/242
            """
            matches = re.findall(r"\{.*\}", die_output, re.S)
            return json.loads(matches[0]) if matches else {}

        def get_matches() -> list[str]:
            """Get the string values from the detect it easy output."""
            return [sub["string"] for block in get_json().get("detects", []) for sub in block.get("values", [])]

        return [] if "detects" not in die_output else get_matches()
    except subprocess.CalledProcessError as err:
        safe_cmd = shlex.join(err.cmd).encode("utf-8", errors="replace").decode("utf-8")
        log.warning(
            "Detect-It-Easy: Failed to execute cmd=`%s` (returncode=%s), stdout=`%s`, stderr=`%s`",
            safe_cmd,
            err.returncode,
            err.stdout,
            err.stderr,
        )
    except json.decoder.JSONDecodeError as e:
        log.debug("DIE results are not in json format: %s", str(e))
    except Exception as e:
        log.error("DIE error: %s", str(e))
    return []


def trid_info(file_path: dict):
    try:
        output = subprocess.check_output(
            [trid_binary, f"-d:{definitions}", file_path],
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            errors="replace",
        )
        return output.split("\n")[6:-1]
    except subprocess.CalledProcessError:
        log.warning(
            "You need to configure your server to make TrID work properly. Run trid by hand on file as example to ensure that it works properly."
        )
        log.warning("sudo rm -f /usr/lib/locale/locale-archive && sudo locale-gen --no-archive")
    except PermissionError:
        log.error(
            "You have permission error. FIX IT! sudo chown cape:cape /opt/CAPEv2/data/trid -R && sudo chmod a+x /opt/CAPEv2/data/trid/trid"
        )
    except Exception as e:
        log.error("Trid error: %s", str(e))


def _extracted_files_metadata(
    folder: str,
    destination_folder: str,
    files: List[str],
    results: Optional[dict] = None,
) -> List[dict]:
    """
    args:
        folder - where files extracted
        destination_folder - where to move extracted files
        files - file names relative to 'folder'
    """
    metadata = []
    filelog = os.path.join(os.path.dirname(destination_folder), "files.json")
    with open(filelog, "a") as f:
        for file in files:
            full_path = os.path.join(folder, file)
            if not path_is_file(full_path):
                # ToDo walk subfolders
                continue

            size_mb = int(path_get_size(full_path) / (1024 * 1024))
            if size_mb > int(processing_conf.CAPE.max_file_size):
                log.info("_extracted_files_metadata: file exceeded max_file_size: %s: %d MB", full_path, size_mb)
                continue

            file = File(full_path)
            file_info, pefile_object = file.get_all()
            if pefile_object:
                results.setdefault("pefiles", {}).setdefault(file_info["sha256"], pefile_object)

            if processing_conf.trid.enabled:
                file_info["trid"] = trid_info(full_path)

            if processing_conf.die.enabled:
                file_info["die"] = detect_it_easy_info(full_path)

            dest_path = os.path.join(destination_folder, file_info["sha256"])
            file_info["path"] = dest_path
            file_info["guest_paths"] = [file_info["name"]]
            file_info["name"] = os.path.basename(dest_path)
            dest_existed = path_exists(dest_path)
            deduplicate_file_to_storage(full_path, file_info["sha256"], dest_path)
            if not dest_existed:
                folder_name = os.path.basename(os.path.normpath(destination_folder)) or "selfextracted"
                print(
                    json.dumps(
                        {
                            "path": os.path.join(folder_name, file_info["sha256"]),
                            "filepath": file_info["name"],
                            "pids": [],
                            "ppids": [],
                            "metadata": "",
                            "category": folder_name,
                        },
                        ensure_ascii=False,
                    ),
                    file=f,
                )
            file_info["data"] = is_text_file(file_info, destination_folder, processing_conf.CAPE.buffer)
            metadata.append(file_info)

    return metadata


from lib.cuckoo.common.integrations.utils import run_tool
from lib.cuckoo.common.pebble_utils import is_pool_healthy, teardown_pool

# Extractor sub-pool lifecycle.
#
# `generic_file_extractors` runs once per extracted file, so a task with N
# payloads calls it N times. Two strategies:
#
#   * Shared-per-task: `run_task` (under both `pebble` and `prefork` engines)
#     and `PreforkEngine._child_main` opt into the shared-per-task pool via
#     `enable_shared_extractor_pool()` and tear it down cleanly via
#     `shutdown_shared_extractor_pool()`. A single pool is created on first use
#     and reused across all N files, reclaiming the per-file fork+interpreter
#     startup cost (~1.2s/file on heavy tasks).
#
#   * Per-call: fallback when called outside `run_task` (e.g. ad-hoc extraction,
#     direct module execution, or standalone tests without shared pool enabled).
#     Creates a fork-context pool right-sized to scheduled extractors, uses it,
#     and tears it down immediately in a finally block.
_SHARED_EXTRACTOR_POOL = None
_USE_SHARED_POOL = False
_ACTIVE_EXTRACTOR_POOLS = set()
_EXTRACTOR_FINALIZER_PID = None

# Bound extractor-pool teardown. A wedged grandchild (D-state IO, a hung Java
# decompiler — see the stray hs_err_pid dumps) would otherwise make pool.join()
# block forever, hanging the whole worker with no external timeout to break it
# (the pebble task timeout only covers task execution, not teardown). Wait this
# long for a graceful drain, then force-stop.
EXTRACTOR_POOL_JOIN_TIMEOUT = 60
# Shorter bound for the reap AFTER force-stop; stop() already SIGKILLed the workers,
# so this only waits for the OS to reap them. Kept finite so a D-state straggler
# can't wedge the worker even here.
EXTRACTOR_POOL_STOP_JOIN_TIMEOUT = 5


def _stop_active_extractor_pools():
    """Force-stop any active nested extractor pools before multiprocessing's
    _exit_function() attempts to join non-daemon child processes (e.g. when a
    Pebble 5.2+ worker receives SIGTERM and invokes process_exit)."""
    global _EXTRACTOR_FINALIZER_PID
    _EXTRACTOR_FINALIZER_PID = None
    for pool in list(_ACTIVE_EXTRACTOR_POOLS):
        try:
            if hasattr(pool, "stop"):
                pool.stop()
        except Exception:
            pass
        pool_mgr = getattr(pool, "_pool_manager", None)
        worker_mgr = getattr(pool_mgr, "worker_manager", None)
        if worker_mgr is not None:
            try:
                worker_mgr.close_channels()
            except Exception:
                pass
            for proc in list(getattr(worker_mgr, "workers", {}).values()):
                try:
                    proc.terminate()
                except Exception:
                    pass
    _ACTIVE_EXTRACTOR_POOLS.clear()


def _register_extractor_pool(pool):
    global _EXTRACTOR_FINALIZER_PID
    if pool is None:
        return pool
    _ACTIVE_EXTRACTOR_POOLS.add(pool)
    current_pid = os.getpid()
    if _EXTRACTOR_FINALIZER_PID != current_pid:
        try:
            from multiprocessing.util import Finalize

            Finalize(None, _stop_active_extractor_pools, exitpriority=100)
            _EXTRACTOR_FINALIZER_PID = current_pid
        except Exception:
            pass
    return pool


def _is_extractor_pool_healthy(pool):
    """Return True if a shared extractor pool's management threads and status are healthy."""
    return is_pool_healthy(pool)


def _new_extractor_pool(max_workers=None):
    """Create a fresh fork-context pebble pool. Fork (not forkserver/spawn) is
    deliberate: the task child is single-threaded when the pool is created, so
    fork is deadlock-safe here, ~10ms/pool faster than forkserver, and leaves no
    orphans (workers are swept by the supervisor's process-group kill)."""
    ctx = multiprocessing.get_context("fork")
    configured = int(integration_conf.general.max_workers)
    workers = max(1, min(configured, int(max_workers))) if max_workers else configured
    return pebble.ProcessPool(max_workers=workers, context=ctx)


def _create_extractor_pool(max_workers=None):
    return _register_extractor_pool(_new_extractor_pool(max_workers=max_workers))


def _teardown_extractor_pool(pool):
    """Close+join a pool within a hard wall-clock bound, force-stopping any
    straggler so a hung extractor can never wedge the worker. Exception-safe.

    The pool stays registered in ``_ACTIVE_EXTRACTOR_POOLS`` if its workers
    could not be reaped (e.g. a grandchild wedged in D-state IO), so the exit
    finalizer still terminates them before multiprocessing's ``_exit_function``
    joins non-daemon children."""
    if pool is None:
        return
    reaped = teardown_pool(
        pool,
        join_timeout=EXTRACTOR_POOL_JOIN_TIMEOUT,
        stop_join_timeout=EXTRACTOR_POOL_STOP_JOIN_TIMEOUT,
        name="extractor pool",
    )
    if reaped:
        _ACTIVE_EXTRACTOR_POOLS.discard(pool)


def enable_shared_extractor_pool():
    """Opt this process into a shared extractor pool reused across every call to
    `generic_file_extractors`. Called by the task worker before processing."""
    global _USE_SHARED_POOL
    _USE_SHARED_POOL = True


def _acquire_extractor_pool(max_workers=None):
    """Return ``(pool, is_shared)``. In shared mode a single process-wide pool is
    created on first use and reused (or recreated if unhealthy); otherwise a
    fresh per-call pool right-sized to ``max_workers`` is returned."""
    global _SHARED_EXTRACTOR_POOL
    if _USE_SHARED_POOL:
        if _SHARED_EXTRACTOR_POOL is not None and not _is_extractor_pool_healthy(_SHARED_EXTRACTOR_POOL):
            log.warning("shared extractor pool became unhealthy; recreating")
            dead_pool = _SHARED_EXTRACTOR_POOL
            _SHARED_EXTRACTOR_POOL = None
            _teardown_extractor_pool(dead_pool)
        if _SHARED_EXTRACTOR_POOL is None:
            _SHARED_EXTRACTOR_POOL = _create_extractor_pool()
        return _SHARED_EXTRACTOR_POOL, True
    return _create_extractor_pool(max_workers=max_workers), False


def shutdown_shared_extractor_pool():
    """Close+join the shared extractor pool once, if one was created, and reset
    shared-pool mode. Idempotent and exception-safe; called when the task finishes."""
    global _SHARED_EXTRACTOR_POOL, _USE_SHARED_POOL
    _USE_SHARED_POOL = False
    pool = _SHARED_EXTRACTOR_POOL
    _SHARED_EXTRACTOR_POOL = None
    _teardown_extractor_pool(pool)


def generic_file_extractors(
    file: str,
    destination_folder: str,
    data_dictionary: dict,
    options: dict,
    results: dict,
    duplicated: DuplicatesType,
    tests: bool = False,
):
    """
    file - path to binary
    destination_folder - where to move extracted files
    filetype - magic string
    data_dictionary - where to add data
    options - initial task options, might contain password

    Run all extra extractors/unpackers/extra scripts here, each extractor should check file header/type/identification:
    """

    if not path_exists(destination_folder):
        path_mkdir(destination_folder)

    # Arguments that all extractors need.
    args = (file,)
    # Arguments that some extractors need. They will always get passed, so the
    # extractor functions need to accept `**_` and just discard them.
    kwargs = {
        "filetype": data_dictionary.get("type", ""),
        "data_dictionary": data_dictionary,
        "options": options,
        "tests": tests,
    }

    futures = {}
    executed_tools = data_dictionary.setdefault("executed_tools", [])
    to_schedule = []

    # Prefer custom modules over the built-in ones, since only 1 is allowed
    # to be the extracted_files_tool.
    if extra_info_modules:
        for module in extra_info_modules:
            func_timeout = int(getattr(module, "timeout", 60))
            funcname = module.__name__.split(".")[-1]
            if funcname in executed_tools:
                continue
            executed_tools.append(funcname)
            to_schedule.append((funcname, module.extract_details, func_timeout))

    for extraction_func in file_info_funcs:
        funcname = extraction_func.__name__.split(".")[-1]
        if (
            not getattr(integration_conf, funcname, {}).get("enabled", False)
            and getattr(extraction_func, "enabled", False) is False
        ):
            continue

        if funcname in executed_tools:
            continue
        executed_tools.append(funcname)

        func_timeout = int(getattr(integration_conf, funcname, {}).get("timeout", 60))
        to_schedule.append((funcname, extraction_func, func_timeout))

    if not to_schedule:
        return

    # Lazily acquire the per-call pool or shared-per-task pool only when at
    # least one extractor is actually scheduled.
    pool, shared_pool = _acquire_extractor_pool(max_workers=len(to_schedule))
    try:
        for funcname, fn, func_timeout in to_schedule:
            try:
                futures[funcname] = pool.schedule(fn, args=args, kwargs=kwargs, timeout=func_timeout)
            except (RuntimeError, concurrent.futures.process.BrokenProcessPool) as err:
                if shared_pool:
                    log.warning("shared extractor pool schedule failed (%s); recreating pool and retrying", err)
                    shutdown_shared_extractor_pool()
                    enable_shared_extractor_pool()
                    pool, shared_pool = _acquire_extractor_pool(max_workers=len(to_schedule))
                    try:
                        futures[funcname] = pool.schedule(fn, args=args, kwargs=kwargs, timeout=func_timeout)
                    except Exception as retry_err:
                        log.exception("failed to schedule extractor %s after pool recreation: %s", funcname, retry_err)
                else:
                    log.exception("failed to schedule extractor %s: %s", funcname, err)

        for funcname, future in futures.items():
            func_result = None
            try:
                func_result = future.result()
            except concurrent.futures.TimeoutError as err:
                timeout = err.args[0]
                log.debug("Function: %s took longer than %d seconds", funcname, timeout)
                continue
            except TypeError as err:
                log.debug("TypeError on getting results: %s", str(err))
            except Exception as err:
                log.exception("file_extra_info: %s", err)
                continue
            if not func_result:
                continue
            extraction_result = func_result.get("result")
            if extraction_result is None:
                continue
            tempdir = extraction_result.get("tempdir")
            if extraction_result.get("data_dictionary"):
                data_dictionary.update(extraction_result["data_dictionary"])
                extraction_result.pop("data_dictionary")
            """
            if extraction_result.get("parent_sample"):
                results.setdefault("info", {}).setdefault("parent_sample", {})
                results["info"]["parent_sample"] = extraction_result["parent_sample"]
                extraction_result.pop("parent_sample")
            """
            try:
                extracted_files = extraction_result.get("extracted_files", [])
                if not extracted_files:
                    continue
                old_tool_name = data_dictionary.get("extracted_files_tool")
                new_tool_name = extraction_result["tool_name"]
                if old_tool_name:
                    log.debug("Files already extracted from %s by %s. Also extracted with %s", file, old_tool_name, new_tool_name)
                    continue
                metadata = _extracted_files_metadata(tempdir, destination_folder, files=extracted_files, results=results)
                data_dictionary.setdefault("selfextract", {})
                data_dictionary["selfextract"][new_tool_name] = {
                    "extracted_files": metadata,
                    "extracted_files_time": func_result["took_seconds"],
                    "password": extraction_result.get("password", ""),
                }
            finally:
                if tempdir:
                    # ToDo doesn't work
                    shutil.rmtree(tempdir, ignore_errors=True)
    finally:
        # A shared pool (run_task / prefork) is kept warm for the next file and
        # torn down once via shutdown_shared_extractor_pool(); a per-call pool
        # is torn down here so no nested pool outlives the call.
        if not shared_pool:
            _teardown_extractor_pool(pool)


def _generic_post_extraction_process(file: str, tool_name: str, decoded: str) -> SuccessfulExtractionReturnType:
    with extractor_ctx(file, tool_name, folder=tools_folder) as ctx:
        basename = f"{os.path.basename(file)}_decoded"
        decoded_file_path = os.path.join(ctx["tempdir"], basename)
        _ = path_write_file(decoded_file_path, decoded, mode="text")
        ctx["extracted_files"] = [basename]

    return ctx


@time_tracker
def batch_extract(file: str, **_) -> ExtractorReturnType:
    # https://github.com/DissectMalware/batch_deobfuscator
    # https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf

    if not HAVE_BAT_DECODER or not file.endswith(".bat"):
        return

    decoded = handle_bat_file(batch_deobfuscator, file)
    if not decoded:
        return

    # compare hashes to ensure that they are not the same
    data = path_read_file(file)
    original_sha256 = hashlib.sha256(data).hexdigest()
    decoded_sha256 = hashlib.sha256(decoded).hexdigest()

    if original_sha256 == decoded_sha256:
        return

    return _generic_post_extraction_process(file, "Batch", decoded)


@time_tracker
def vbe_extract(file: str, **_) -> ExtractorReturnType:
    if not HAVE_VBE_DECODER:
        log.debug("Missed VBE decoder")
        return

    decoded = False
    data = path_read_file(file)
    if b"#@~^" not in data[:100]:
        return

    try:
        decoded = vbe_decode_file(file, data)
    except Exception as e:
        log.exception(e)

    if not decoded:
        log.debug("VBE content wasn't decoded")
        return

    return _generic_post_extraction_process(file, "Vbe", decoded)


@time_tracker
def eziriz_deobfuscate(file: str, *, data_dictionary: dict, **_) -> ExtractorReturnType:
    if file.endswith("_Slayed"):
        return

    if all(".NET Reactor" not in string for string in data_dictionary.get("die", [])):
        return

    raw_binary = integration_conf.eziriz_deobfuscate.binary.strip()
    binary = os.path.join(CUCKOO_ROOT, shlex.split(raw_binary)[0]) if raw_binary else "NETReactorSlayer.CLI"
    if not _is_tool_routed_to_docker(binary):
        if not raw_binary:
            log.warning("eziriz_deobfuscate.binary is not defined in the configuration.")
            return

        if not path_exists(binary):
            log.error(
                "Missing dependency: Download from https://github.com/otavepto/NETReactorSlayer/releases and place under %s.",
                binary,
            )
            return

        if not os.access(binary, os.X_OK):
            log.error("You need to add execution permissions: chmod a+x data/NETReactorSlayer.CLI")
            return

    with extractor_ctx(file, "eziriz", prefix="eziriz_", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        dest_path = os.path.join(tempdir, os.path.basename(file))
        _ = run_tool(
            [
                binary,
                *shlex.split(integration_conf.eziriz_deobfuscate.extra_args.strip()),
                file,
            ],
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )
        deobf_file = file + "_Slayed"
        if path_exists(deobf_file):
            shutil.move(deobf_file, dest_path)
            ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx


@time_tracker
def de4dot_deobfuscate(file: str, *, filetype: str, **_) -> ExtractorReturnType:
    if "Mono" not in filetype:
        return

    raw_binary = integration_conf.de4dot_deobfuscate.binary.strip()
    binary = shlex.split(raw_binary)[0] if raw_binary else "de4dot"
    if not _is_tool_routed_to_docker(binary):
        if not raw_binary:
            log.warning("de4dot_deobfuscate.binary is not defined in the configuration.")
            return
        if not path_exists(binary):
            log.error("Missed dependency: sudo apt install de4dot")
            return

    with extractor_ctx(file, "de4dot", prefix="de4dot_", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        dest_path = os.path.join(tempdir, os.path.basename(file))
        _ = run_tool(
            [
                binary,
                *shlex.split(integration_conf.de4dot_deobfuscate.extra_args.strip()),
                "-f",
                file,
                "-o",
                dest_path,
            ],
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )
        ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx




@time_tracker
def Inno_extract(file: str, *, data_dictionary: dict, **_) -> ExtractorReturnType:
    """Work on Inno Installers"""

    if all("Inno Setup" not in string for string in data_dictionary.get("die", [])):
        return

    binary = innoextact_binary or "innoextract"
    if not _is_tool_routed_to_docker(binary) and not path_exists(innoextact_binary):
        log.error("Missed dependency: Get a release from https://github.com/gdesmar/innoextract")
        return

    password = ""
    with extractor_ctx(file, "InnoExtract", prefix="innoextract_", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        output = run_tool(
            [binary, file, "--output-dir", tempdir],
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )
        if (
            "Warning: Setup contains encrypted files, use the --password option to extract them" in output
            or "- encrypted" in output
        ):
            output = run_tool(
                [binary, "--crack", file],
                universal_newlines=True,
                stderr=subprocess.PIPE,
            )
            if "Password found: " in output:
                password = output.split("\n")[0].split(": ")[1]
            if password:
                _ = run_tool(
                    [binary, file, "--output-dir", tempdir, "--password", password],
                    universal_newlines=True,
                    stderr=subprocess.PIPE,
                )
                ctx["password"] = password
        ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx


@time_tracker
def kixtart_extract(file: str, **_) -> ExtractorReturnType:
    """
    https://github.com/jhumble/Kixtart-Detokenizer/blob/main/detokenize.py
    """

    if not HAVE_KIXTART:
        return

    data = path_read_file(file)

    if not data.startswith(b"\x1a\xaf\x06\x00\x00\x10"):
        return

    with extractor_ctx(file, "Kixtart", prefix="kixtart_", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        kix = Kixtart(file, dump_dir=tempdir)
        kix.decrypt()
        kix.dump()
        ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx


UN_AUTOIT_NOTIF = False


@time_tracker
def UnAutoIt_extract(file: str, *, data_dictionary: dict, **_) -> ExtractorReturnType:
    global UN_AUTOIT_NOTIF
    merged_lists = data_dictionary.get("yara", []) + data_dictionary.get("cape_yara", [])
    if all(not block.get("name", "").lower().startswith("autoit") for block in merged_lists):
        return

    binary = unautoit_binary or "UnAutoIt"
    # this is useless to notify in each iteration
    if not _is_tool_routed_to_docker(binary) and not path_exists(unautoit_binary):
        if not UN_AUTOIT_NOTIF:
            # log.warning(f"Missing UnAutoIt binary: {unautoit_binary}. Download from - https://github.com/x0r19x91/UnAutoIt")
            UN_AUTOIT_NOTIF = True
        return

    with extractor_ctx(file, "UnAutoIt", prefix="unautoit_", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        output = run_tool(
            [binary, "extract-all", "--output-dir", tempdir, file],
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )
        if output:
            ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx


@time_tracker
def UPX_unpack(file: str, *, filetype: str, data_dictionary: dict, **_) -> ExtractorReturnType:
    if (
        "UPX compressed" not in filetype
        and all("UPX" not in string for string in data_dictionary.get("die", []))
        and all(block.get("name") != "UPX" for block in data_dictionary.get("yara", {}))
    ):
        return

    with extractor_ctx(file, "UnUPX", prefix="unupx_", folder=tools_folder) as ctx:
        basename = f"{os.path.basename(file)}_unpacked"
        dest_path = os.path.join(ctx["tempdir"], basename)
        output = run_tool(
            [
                "upx",
                "-d",
                file,
                f"-o{dest_path}",
            ],
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )
        if (output and "Unpacked 1 file." in output) or path_exists(dest_path):
            ctx["extracted_files"] = [basename]

    return ctx


# ToDo do not ask for password + test with pass
@time_tracker
def SevenZip_unpack(file: str, *, filetype: str, data_dictionary: dict, options: dict, **_) -> ExtractorReturnType:
    tool = False

    if not _is_tool_routed_to_docker(sevenzip_binary) and not path_exists(sevenzip_binary):
        logging.error("Missed 7zip executable. Run: poetry run python utils/community.py -waf")
        return

    # Check for msix file since it's a zip
    file_data = File(file).file_data
    if not file_data:
        log.debug("sevenzip: No file data")
        return

    if (
        ".msix" in data_dictionary.get("name", "")
        or all([pattern in file_data for pattern in (b"Registry.dat", b"AppxManifest.xml")])
        or any("MSIX Windows app" in string for string in data_dictionary.get("trid", []))
    ):
        return

    if all([pattern in file_data for pattern in (b"AndroidManifest.xml", b"classes.dex")]):
        return

    # Only for real 7zip, breaks others
    password = options.get("password", "infected")
    if any(
        "7-zip Installer data" in string for string in data_dictionary.get("die", [])
    ) or "Zip archive data" in data_dictionary.get("type", ""):
        tool = "SevenZip"
        prefix = "SevenZip_"
        password = options.get("password", "infected")
        password = f"-p{password}"

    elif any(
        "Microsoft Cabinet" in string for string in data_dictionary.get("die", [])
    ) or "Microsoft Cabinet" in data_dictionary.get("type", ""):
        tool = "UnCab"
        prefix = "cab_"
        password = ""

    elif "Nullsoft Installer self-extracting archive" in filetype or any(
        "Nullsoft Scriptable Install System" in string for string in data_dictionary.get("die", [])
    ):
        tool = "UnNSIS"
        prefix = "unnsis_"
        password = ""
        """
        elif (
            any("SFX: WinRAR" in string for string in data_dictionary.get("die", [{}]))
            or any("RAR Self Extracting archive" in string for string in data_dictionary.get("trid", []]))
            or "RAR self-extracting archive" in data_dictionary.get("type", "")
        ):
            tool = "UnRarSFX"
            prefix = "unrar_"
        """
    else:
        return

    with extractor_ctx(file, tool, prefix=prefix, folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        HAVE_SFLOCK = False
        if HAVE_SFLOCK and tool not in ("UnNSIS",):
            unpacked = unpack(file.encode(), password=password)
            for child in unpacked.children:
                _ = path_write_file(os.path.join(tempdir, child.filename.decode()), child.contents)
        else:
            sevenzip_args = [sevenzip_binary, "e", file, f"-o{tempdir}", "-y"]
            # Need this, otherwie NSIS fails
            if password:
                sevenzip_args.append(password)
            _ = run_tool(sevenzip_args, universal_newlines=True, stderr=subprocess.PIPE)
        ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx


# ToDo move to sflock
@time_tracker
def RarSFX_extract(file, *, data_dictionary, options: dict, **_) -> ExtractorReturnType:
    if (
        all("SFX: WinRAR" not in string for string in data_dictionary.get("die", []))
        and all("RAR Self Extracting archive" not in string for string in data_dictionary.get("trid", []))
        and "RAR self-extracting archive" not in data_dictionary.get("type", "")
    ):
        return

    if not _is_tool_routed_to_docker("/usr/bin/unrar") and not path_exists("/usr/bin/unrar"):
        log.warning("Missed UnRar binary: /usr/bin/unrar. sudo apt install unrar")
        return

    with extractor_ctx(file, "UnRarSFX", prefix="unrar_", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        password = options.get("password", "infected")
        output = run_tool(
            ["/usr/bin/unrar", "e", "-kb", f"-p{password}", file, tempdir],
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )
        if output:
            ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx


@time_tracker
def office_one(file, **_) -> ExtractorReturnType:
    if not HAVE_ONE:
        return

    with open(file, "rb") as f:
        header = f.read(16)

    if header not in (
        b"\xE4\x52\x5C\x7B\x8C\xD8\xA7\x4D\xAE\xB1\x53\x78\xD0\x29\x96\xD3",
        b"\xA1\x2F\xFF\x43\xD9\xEF\x76\x4C\x9E\xE2\x10\xEA\x57\x22\x76\x5F",
    ):
        return

    with extractor_ctx(file, "OfficeOne", prefix="office_one", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        try:
            document = OneNoteExtractor(path_read_file(file))
            for index, file_data in enumerate(document.extract_files()):
                target_path = os.path.join(tempdir, f"_{index}.extracted")
                _ = path_write_file(target_path, file_data)
        except OneNoteExtractorException:
            log.error("Can't process One file: %s", file)
        ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx


@time_tracker
def msix_extract(file: str, *, data_dictionary: dict, **_) -> ExtractorReturnType:
    """Work on MSIX Package"""

    if not all([pattern in File(file).file_data for pattern in (b"Registry.dat", b"AppxManifest.xml")]) and not any(
        "MSIX Windows app" in string for string in data_dictionary.get("trid", [])
    ):
        return

    with extractor_ctx(file, "MSIX", prefix="msixdump_", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        _ = run_tool(
            ["unzip", file, "-d", tempdir],
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )
        ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx


@time_tracker
def UnGPG_extract(file: str, filetype: str, data_dictionary: dict, options: dict, **_) -> ExtractorReturnType:

    if "PGP symmetric key encrypted data" not in data_dictionary.get("type", ""):
        return

    password = options.get("password", "infected")
    filename = os.path.basename(file)
    with extractor_ctx(file, "UnGPG", prefix="unpgp", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        _ = run_tool(
            ["gpg", "--passphrase", password, "--batch", "--quiet", "--yes", "-o", os.path.join(tempdir, filename), "-d", file],
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )
        ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx

file_info_funcs = [
    kixtart_extract,
    vbe_extract,
    batch_extract,
    UnAutoIt_extract,
    UPX_unpack,
    RarSFX_extract,
    Inno_extract,
    SevenZip_unpack,
    de4dot_deobfuscate,
    eziriz_deobfuscate,
    office_one,
    msix_extract,
    UnGPG_extract,
]


# Mapping of binary executable names to their corresponding integrations.conf section and default container name.
# NOTE: detect-it-easy and trid are invoked through subprocess directly (not through run_tool) and rely on
# host-side definition files, so they are deliberately not routed into containers.
BINARY_TO_TOOL_MAPPING = {
    "innoextract": ("Inno_extract", "cape-innoextract"),
    "7z": ("SevenZip_unpack", "cape-7z"),
    "7zz": ("SevenZip_unpack", "cape-7z"),
    "upx": ("UPX_unpack", "cape-upx"),
    "de4dot": ("de4dot_deobfuscate", "cape-de4dot"),
    "NETReactorSlayer.CLI": ("eziriz_deobfuscate", "cape-eziriz"),
    "UnAutoIt": ("UnAutoIt_extract", "cape-unautoit"),
    "unrar": ("RarSFX_extract", "cape-unrar"),
    "unzip": ("msix_extract", "cape-msix"),
    "msiextract": ("msi_extract", "cape-msiextract"),
    "gpg": ("UnGPG_extract", "cape-gpg"),
}

# Sections that have default active services in extra/docker/docker-compose.yml.
# Other sections default to run_in_docker = False unless explicitly enabled in integrations.conf.
DEFAULT_DOCKER_ENABLED_SECTIONS = {
    "Inno_extract",
    "SevenZip_unpack",
    "UPX_unpack",
}

try:
    import docker

    HAVE_DOCKER_SDK = True
except ImportError:
    HAVE_DOCKER_SDK = False

# Default timeout, in seconds, for a single in-container tool execution.
DOCKER_EXEC_TIMEOUT = 120


def _is_section_docker_enabled(section_name: str) -> bool:
    sec_conf = getattr(integration_conf, section_name, {})
    if not sec_conf.get("enabled", False):
        return False
    default_in_docker = section_name in DEFAULT_DOCKER_ENABLED_SECTIONS
    return bool(sec_conf.get("run_in_docker", default_in_docker))


def _is_tool_routed_to_docker(binary_name: str) -> bool:
    """Return True if docker_extra_info is enabled and the given binary is configured to run in Docker."""
    try:
        docker_conf = _get_docker_extra_info_conf()
        if not docker_conf.get("enabled", False):
            return False
        clean_name = os.path.basename(binary_name)
        if clean_name not in BINARY_TO_TOOL_MAPPING:
            return False
        section_name, _ = BINARY_TO_TOOL_MAPPING[clean_name]
        return _is_section_docker_enabled(section_name)
    except Exception:
        return False


def _is_within_shared_volume(path: str, shared_volume_path: str) -> bool:
    """Return True if path resides inside shared_volume_path on a directory boundary."""
    if not isinstance(path, str) or not os.path.isabs(path):
        return False
    try:
        abs_path = os.path.abspath(path)
        abs_vol = os.path.abspath(shared_volume_path)
        return os.path.commonpath([abs_path, abs_vol]) == abs_vol
    except ValueError:
        return False


def _split_opt_path(arg: str) -> Tuple[str, str]:
    """Split a combined option+path argument like '-o/tmp/...' into ('-o', '/tmp/...')."""
    if isinstance(arg, str) and arg.startswith("-o") and len(arg) > 2 and os.path.isabs(arg[2:]):
        return "-o", arg[2:]
    return "", arg


def _wants_text(kwargs: dict) -> bool:
    """subprocess returns str instead of bytes when any of these are set."""
    return bool(kwargs.get("universal_newlines") or kwargs.get("text") or kwargs.get("encoding") or kwargs.get("errors"))


def _coerce_output(output: Union[bytes, str, None], kwargs: dict) -> Union[bytes, str]:
    """Honour the bytes/str contract that the run_tool() caller asked for.

    Callers pass universal_newlines=True and then do string operations on the result, so
    returning raw bytes from the container would raise TypeError inside the extractors.
    """
    if output is None:
        output = b""
    if _wants_text(kwargs):
        if isinstance(output, bytes):
            return output.decode(kwargs.get("encoding") or "utf-8", errors=kwargs.get("errors") or "replace")
        return output
    if isinstance(output, str):
        return output.encode()
    return output


class ToolDispatcher:
    def __init__(self):
        global tools_folder
        self.docker_client = None
        self._docker_client_pid: Optional[int] = None
        self.enabled = False
        self.mode = "mounted"
        self.sudo_restriction = False
        self.shared_volume_path = tools_folder
        self.api_url = "http://127.0.0.1:8000"
        self.exec_timeout = DOCKER_EXEC_TIMEOUT

        # Load configuration gracefully from integrations.conf (with processing.conf fallback)
        try:
            docker_conf = _get_docker_extra_info_conf()
            self.enabled = bool(docker_conf.get("enabled", False))
            self.mode = docker_conf.get("mode", "mounted")
            self.sudo_restriction = bool(docker_conf.get("sudo_restriction", False))
            self.shared_volume_path = docker_conf.get("shared_volume_path", tools_folder) or tools_folder
            self.api_url = docker_conf.get("api_url", "http://127.0.0.1:8000")
            self.exec_timeout = int(docker_conf.get("timeout", DOCKER_EXEC_TIMEOUT))
        except Exception as e:
            log.debug("Docker extra info config not fully loaded, using defaults: %s", str(e))

        if self.enabled and self.shared_volume_path:
            tools_folder = self.shared_volume_path

    def _get_docker_client(self):
        """Return a fork-safe Docker SDK client for the current process."""
        current_pid = os.getpid()
        if self.docker_client is not None:
            if self._docker_client_pid is None or self._docker_client_pid == current_pid:
                return self.docker_client
            # Recreate client if inherited across os.fork()
            self.docker_client = None
        if not self.sudo_restriction and HAVE_DOCKER_SDK:
            try:
                self.docker_client = docker.from_env(timeout=self.exec_timeout)
                self._docker_client_pid = current_pid
            except Exception as e:
                log.error("Failed to initialize Docker SDK: %s. Falling back to subprocess execution.", str(e))
        return self.docker_client

    def is_container_configured(self, binary_name: str) -> bool:
        """Checks if Docker integration is enabled and the given binary is mapped to a container."""
        if not self.enabled:
            return False

        # Strip trailing/leading parts to isolate the binary name
        clean_name = os.path.basename(binary_name)
        if clean_name not in BINARY_TO_TOOL_MAPPING:
            return False

        section_name, _ = BINARY_TO_TOOL_MAPPING[clean_name]

        # Verify if the tool is enabled and configured to run in Docker
        try:
            return _is_section_docker_enabled(section_name)
        except Exception:
            return False

    def _resolve_container_name(self, section_name: str, default_container: str) -> str:
        """Per-tool container_name override from integrations.conf.

        Config.get() only accepts a section name and raises on missing sections, so getattr()
        with a default is used instead.
        """
        try:
            sec_conf = getattr(integration_conf, section_name, {})
            return sec_conf.get("container_name") or default_container
        except Exception:
            return default_container

    def execute_in_container(self, binary_name: str, cmd_args: List[str], **kwargs) -> Union[bytes, str]:
        """Dispatches execution of the tool inside its designated Docker container."""
        clean_name = os.path.basename(binary_name)
        section_name, default_container = BINARY_TO_TOOL_MAPPING[clean_name]
        container_name = self._resolve_container_name(section_name, default_container)

        # 1. Prepare paths in shared volume so both local containers and API gateway receive container-visible paths
        new_args, copied_files, staging_dir = self._prepare_paths_for_container(cmd_args, self.shared_volume_path)
        orig_by_staged = {}
        for orig_arg, rewritten_arg in zip(cmd_args[1:], new_args[1:]):
            _, orig_path = _split_opt_path(orig_arg)
            _, staged_path = _split_opt_path(rewritten_arg)
            if staged_path != orig_path and staged_path in copied_files:
                orig_by_staged[staged_path] = orig_path

        # 2. Replace local host binary path with the simple binary execution name inside the container
        new_args[0] = clean_name

        try:
            # 3. Route to Remote API Gateway or local Docker Exec
            if self.mode == "api":
                stdout = self._execute_via_api(container_name, new_args, **kwargs)
            elif self.sudo_restriction:
                stdout = self._execute_via_restricted_sudo(container_name, new_args, **kwargs)
            else:
                stdout = self._execute_via_sdk_or_subprocess(container_name, new_args, **kwargs)

            # Recover sidecar output files written next to staged inputs (e.g. NETReactorSlayer '<file>_Slayed')
            for staged_path, orig_path in orig_by_staged.items():
                slayed_staged = f"{staged_path}_Slayed"
                if path_exists(slayed_staged):
                    try:
                        shutil.move(slayed_staged, f"{orig_path}_Slayed")
                    except Exception as e:
                        log.warning("Failed to move sidecar output %s: %s", slayed_staged, str(e))

            return _coerce_output(stdout, kwargs)
        finally:
            # 4. Clean up any copied files on the host
            for path in copied_files:
                try:
                    os.remove(path)
                except Exception as e:
                    log.warning("Failed to clean up copied input file %s: %s", path, str(e))
            if staging_dir:
                shutil.rmtree(staging_dir, ignore_errors=True)

    def _prepare_paths_for_container(
        self, cmd_args: List[str], shared_volume_path: str
    ) -> Tuple[List[str], List[str], Optional[str]]:
        """Ensures input files are located inside the shared volume before execution.

        Returns the rewritten arguments, the list of copies made on the host and, when one had to
        be created, the private staging directory that the caller must remove afterwards.
        """
        tempdir = None
        staging_dir = None
        output_file_targets: Set[str] = set()
        for arg in cmd_args[1:]:
            _, candidate = _split_opt_path(arg)
            if isinstance(candidate, str) and _is_within_shared_volume(candidate, shared_volume_path):
                if os.path.isdir(candidate):
                    if not tempdir:
                        tempdir = candidate
                else:
                    output_file_targets.add(os.path.abspath(candidate))

        copied_files = []
        new_args = []

        for i, arg in enumerate(cmd_args):
            # Skip the first argument (index 0) because it is always the binary executable path
            if i == 0:
                new_args.append(arg)
                continue

            opt_prefix, candidate = _split_opt_path(arg)
            if (
                isinstance(candidate, str)
                and os.path.isabs(candidate)
                and not _is_within_shared_volume(candidate, shared_volume_path)
                and os.path.isfile(candidate)
            ):
                target_dir = tempdir
                if target_dir:
                    candidate_dest = os.path.abspath(os.path.join(target_dir, os.path.basename(candidate)))
                    if candidate_dest in output_file_targets:
                        target_dir = None

                if not target_dir:
                    # Never stage into the root of the shared volume or overwrite an output file target:
                    # concurrent tasks analysing files with the same basename would clobber each other's
                    # input, and staging onto an output path (e.g. de4dot -o <tempdir>/<basename>) would
                    # delete the tool's output during finally cleanup.
                    if not staging_dir:
                        try:
                            path_mkdir(shared_volume_path, exist_ok=True)
                            staging_dir = tempfile.mkdtemp(prefix="dockerstage_", dir=shared_volume_path)
                        except Exception as e:
                            log.error("Failed to create staging directory under %s: %s", shared_volume_path, str(e))
                            new_args.append(arg)
                            continue
                    target_dir = staging_dir

                dest_path = os.path.join(target_dir, os.path.basename(candidate))
                try:
                    shutil.copy2(candidate, dest_path)
                    copied_files.append(dest_path)
                    new_args.append(f"{opt_prefix}{dest_path}" if opt_prefix else dest_path)
                    log.debug("Copied file %s to shared volume at %s for Docker container", candidate, dest_path)
                except Exception as e:
                    log.error("Failed to copy file %s to %s: %s", candidate, dest_path, str(e))
                    new_args.append(arg)
            else:
                new_args.append(arg)

        return new_args, copied_files, staging_dir

    def _log_stderr(self, container_name: str, stderr: Union[bytes, str, None]):
        if not stderr:
            return
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        log.debug("Container %s stderr: %s", container_name, stderr.strip())

    def _kill_in_container(self, container_name: str, cmd_args: Optional[List[str]] = None):
        """Terminates the running tool process inside the container on SIGTERM or timeout."""
        if not cmd_args:
            return
        host_user = f"{os.getuid()}:{os.getgid()}"
        # pkill -f matches an Extended Regular Expression against /proc/<pid>/cmdline joined by spaces
        # (unquoted), so regex metacharacters must be escaped rather than shell-quoted.
        pattern = re.escape(" ".join(cmd_args))
        kill_args = ["pkill", "-TERM", "-f", "--", pattern]
        try:
            client = self._get_docker_client()
            if self.sudo_restriction:
                subprocess.run(
                    ["sudo", "-n", "docker", "exec", "-u", host_user, "-w", self.shared_volume_path, container_name]
                    + kill_args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    check=False,
                )
            elif client:
                container = client.containers.get(container_name)
                container.exec_run(cmd=kill_args, workdir=self.shared_volume_path, user=host_user, demux=True)
            else:
                subprocess.run(
                    ["docker", "exec", "-u", host_user, "-w", self.shared_volume_path, container_name] + kill_args,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=5,
                    check=False,
                )
        except Exception as e:
            log.debug("Failed to terminate process in container %s: %s", container_name, str(e))

    def _run_docker_cli(
        self, exec_cmd: List[str], container_name: str, cmd_args: Optional[List[str]] = None
    ) -> bytes:
        """Runs a docker CLI command keeping stdout and stderr separated and forwarding SIGTERM."""
        old_handler = None

        def _on_sigterm(proc, signum, frame):
            try:
                proc.send_signal(signum)
            except Exception:
                pass
            self._kill_in_container(container_name, cmd_args)
            if callable(old_handler):
                old_handler(signum, frame)

        try:
            with subprocess.Popen(
                exec_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as proc:
                try:
                    old_handler = signal.signal(signal.SIGTERM, functools.partial(_on_sigterm, proc))
                except ValueError:
                    old_handler = None
                try:
                    stdout, stderr = proc.communicate(timeout=self.exec_timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    self._kill_in_container(container_name, cmd_args)
                    log.error("Container %s execution timed out after %ds", container_name, self.exec_timeout)
                    return b""
                returncode = proc.returncode
        except Exception as e:
            log.error("Failed to run docker exec on %s: %s", container_name, str(e))
            return b""
        finally:
            if old_handler is not None:
                try:
                    signal.signal(signal.SIGTERM, old_handler)
                except ValueError:
                    pass

        self._log_stderr(container_name, stderr)
        if returncode != 0:
            log.warning("Container %s execution returned non-zero exit code: %d", container_name, returncode)
        return stdout or b""

    def _execute_via_sdk_or_subprocess(self, container_name: str, cmd_args: List[str], **kwargs) -> bytes:
        """Executes a command inside the target container using docker-py, falling back to subprocess docker exec."""
        host_user = f"{os.getuid()}:{os.getgid()}"
        client = self._get_docker_client()
        if client:
            old_handler = None

            def _on_sdk_sigterm(signum, frame):
                self._kill_in_container(container_name, cmd_args)
                if callable(old_handler):
                    old_handler(signum, frame)

            try:
                container = client.containers.get(container_name)
                if container.status != "running":
                    log.info("Starting container %s as it is currently stopped", container_name)
                    container.start()

                try:
                    old_handler = signal.signal(signal.SIGTERM, _on_sdk_sigterm)
                except ValueError:
                    old_handler = None

                # demux keeps stderr out of the returned buffer, matching stderr=subprocess.PIPE on the host
                exit_code, (stdout, stderr) = container.exec_run(
                    cmd=cmd_args, workdir=self.shared_volume_path, user=host_user, demux=True
                )
                self._log_stderr(container_name, stderr)
                if exit_code != 0:
                    log.warning("Container %s execution returned non-zero exit code: %d", container_name, exit_code)
                return stdout or b""
            except Exception as e:
                if "timed out" in str(e).lower() or "timeout" in type(e).__name__.lower():
                    self._kill_in_container(container_name, cmd_args)
                    log.error("Container %s execution timed out via Docker SDK: %s", container_name, str(e))
                    return b""
                log.error("Docker SDK execution failed for %s: %s. Falling back to subprocess exec.", container_name, str(e))
            finally:
                if old_handler is not None:
                    try:
                        signal.signal(signal.SIGTERM, old_handler)
                    except ValueError:
                        pass

        # Subprocess docker exec fallback
        exec_cmd = ["docker", "exec", "-u", host_user, "-w", self.shared_volume_path, container_name] + cmd_args
        return self._run_docker_cli(exec_cmd, container_name, cmd_args)

    def _execute_via_restricted_sudo(self, container_name: str, cmd_args: List[str], **kwargs) -> bytes:
        """Executes a command via restricted sudo command lines to satisfy /etc/sudoers hardening policy.

        -n is mandatory: without it a missing NOPASSWD rule makes sudo block on the tty forever and
        hangs the processing worker.
        """
        host_user = f"{os.getuid()}:{os.getgid()}"
        exec_cmd = ["sudo", "-n", "docker", "exec", "-u", host_user, "-w", self.shared_volume_path, container_name] + cmd_args
        return self._run_docker_cli(exec_cmd, container_name, cmd_args)

    def _execute_via_api(self, container_name: str, cmd_args: List[str], **kwargs) -> bytes:
        """Sends a request to the remote FastAPI Gateway to orchestrate the container execution."""
        import requests

        # Locate the input file to transmit (skip index 0, which is the binary executable path)
        file_to_send = None
        for arg in cmd_args[1:]:
            _, candidate = _split_opt_path(arg)
            if isinstance(candidate, str) and os.path.isabs(candidate) and os.path.isfile(candidate):
                file_to_send = candidate
                break

        if not file_to_send:
            log.error("API Mode: No input file was identified in command arguments")
            return b""

        api_cmd_args = [os.path.basename(cmd_args[0]), *cmd_args[1:]] if cmd_args else []

        try:
            with open(file_to_send, "rb") as f:
                files = {"file": f}
                data = {
                    "container_name": container_name,
                    "cmd_args": json.dumps(api_cmd_args),
                }
                url = f"{self.api_url}/extract"
                response = requests.post(url, files=files, data=data, timeout=self.exec_timeout)

                if response.status_code != 200:
                    log.error("API Gateway returned error %d: %s", response.status_code, response.text)
                    return b""

                content_type = response.headers.get("content-type", "")
                if "application/zip" not in content_type:
                    return response.content

                # Extract the ZIP to local destination directory
                dest_dir = None
                for arg in cmd_args[1:]:
                    _, candidate = _split_opt_path(arg)
                    if isinstance(candidate, str) and _is_within_shared_volume(candidate, self.shared_volume_path):
                        if os.path.isdir(candidate):
                            dest_dir = candidate
                            break
                        parent_dir = os.path.dirname(candidate)
                        if os.path.isdir(parent_dir) and _is_within_shared_volume(parent_dir, self.shared_volume_path):
                            dest_dir = parent_dir
                            break
                if not dest_dir:
                    log.error("API Mode: no destination directory inside %s was found in the arguments", self.shared_volume_path)
                    return b""

                import zipfile
                from io import BytesIO

                with zipfile.ZipFile(BytesIO(response.content)) as z:
                    for member in z.infolist():
                        member_dest = os.path.abspath(os.path.join(dest_dir, member.filename))
                        if not _is_within_shared_volume(member_dest, dest_dir):
                            log.error(
                                "API Mode: refusing to extract unsafe zip member %r outside %s",
                                member.filename,
                                dest_dir,
                            )
                            return b""
                    z.extractall(dest_dir)
                header_stdout = response.headers.get("X-Tool-Stdout")
                if header_stdout:
                    return header_stdout.encode("utf-8", errors="replace")
                return b"Extraction completed via API Gateway"
        except Exception as e:
            log.error("API Gateway connection failed: %s", str(e))
            return b""


