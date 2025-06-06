import concurrent.futures
import functools
import hashlib
import json
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess

# from contextlib import suppress
from typing import Any, DefaultDict, List, Optional, Set, Union

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

# from lib.cuckoo.common.integrations.parse_elf import ELF
from lib.cuckoo.common.load_extra_modules import file_extra_info_load_modules
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import (
    path_delete,
    path_exists,
    path_get_size,
    path_is_file,
    path_mkdir,
    path_read_file,
    path_write_file,
)
from lib.cuckoo.common.utils import get_options, is_text_file

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
sevenzip_binary = "/usr/bin/7z"
if integration_conf.SevenZip_unpack.binary:
    tmp_sevenzip_binary = os.path.join(CUCKOO_ROOT, integration_conf.SevenZip_unpack.binary)
    if path_exists(tmp_sevenzip_binary):
        sevenzip_binary = tmp_sevenzip_binary

if processing_conf.trid.enabled:
    trid_binary = os.path.join(CUCKOO_ROOT, processing_conf.trid.identifier)
    definitions = os.path.join(CUCKOO_ROOT, processing_conf.trid.definitions)

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

HAVE_MANDIANT_INTEL = False
if integration_conf.mandiant_intel.enabled:
    from lib.cuckoo.common.integrations.mandiant_intel import mandiant_lookup

    HAVE_MANDIANT_INTEL = True

exclude_startswith = ("parti_",)
excluded_extensions = (".parti",)
tools_folder = os.path.join(cfg.cuckoo.get("tmppath", "/tmp"), "cape-external")


def static_file_info(
    data_dictionary: dict,
    file_path: str,
    task_id: str,
    package: str,
    options: str,
    destination_folder: str,
    results: dict,
    duplicated: DuplicatesType,
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
        and "Zip archive data, at least v2.0" in data_dictionary["type"]
        and package in {"doc", "ppt", "xls", "pub"}
    ):
        log.info("Missed dependencies: pip3 install oletools")

    # ToDo we need type checking as it wont work for most of static jobs
    if HAVE_PEFILE and ("PE32" in data_dictionary["type"] or "MS-DOS executable" in data_dictionary["type"]):
        data_dictionary["pe"] = PortableExecutable(file_path).run(task_id)

        if HAVE_FLARE_CAPA:
            # https://github.com/mandiant/capa/issues/2620
            capa_details = flare_capa_details(file_path, "static")
            if capa_details:
                data_dictionary["flare_capa"] = capa_details

        if HAVE_FLOSS and integration_conf.floss.enabled and "Mono" not in data_dictionary["type"]:
            floss_strings = Floss(file_path, "static", "pe").run()
            if floss_strings:
                data_dictionary["floss"] = floss_strings

        if "Mono" in data_dictionary["type"]:
            if integration_conf.general.dotnet:
                data_dictionary["dotnet"] = DotNETExecutable(file_path).run()
                if processing_conf.strings.dotnet:
                    dotnet_strings = dotnet_user_strings(file_path)
                    if dotnet_strings:
                        data_dictionary.setdefault("dotnet_strings", dotnet_strings)

    elif (HAVE_OLETOOLS and package in {"doc", "ppt", "xls", "pub"} and integration_conf.general.office) or data_dictionary.get("name", "").endswith((".doc", ".ppt", ".xls", ".pub")):
        # options is dict where we need to get pass get_options
        data_dictionary["office"] = Office(file_path, task_id, data_dictionary["sha256"], options_dict).run()
    elif ("PDF" in data_dictionary["type"] or file_path.endswith(".pdf")) and integration_conf.general.pdf:
        data_dictionary["pdf"] = PDF(file_path).run()
    elif (
        package in {"wsf", "hta"} or data_dictionary["type"] == "XML document text" or file_path.endswith(".wsf")
    ) and integration_conf.general.windows_script:
        data_dictionary["wsf"] = WindowsScriptFile(file_path).run()
    # elif package in {"js", "vbs"}:
    #    data_dictionary["js"] = EncodedScriptFile(file_path).run()
    elif (package == "lnk" or "MS Windows shortcut" in data_dictionary["type"]) and integration_conf.general.lnk:
        data_dictionary["lnk"] = LnkShortcut(file_path).run()
    elif ("Java Jar" in data_dictionary["type"] or file_path.endswith(".jar")) and integration_conf.general.java:
        if integration_conf.procyon.binary and not path_exists(integration_conf.procyon.binary):
            log.error("procyon_path specified in processing.conf but the file does not exist")
        else:
            data_dictionary["java"] = Java(file_path, integration_conf.procyon.binary).run()
    elif file_path.endswith(".rdp") or data_dictionary.get("name", {}).endswith(".rdp"):
        data_dictionary["rdp"] = parse_rdp_file(file_path)
    # It's possible to fool libmagic into thinking our 2007+ file is a zip.
    # So until we have static analysis for zip files, we can use oleid to fail us out silently,
    # yeilding no static analysis results for actual zip files.
    # elif ("ELF" in data_dictionary["type"] or file_path.endswith(".elf")) and integration_conf.general.elf:
    #    data_dictionary["elf"] = ELF(file_path).run()
    #    data_dictionary["keys"] = f.get_keys()
    # elif HAVE_OLETOOLS and package == "hwp" and integration_conf.general.hwp:
    #    data_dictionary["hwp"] = HwpDocument(file_path).run()

    data = path_read_file(file_path)

    if not file_path.startswith(exclude_startswith) and not file_path.endswith(excluded_extensions):
        data_dictionary["data"] = is_text_file(data_dictionary, file_path, processing_conf.CAPE.buffer, data)

        if processing_conf.trid.enabled:
            data_dictionary["trid"] = trid_info(file_path)

        if processing_conf.die.enabled:
            data_dictionary["die"] = detect_it_easy_info(file_path)

        if HAVE_FLOSS and processing_conf.floss.enabled and "Mono" not in data_dictionary["type"]:
            floss_strings = Floss(file_path, package).run()
            if floss_strings:
                data_dictionary["floss"] = floss_strings

        if data_dictionary["data"]:
            # Don't store "strings" for text files, but don't let the web frontend
            # think that we want to look them up on-demand (i.e. display the
            # "strings" button linking to an on_demand URL).
            data_dictionary["strings"] = []
        elif HAVE_STRINGS:
            strings = extract_strings(file_path, dedup=True)
            data_dictionary["strings"] = strings
        else:
            # Don't store anything in data_dictionary["strings"] so that the frontend
            # will display the "strings" button and allow them to be fetched on-demand.
            pass

        # ToDo we need url support
        if HAVE_VIRUSTOTAL and processing_conf.virustotal.enabled:
            vt_details = vt_lookup("file", file_path, results)
            if vt_details:
                data_dictionary["virustotal"] = vt_details

        if HAVE_MANDIANT_INTEL and processing_conf.mandiant_intel.enabled:
            mandiant_intel_details = mandiant_lookup("file", file_path, results)
            if mandiant_intel_details:
                data_dictionary["mandiant_intel"] = mandiant_intel_details

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
            stderr=subprocess.STDOUT,
            universal_newlines=True,
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
        log.error(
            "Detect-It-Easy: Failed to execute cmd=`%s`, stdout=`%s`, stderr=`%s`",
            shlex.join(err.cmd),
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
            if not path_exists(dest_path):
                shutil.move(full_path, dest_path)
                print(
                    json.dumps(
                        {
                            "path": os.path.join("files", file_info["sha256"]),
                            "filepath": file_info["name"],
                            "pids": [],
                            "ppids": [],
                            "metadata": "",
                            "category": "files",
                        },
                        ensure_ascii=False,
                    ),
                    file=f,
                )
            file_info["data"] = is_text_file(file_info, destination_folder, processing_conf.CAPE.buffer)
            metadata.append(file_info)

    return metadata


def pass_signal(proc, signum, frame):
    proc.send_signal(signum)


def run_tool(*args, **kwargs) -> Union[bytes, str]:
    """Start a subprocess to run the given tool. Make sure to pass a SIGTERM signal to
    that process if it is received.
    """
    kwargs["stdout"] = subprocess.PIPE
    old_handler = None
    try:
        proc = subprocess.Popen(*args, **kwargs)
        old_handler = signal.signal(signal.SIGTERM, functools.partial(pass_signal, proc))
        (stdout, stderr) = proc.communicate()
        return stdout
    finally:
        if old_handler:
            signal.signal(signal.SIGTERM, old_handler)


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
        "filetype": data_dictionary["type"],
        "data_dictionary": data_dictionary,
        "options": options,
        "tests": tests,
    }

    file_info_funcs = [
        msi_extract,
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

    futures = {}
    with pebble.ProcessPool(max_workers=int(integration_conf.general.max_workers)) as pool:
        # Prefer custom modules over the built-in ones, since only 1 is allowed
        # to be the extracted_files_tool.
        if extra_info_modules:
            for module in extra_info_modules:
                func_timeout = int(getattr(module, "timeout", 60))
                funcname = module.__name__.split(".")[-1]
                futures[funcname] = pool.schedule(module.extract_details, args=args, kwargs=kwargs, timeout=func_timeout)

        for extraction_func in file_info_funcs:
            funcname = extraction_func.__name__.split(".")[-1]
            if (
                not getattr(integration_conf, funcname, {}).get("enabled", False)
                and getattr(extraction_func, "enabled", False) is False
            ):
                continue

            func_timeout = int(getattr(integration_conf, funcname, {}).get("timeout", 60))
            futures[funcname] = pool.schedule(extraction_func, args=args, kwargs=kwargs, timeout=func_timeout)
    pool.join()

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

    binary = shlex.split(integration_conf.eziriz_deobfuscate.binary.strip())[0]
    binary = os.path.join(CUCKOO_ROOT, binary)
    if not binary:
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
                os.path.join(CUCKOO_ROOT, binary),
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

    binary = shlex.split(integration_conf.de4dot_deobfuscate.binary.strip())[0]
    if not binary:
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
def msi_extract(file: str, *, filetype: str, **kwargs) -> ExtractorReturnType:
    """Work on MSI Installers"""

    if "MSI Installer" not in filetype:
        return

    extracted_files = []
    # sudo apt install msitools or 7z
    with extractor_ctx(file, "MsiExtract", prefix="msidump_", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        output = False
        if not kwargs.get("tests"):
            # msiextract in different way that 7z, we need to add subfolder support
            output = run_tool(
                [integration_conf.msi_extract.binary, file, "--directory", tempdir],
                universal_newlines=True,
                stderr=subprocess.PIPE,
            )
        if output:
            extracted_files = [
                extracted_file
                for extracted_file in list(filter(None, output.split("\n")))
                if path_is_file(os.path.join(tempdir, extracted_file))
            ]
        else:
            output = run_tool(
                ["7z", "e", f"-o{tempdir}", "-y", file],
                universal_newlines=True,
                stderr=subprocess.PIPE,
            )
            valid_msi_filetypes = ["PE32", "text", "Microsoft Cabinet archive"]
            for root, _, filenames in os.walk(tempdir):
                for filename in filenames:
                    path = os.path.join(root, filename)
                    if any([x in File(path).get_type() for x in valid_msi_filetypes]):
                        os.rename(path, os.path.join(root, filename.split(".")[-1].strip("'").strip("!")))
                    else:
                        path_delete(path)
            extracted_files = collect_extracted_filenames(tempdir)

        ctx["extracted_files"] = extracted_files

    return ctx


@time_tracker
def Inno_extract(file: str, *, data_dictionary: dict, **_) -> ExtractorReturnType:
    """Work on Inno Installers"""

    if all("Inno Setup" not in string for string in data_dictionary.get("die", [])):
        return

    if not path_exists(innoextact_binary):
        log.error("Missed dependency: Get a release from https://github.com/gdesmar/innoextract")
        return

    password = ""
    with extractor_ctx(file, "InnoExtract", prefix="innoextract_", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        output = run_tool(
            [innoextact_binary, file, "--output-dir", tempdir],
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )
        if (
            "Warning: Setup contains encrypted files, use the --password option to extract them" in output
            or "- encrypted" in output
        ):
            output = run_tool(
                [innoextact_binary, "--crack", file],
                universal_newlines=True,
                stderr=subprocess.PIPE,
            )
            if "Password found: " in output:
                password = output.split("\n")[0].split(": ")[1]
            if password:
                _ = run_tool(
                    [innoextact_binary, file, "--output-dir", tempdir, "--password", password],
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

    # this is useless to notify in each iteration
    if not UN_AUTOIT_NOTIF and not path_exists(unautoit_binary):
        # log.warning(f"Missing UnAutoIt binary: {unautoit_binary}. Download from - https://github.com/x0r19x91/UnAutoIt")
        UN_AUTOIT_NOTIF = True
        return

    with extractor_ctx(file, "UnAutoIt", prefix="unautoit_", folder=tools_folder) as ctx:
        tempdir = ctx["tempdir"]
        output = run_tool(
            [unautoit_binary, "extract-all", "--output-dir", tempdir, file],
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
        if output and "Unpacked 1 file." in output:
            ctx["extracted_files"] = [basename]

    return ctx


# ToDo do not ask for password + test with pass
@time_tracker
def SevenZip_unpack(file: str, *, filetype: str, data_dictionary: dict, options: dict, **_) -> ExtractorReturnType:
    tool = False

    if not path_exists(sevenzip_binary):
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

    if not path_exists("/usr/bin/unrar"):
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
    if not HAVE_ONE or open(file, "rb").read(16) not in (
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
        output = run_tool(
            ["gpg", "--passphrase", password, "--batch", "--quiet", "--yes", "-o", os.path.join(tempdir, filename), "-d", file],
            universal_newlines=True,
            stderr=subprocess.PIPE,
        )
        if output:
            ctx["extracted_files"] = collect_extracted_filenames(tempdir)

    return ctx
