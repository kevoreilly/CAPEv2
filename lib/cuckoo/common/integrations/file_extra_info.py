import hashlib
import json
import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from typing import List

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.integrations.parse_dotnet import DotNETExecutable
from lib.cuckoo.common.integrations.parse_java import Java
from lib.cuckoo.common.integrations.parse_lnk import LnkShortcut
from lib.cuckoo.common.integrations.parse_office import HAVE_OLETOOLS, Office

# ToDo duplicates logging here
from lib.cuckoo.common.integrations.parse_pdf import PDF
from lib.cuckoo.common.integrations.parse_pe import HAVE_PEFILE, PortableExecutable
from lib.cuckoo.common.integrations.parse_wsf import WindowsScriptFile  # EncodedScriptFile
from lib.cuckoo.common.objects import File

# from lib.cuckoo.common.integrations.parse_elf import ELF
from lib.cuckoo.common.utils import get_options, is_text_file

try:
    from sflock import unpack

    HAVE_SFLOCK = True
except ImportError:
    HAVE_SFLOCK = False

processing_conf = Config("processing")

HAVE_FLARE_CAPA = False
# required to not load not enabled dependencies
if processing_conf.flare_capa.enabled and not processing_conf.flare_capa.on_demand:
    from lib.cuckoo.common.integrations.capa import HAVE_FLARE_CAPA, flare_capa_details

HAVE_FLOSS = False
if processing_conf.floss.enabled and not processing_conf.floss.on_demand:
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
    print("Missed dependency: pip3 install -U git+https://github.com/DissectMalware/batch_deobfuscator")

processing_conf = Config("processing")
selfextract_conf = Config("selfextract")

unautoit_binary = os.path.join(CUCKOO_ROOT, selfextract_conf.UnAutoIt_extract.binary)

if processing_conf.trid.enabled:
    trid_binary = os.path.join(CUCKOO_ROOT, processing_conf.trid.identifier)
    definitions = os.path.join(CUCKOO_ROOT, processing_conf.trid.definitions)

HAVE_FLOSS = False
if processing_conf.floss.enabled and not processing_conf.floss.on_demand:
    from lib.cuckoo.common.integrations.floss import HAVE_FLOSS, Floss

HAVE_STRINGS = False
if processing_conf.strings.enabled and not processing_conf.strings.on_demand:
    from lib.cuckoo.common.integrations.strings import extract_strings

    HAVE_STRINGS = True


HAVE_VIRUSTOTAL = False
if processing_conf.virustotal.enabled and not processing_conf.virustotal.on_demand:
    from lib.cuckoo.common.integrations.virustotal import vt_lookup

    HAVE_VIRUSTOTAL = True


def static_file_info(
    data_dictionary: dict, file_path: str, task_id: str, package: str, options: str, destination_folder: str, results: dict
):

    if int(os.path.getsize(file_path) / (1024 * 1024)) > int(processing_conf.static.max_file_size):
        return

    if (
        not HAVE_OLETOOLS
        and "Zip archive data, at least v2.0" in data_dictionary["type"]
        and package in {"doc", "ppt", "xls", "pub"}
    ):
        log.info("Missed dependencies: pip3 install oletools")

    options_dict = get_options(options)

    if HAVE_PEFILE and ("PE32" in data_dictionary["type"] or "MS-DOS executable" in data_dictionary["type"]):
        data_dictionary["pe"] = PortableExecutable(file_path).run(task_id)

        if HAVE_FLARE_CAPA:
            capa_details = flare_capa_details(file_path, "static")
            if capa_details:
                data_dictionary["flare_capa"] = capa_details

        if HAVE_FLOSS:
            floss_strings = Floss(file_path, "static", "pe").run()
            if floss_strings:
                data_dictionary["floss"] = floss_strings

        if "Mono" in data_dictionary["type"]:
            data_dictionary["dotnet"] = DotNETExecutable(file_path).run()
    elif HAVE_OLETOOLS and package in {"doc", "ppt", "xls", "pub"}:
        # options is dict where we need to get pass get_options
        data_dictionary["office"] = Office(file_path, task_id, data_dictionary["sha256"], options_dict).run()
    elif "PDF" in data_dictionary["type"] or file_path.endswith(".pdf"):
        data_dictionary["pdf"] = PDF(file_path).run()
    elif package in {"wsf", "hta"} or data_dictionary["type"] == "XML document text" or file_path.endswith(".wsf"):
        data_dictionary["wsf"] = WindowsScriptFile(file_path).run()
    # elif package in {"js", "vbs"}:
    #    data_dictionary["js"] = EncodedScriptFile(file_path).run()
    elif package == "lnk" or "MS Windows shortcut" in data_dictionary["type"]:
        data_dictionary["lnk"] = LnkShortcut(file_path).run()
    elif "Java Jar" in data_dictionary["type"] or file_path.endswith(".jar"):
        if selfextract_conf.procyon.binary and not os.path.exists(selfextract_conf.procyon.binary):
            log.error("procyon_path specified in processing.conf but the file does not exist")
        else:
            data_dictionary["java"] = Java(file_path, selfextract_conf.procyon.binary).run()

    # It's possible to fool libmagic into thinking our 2007+ file is a zip.
    # So until we have static analysis for zip files, we can use oleid to fail us out silently,
    # yeilding no static analysis results for actual zip files.
    # elif "ELF" in data_dictionary["type"] or file_path.endswith(".elf"):
    #    data_dictionary["elf"] = ELF(file_path).run()
    #    data_dictionary["keys"] = f.get_keys()
    # elif HAVE_OLETOOLS and package == "hwp":
    #    data_dictionary["hwp"] = HwpDocument(file_path).run()

    with open(file_path, "rb") as f:
        is_text_file(data_dictionary, file_path, 8192, f.read())

    if processing_conf.trid.enabled:
        trid_info(file_path, data_dictionary)

    if processing_conf.die.enabled:
        detect_it_easy_info(file_path, data_dictionary)

    if HAVE_FLOSS and processing_conf.floss.enabled:
        floss_strings = Floss(file_path, package).run()
        if floss_strings:
            data_dictionary["floss"] = floss_strings

    if HAVE_STRINGS:
        strings = extract_strings(file_path)
        if strings:
            data_dictionary["strings"] = strings

    # ToDo we need url support
    if HAVE_VIRUSTOTAL and processing_conf.virustotal.enabled:
        vt_details = vt_lookup("file", file_path, results)
        if vt_details:
            data_dictionary["virustotal"] = vt_details

    generic_file_extractors(file_path, destination_folder, data_dictionary["type"], data_dictionary, options_dict, results)


def detect_it_easy_info(file_path: str, data_dictionary: dict):
    if not os.path.exists(processing_conf.die.binary):
        return

    try:
        output = subprocess.check_output(
            [processing_conf.die.binary, "-j", file_path], stderr=subprocess.STDOUT, universal_newlines=True
        )
        if "detects" not in output:
            return

        strings = [sub["string"] for block in json.loads(output).get("detects", []) for sub in block.get("values", [])]

        if strings:
            data_dictionary["die"] = strings
    except subprocess.CalledProcessError:
        log.warning("You need to configure your server to make TrID work properly")
        log.warning("sudo rm -f /usr/lib/locale/locale-archive && sudo locale-gen --no-archive")


def trid_info(file_path: dict, data_dictionary: dict):
    try:
        output = subprocess.check_output(
            [trid_binary, f"-d:{definitions}", file_path], stderr=subprocess.STDOUT, universal_newlines=True
        )
        data_dictionary["trid"] = output.split("\n")[6:-1]
    except subprocess.CalledProcessError:
        log.warning("You need to configure your server to make TrID work properly")
        log.warning("sudo rm -f /usr/lib/locale/locale-archive && sudo locale-gen --no-archive")


def _extracted_files_metadata(folder: str, destination_folder: str, files: list = None) -> List[dict]:
    """
    args:
        folder - where files extracted
        destination_folder - where to move extracted files
        files - file names
    """
    metadata = []
    filelog = os.path.join(os.path.dirname(destination_folder), "files.json")
    if not files:
        files = os.listdir(folder)
    with open(filelog, "a") as f:
        for file in files:
            full_path = os.path.join(folder, file)
            file_details, _pe = File(full_path).get_all()

            if processing_conf.trid.enabled:
                trid_info(full_path, file_details)

            if processing_conf.die.enabled:
                detect_it_easy_info(full_path, file_details)

            dest_path = os.path.join(destination_folder, file_details["sha256"])
            file_details["path"] = dest_path
            file_details["name"] = os.path.basename(dest_path)
            metadata.append(file_details)
            if not os.path.exists(dest_path):
                shutil.move(full_path, dest_path)
                print(
                    json.dumps(
                        {
                            "path": os.path.join("files", file_details["sha256"]),
                            "filepath": file_details["name"],
                            "pids": [],
                            "ppids": [],
                            "metadata": "",
                            "category": "files",
                        },
                        ensure_ascii=False,
                    ),
                    file=f,
                )

    return metadata


def generic_file_extractors(file: str, destination_folder: str, filetype: str, data_dictionary: dict, options: dict, results: dict):
    """
    file - path to binary
    destination_folder - where to move extracted files
    filetype - magic string
    data_dictionary - where to add data
    options - initial task options, might contain password

    Run all extra extractors/unpackers/extra scripts here, each extractor should check file header/type/identification:
    """

    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)

    for funcname in (
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
    ):

        if not getattr(selfextract_conf, funcname.__name__).get("enabled", False):
            continue
        try:
            extraction_result = funcname(file, destination_folder, filetype, data_dictionary, options, results)
            if extraction_result is not None:
                tool_name, metadata = extraction_result
                if metadata:
                    for meta in metadata:
                        is_text_file(meta, destination_folder, 8192)

                    data_dictionary.setdefault("extracted_files", metadata)
                    data_dictionary.setdefault("extracted_files_tool", tool_name)
        except Exception as e:
            log.error(e, exc_info=True)


def _generic_post_extraction_process(file: str, decoded: str, destination_folder: str, data_dictionary: dict):
    with tempfile.TemporaryDirectory() as tempdir:
        decoded_file_path = os.path.join(tempdir, f"{os.path.basename(file)}_decoded")
        with open(decoded_file_path, "w") as f:
            f.write(decoded)

    return _extracted_files_metadata(tempdir, destination_folder, files=[decoded_file_path])


def batch_extract(file: str, destination_folder: str, filetype: str, data_dictionary: dict, options: dict, results: dict):
    # https://github.com/DissectMalware/batch_deobfuscator
    # https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/dosfuscation-report.pdf

    if not HAVE_BAT_DECODER or not file.endswith(".bat"):
        return

    decoded = handle_bat_file(batch_deobfuscator, file)
    if not decoded:
        return

    # compare hashes to ensure that they are not the same
    with open(file, "rb") as f:
        data = f.read()

    original_sha256 = hashlib.sha256(data).hexdigest()
    decoded_sha256 = hashlib.sha256(decoded).hexdigest()

    if original_sha256 == decoded_sha256:
        return

    return "Batch", _generic_post_extraction_process(file, decoded, destination_folder, data_dictionary)


def vbe_extract(file: str, destination_folder: str, filetype: str, data_dictionary: dict, options: dict, results: dict):

    if not HAVE_VBE_DECODER:
        log.debug("Missed VBE decoder")
        return

    decoded = False

    with open(file, "rb") as f:
        data = f.read()

    if b"#@~^" not in data[:100]:
        return

    try:
        decoded = vbe_decode_file(file, data)
    except Exception as e:
        log.error(e, exc_info=True)

    if not decoded:
        log.debug("VBE content wasn't decoded")
        return

    return "Vbe", _generic_post_extraction_process(file, decoded, destination_folder, data_dictionary)


def de4dot_deobfuscate(file: str, destination_folder: str, filetype: str, data_dictionary: dict, options: dict, results: dict):
    if "Mono" not in filetype:
        return

    de4dot_binary = shlex.split(selfextract_conf.de4dot_deobfuscate.binary.strip())
    if not de4dot_binary:
        log.warning("de4dot_deobfuscate.binary is not defined in the configuration.")
        return
    if not os.path.exists(de4dot_binary[0]):
        log.error("Missed dependency: sudo apt install de4dot")
        return
    metadata = []

    with tempfile.TemporaryDirectory(prefix="de4dot_") as tempdir:
        try:
            dest_path = os.path.join(tempdir, os.path.basename(file))
            output = subprocess.check_output(
                [
                    *de4dot_binary,
                    *shlex.split(selfextract_conf.de4dot_deobfuscate.extra_args.strip()),
                    "-f",
                    file,
                    "-o",
                    dest_path,
                ],
                universal_newlines=True,
            )
            metadata.extend(_extracted_files_metadata(tempdir, destination_folder))
        except subprocess.CalledProcessError:
            log.exception("Failed to deobfuscate %s with de4dot.", file)
        except Exception as e:
            log.error(e, exc_info=True)

    return "de4dot", metadata


def msi_extract(file: str, destination_folder: str, filetype: str, data_dictionary: dict, options: dict, results: dict):
    """Work on MSI Installers"""

    if "MSI Installer" not in filetype:
        return

    if not os.path.exists(selfextract_conf.msi_extract.binary):
        log.error("Missed dependency: sudo apt install msitools")
        return

    metadata = []
    files = []

    with tempfile.TemporaryDirectory(prefix="msidump_") as tempdir:
        try:
            output = subprocess.check_output(
                [selfextract_conf.msi_extract.binary, file, "--directory", tempdir], universal_newlines=True
            )
            if output:
                files = [
                    extracted_file
                    for extracted_file in list(filter(None, output.split("\n")))
                    if os.path.isfile(os.path.join(tempdir, extracted_file))
                ]
            else:
                output = subprocess.check_output(
                    [
                        "7z",
                        "e",
                        f"-o{tempdir}",
                        "-y",
                        file,
                        "Binary.*",
                    ],
                    universal_newlines=True,
                )
                for root, _, filenames in os.walk(tempdir):
                    for filename in filenames:
                        os.rename(os.path.join(root, filename), os.path.join(root, filename.split("Binary.")[-1]))
                files = [
                    extracted_file.split("Binary.")[-1]
                    for root, _, extracted_files in os.walk(tempdir)
                    for extracted_file in extracted_files
                    if os.path.isfile(os.path.join(tempdir, extracted_file))
                ]
            if files:
                metadata.extend(_extracted_files_metadata(tempdir, destination_folder, files=files))
        except Exception as e:
            log.error(e, exc_info=True)

    return "MsiExtract", metadata


def Inno_extract(file: str, destination_folder: str, filetype: str, data_dictionary: dict, options: dict, results: dict):
    """Work on Inno Installers"""

    if all("Inno Setup" not in string for string in data_dictionary.get("die", {})):
        return

    if not os.path.exists(selfextract_conf.Inno_extract.binary):
        log.error("Missed dependency: sudo apt install innoextract")
        return

    metadata = []

    with tempfile.TemporaryDirectory(prefix="innoextract_") as tempdir:
        try:
            subprocess.check_output([selfextract_conf.Inno_extract.binary, file, "--output-dir", tempdir], universal_newlines=True)
            files = [os.path.join(root, file) for root, _, filenames in os.walk(tempdir) for file in filenames]
            metadata.extend(_extracted_files_metadata(tempdir, destination_folder, files=files))
        except subprocess.CalledProcessError:
            log.error("Can't unpack InnoSetup for %s", file)
        except Exception as e:
            log.error(e, exc_info=True)

    return "InnoExtract", metadata


def kixtart_extract(file: str, destination_folder: str, filetype: str, data_dictionary: dict, options: dict, results: dict):
    """
    https://github.com/jhumble/Kixtart-Detokenizer/blob/main/detokenize.py
    """

    if not HAVE_KIXTART:
        return

    with open(file, "rb") as f:
        content = f.read()

    metadata = []

    if content.startswith(b"\x1a\xaf\x06\x00\x00\x10"):
        with tempfile.TemporaryDirectory(prefix="kixtart_") as tempdir:
            kix = Kixtart(file, dump_dir=tempdir)
            kix.decrypt()
            kix.dump()

            metadata.extend(_extracted_files_metadata(tempdir, destination_folder, content=content))

    return "Kixtart", metadata


def UnAutoIt_extract(file: str, destination_folder: str, filetype: str, data_dictionary: dict, options: dict, results: dict):
    if all(block.get("name") != "AutoIT_Compiled" for block in data_dictionary.get("yara", {})):
        return

    if not os.path.exists(unautoit_binary):
        log.warning(
            f"Missed UnAutoIt binary: {unautoit_binary}. You can download a copy from - https://github.com/x0r19x91/UnAutoIt"
        )
        return

    metadata = []

    with tempfile.TemporaryDirectory(prefix="unautoit_") as tempdir:
        try:
            output = subprocess.check_output(
                [unautoit_binary, "extract-all", "--output-dir", tempdir, file], universal_newlines=True
            )
            if output:
                files = [
                    os.path.join(tempdir, extracted_file)
                    for extracted_file in tempdir
                    if os.path.isfile(os.path.join(tempdir, extracted_file))
                ]
                metadata.extend(_extracted_files_metadata(tempdir, destination_folder, files=files))
        except subprocess.CalledProcessError:
            log.error("Can't unpack AutoIT for %s", file)
        except Exception as e:
            log.error(e, exc_info=True)

    return "UnAutoIt", metadata


def UPX_unpack(file: str, destination_folder: str, filetype: str, data_dictionary: dict, options: dict, results: dict):
    # TODO: maybe check yara for UPX?
    # hit["name"] == "UPX":
    if "UPX compressed" not in filetype:
        return

    metadata = []

    with tempfile.TemporaryDirectory(prefix="unupx_") as tempdir:
        try:
            dest_path = f"{os.path.join(tempdir, os.path.basename(file))}_unpacked"
            output = subprocess.check_output(
                [
                    "upx",
                    "-d",
                    file,
                    f"-o{dest_path}",
                ],
                universal_newlines=True,
            )
            if output and "Unpacked 1 file." in output:
                metadata.extend(_extracted_files_metadata(tempdir, destination_folder, files=[dest_path]))
        except subprocess.CalledProcessError:
            log.error("Can't unpack UPX for %s", file)
        except Exception as e:
            log.error(e, exc_info=True)

    return "UnUPX", metadata


# ToDo do not ask for password + test with pass
def SevenZip_unpack(file: str, destination_folder: str, filetype: str, data_dictionary: dict, options: dict, results: dict):
    tool = False

    password = ""
    # Only for real 7zip, breaks others
    password = options.get("password", "infected")
    if any(
        "7-zip Installer data" in string for string in data_dictionary.get("die", {})
    ) or "Zip archive data" in data_dictionary.get("type", ""):
        tool = "7Zip"
        prefix = "7zip_"
        password = options.get("password", "infected")
        password = f"-p{password}"

    elif any(
        "Microsoft Cabinet" in string for string in data_dictionary.get("die", {})
    ) or "Microsoft Cabinet" in data_dictionary.get("type", ""):
        tool = "UnCab"
        prefix = "cab_"
        password = ""

    elif "Nullsoft Installer self-extracting archive" in filetype:
        tool = "UnNSIS"
        prefix = "unnsis_"
        """
        elif (
            any("SFX: WinRAR" in string for string in data_dictionary.get("die", {}))
            or any("RAR Self Extracting archive" in string for string in data_dictionary.get("trid", {}))
            or "RAR self-extracting archive" in data_dictionary.get("type", "")
        ):
            tool = "UnRarSFX"
            prefix = "unrar_"
        """
    else:
        return

    metadata = []
    with tempfile.TemporaryDirectory(prefix=prefix) as tempdir:
        try:
            HAVE_SFLOCK = False
            if HAVE_SFLOCK:
                unpacked = unpack(file.encode(), password=password)
                for child in unpacked.children:
                    with open(os.path.join(tempdir, child.filename.decode()), "wb") as f:
                        f.write(child.contents)

            else:
                output = subprocess.check_output(
                    [
                        "7z",
                        "e",
                        file,
                        password,
                        f"-o{tempdir}",
                        "-y",
                    ],
                    universal_newlines=True,
                )
                print(output)
            files = [
                os.path.join(tempdir, extracted_file)
                for extracted_file in tempdir
                if os.path.isfile(os.path.join(tempdir, extracted_file))
            ]
            metadata.extend(_extracted_files_metadata(tempdir, destination_folder, files=files))
        except subprocess.CalledProcessError:
            logging.error("Can't unpack with 7Zip for %s", file)
        except Exception as e:
            log.error(e, exc_info=True)

    return tool, metadata


# ToDo move to sflock
def RarSFX_extract(file, destination_folder, filetype, data_dictionary, options: dict, results: dict):
    if (
        all("SFX: WinRAR" not in string for string in data_dictionary.get("die", {}))
        and all("RAR Self Extracting archive" not in string for string in data_dictionary.get("trid", {}))
        and "RAR self-extracting archive" not in data_dictionary.get("type", "")
    ):
        return

    if not os.path.exists("/usr/bin/unrar"):
        log.warning(f"Missed UnRar binary: /usr/bin/unrar. sudo apt install unrar")
        return

    metadata = []

    with tempfile.TemporaryDirectory(prefix="unrar_") as tempdir:
        try:
            password = options.get("password", "infected")
            output = subprocess.check_output(
                ["/usr/bin/unrar", "e", "-kb", f"-p{password}", file, tempdir], universal_newlines=True
            )
            if output:
                files = [
                    os.path.join(tempdir, extracted_file)
                    for extracted_file in tempdir
                    if os.path.isfile(os.path.join(tempdir, extracted_file))
                ]
                metadata.extend(_extracted_files_metadata(tempdir, destination_folder, files=files))

        except subprocess.CalledProcessError:
            logging.error("Can't unpack SFX for %s", file)
        except Exception as e:
            logging.error(e, exc_info=True)

    return "UnRarSFX", metadata
