import hashlib
import logging
import os
import shutil
import subprocess
import tempfile

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.integrations.parse_dotnet import DotNETExecutable
from lib.cuckoo.common.integrations.parse_java import Java
from lib.cuckoo.common.integrations.parse_lnk import LnkShortcut
from lib.cuckoo.common.integrations.parse_office import HAVE_OLETOOLS, Office

# ToDo duplicates logging here
from lib.cuckoo.common.integrations.parse_pdf import PDF
from lib.cuckoo.common.integrations.parse_pe import HAVE_PEFILE, PortableExecutable
from lib.cuckoo.common.integrations.parse_wsf import EncodedScriptFile, WindowsScriptFile
from lib.cuckoo.common.objects import File

# from lib.cuckoo.common.integrations.parse_elf import ELF
from lib.cuckoo.common.utils import get_options, is_text_file

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
decomp_jar = processing_conf.static.procyon_path


def static_file_info(data_dictionary: dict, file_path: str, task_id: str, package: str, options: str, destination_folder: str):

    if (
        not HAVE_OLETOOLS
        and "Zip archive data, at least v2.0" in data_dictionary["type"]
        and package in ("doc", "ppt", "xls", "pub")
    ):
        log.info("Missed dependencies: pip3 install oletools")

    if HAVE_PEFILE and ("PE32" in data_dictionary["type"] or "MS-DOS executable" in data_dictionary["type"]):
        data_dictionary["pe"] = PortableExecutable(file_path).run()
        if "Mono" in data_dictionary["type"]:
            data_dictionary["dotnet"] = DotNETExecutable(file_path).run()
    elif HAVE_OLETOOLS and package in ("doc", "ppt", "xls", "pub"):
        # options is dict where we need to get pass get_options
        data_dictionary["office"] = Office(file_path, task_id, data_dictionary["sha256"], get_options(options)).run()
    elif "PDF" in data_dictionary["type"] or file_path.endswith(".pdf"):
        data_dictionary["pdf"] = PDF(file_path).run()
    elif package == "wsf" or data_dictionary["type"] == "XML document text" or file_path.endswith(".wsf") or package == "hta":
        data_dictionary["wsf"] = WindowsScriptFile(file_path).run()
    # elif package == "js" or package == "vbs":
    #    static = EncodedScriptFile(file_path).run()
    elif package == "lnk":
        data_dictionary["lnk"] = LnkShortcut(file_path).run()
    elif "Java Jar" in data_dictionary["type"] or file_path.endswith(".jar"):
        if decomp_jar and not os.path.exists(decomp_jar):
            log.error("procyon_path specified in processing.conf but the file does not exist")
        data_dictionary["java"] = Java(file_path, decomp_jar).run()

    # It's possible to fool libmagic into thinking our 2007+ file is a zip.
    # So until we have static analysis for zip files, we can use oleid to fail us out silently,
    # yeilding no static analysis results for actual zip files.
    # elif file_path.endswith(".elf") or "ELF" in thetype:
    #    data_dictionary["elf"] = ELF(file_path).run()
    #    data_dictionary["keys"] = f.get_keys()
    # elif HAVE_OLETOOLS and package in ("hwp", "hwp"):
    #    data_dictionary["hwp"] = HwpDocument(file_path).run()

    with open(file_path, "rb") as f:
        is_text_file(data_dictionary, file_path, 8192, f.read())

    generic_file_extractors(file_path, destination_folder, data_dictionary["type"], data_dictionary)


def _extracted_files_metadata(folder, destination_folder, data_dictionary, content=False, files=False):
    """
    args:
        folder - where files extracted
        destination_folder - where to move extracted files
        files - file names
    """
    metadata = []
    if not files:
        files = os.listdir(folder)
    for file in files:
        full_path = os.path.join(folder, file)
        file_details = File(full_path).get_all()
        if file_details:
            file_details = file_details[0]

        metadata.append(file_details)
        dest_path = os.path.join(destination_folder, file_details["sha256"])
        if not os.path.exists(dest_path):
            shutil.move(full_path, dest_path)

    return metadata


def generic_file_extractors(file, destination_folder, filetype, data_dictionary):
    """
    file - path to binary
    destination_folder - where to move extracted files
    filetype - magic string
    data_dictionary - where to add data

    Run all extra extractors/unpackers/extra scripts here, each extractor should check file header/type/identification:
        msi_extract
        kixtart_extract
    """

    for funcname in (msi_extract, kixtart_extract, vbe_extract, batch_extract):
        try:
            funcname(file, destination_folder, filetype, data_dictionary)
        except Exception as e:
            log.error(e, exc_info=True)


def _generic_post_extraction_process(file, decoded, destination_folder, data_dictionary, tool_name):
    with tempfile.TemporaryDirectory(prefix=tool_name) as tempdir:
        decoded_file_path = os.path.join(tempdir, f"{os.path.basename(file)}_decoded")
        with open(decoded_file_path, "wb") as f:
            f.write(decoded)

    metadata = []
    metadata += _extracted_files_metadata(tempdir, destination_folder, data_dictionary, files=[decoded_file_path])
    if metadata:
        for meta in metadata:
            is_text_file(meta, destination_folder, 8192)

        data_dictionary.setdefault("decoded_files", metadata)
        data_dictionary.setdefault("decoded_files_tool", tool_name)


def batch_extract(file, destination_folder, filetype, data_dictionary):
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

    _generic_post_extraction_process(file, decoded, destination_folder, data_dictionary, "Batch")


def vbe_extract(file, destination_folder, filetype, data_dictionary):

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

    _generic_post_extraction_process(file, decoded, destination_folder, data_dictionary, "Vbe")


def msi_extract(file, destination_folder, filetype, data_dictionary, msiextract="/usr/bin/msiextract"):  # dropped_path
    """Work on MSI Installers"""

    if "MSI Installer" not in filetype:
        return

    if not os.path.exists(msiextract):
        logging.error("Missed dependency: sudo apt install msitools")
        return

    metadata = []

    with tempfile.TemporaryDirectory(prefix="msidump_") as tempdir:
        try:
            files = subprocess.check_output([msiextract, file, "--directory", tempdir], universal_newlines=True)
            if files:
                files = list(filter(None, files.split("\n")))
                metadata += _extracted_files_metadata(tempdir, destination_folder, data_dictionary, files=files)

        except Exception as e:
            logging.error(e, exc_info=True)

    if metadata:
        for meta in metadata:
            is_text_file(meta, destination_folder, 8192)

        data_dictionary.setdefault("extracted_files", metadata)
        data_dictionary.setdefault("extracted_files_tool", "MsiExtract")


def kixtart_extract(file, destination_folder, filetype, data_dictionary):
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

            metadata += _extracted_files_metadata(tempdir, destination_folder, data_dictionary, content=content)

    if metadata:
        for meta in metadata:
            is_text_file(meta, destination_folder, 8192)

        data_dictionary.setdefault("extracted_files", metadata)
        data_dictionary.setdefault("extracted_files_tool", "Kixtart")
