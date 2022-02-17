import hashlib
import logging
import os
import shutil
import subprocess
import tempfile

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import is_text_file

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
