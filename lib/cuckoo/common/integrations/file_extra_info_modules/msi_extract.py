import logging
import os
import subprocess

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.integrations.file_extra_info_modules import (
    ExtractorReturnType,
    collect_extracted_filenames,
    extractor_ctx,
    time_tracker,
)
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_is_file
from lib.cuckoo.common.integrations.utils import run_tool

log = logging.getLogger(__name__)
integration_conf = Config("integrations")

sevenzip_binary = os.path.join(CUCKOO_ROOT, "data/7zz")
if integration_conf.SevenZip_unpack.binary:
    tmp_sevenzip_binary = os.path.join(CUCKOO_ROOT, integration_conf.SevenZip_unpack.binary)
    if path_exists(tmp_sevenzip_binary):
        sevenzip_binary = tmp_sevenzip_binary
# fallback
if not path_exists(sevenzip_binary):
    sevenzip_binary = "/usr/bin/7z"

@time_tracker
def extract_details(file: str, *, filetype: str, **kwargs) -> ExtractorReturnType:
    """Work on MSI Installers"""

    if "MSI Installer" not in filetype:
        return

    # ToDo replace MsiExtract with pymsi
    extracted_files = []
    # sudo apt install msitools
    with extractor_ctx(file, "MsiExtract", prefix="msidump_") as ctx:
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
                [sevenzip_binary, "e", f"-o{tempdir}", "-y", file],
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
