import logging

from lib.cuckoo.common.integrations.file_extra_info_modules import (
    ExtractorReturnType,
    collect_extracted_filenames,
    extractor_ctx,
    time_tracker,
)
from lib.cuckoo.common.integrations.pyinstxtractor import PyInstArchive

log = logging.getLogger(__name__)


@time_tracker
def extract_details(file, *, data_dictionary, **_) -> ExtractorReturnType:
    if all("PyInstaller" not in string for string in data_dictionary.get("die", [])):
        return {}

    with extractor_ctx(file, "PyInstaller", prefix="PyInstaller") as ctx:
        tempdir = ctx["tempdir"]
        arch = PyInstArchive({"file": file, "destination_folder": tempdir, "entry_points": True})
        if arch.open() and arch.checkFile() and arch.getCArchiveInfo():
            arch.parseTOC()
            arch.extractFiles()
            arch.close()
            log.debug(
                "[+] Successfully extracted pyinstaller archive: %s\nYou can now use a python decompiler on the pyc files within the extracted directory",
            )
        arch.close()

        ctx["extracted_files"] = collect_extracted_filenames(tempdir)
    return ctx
