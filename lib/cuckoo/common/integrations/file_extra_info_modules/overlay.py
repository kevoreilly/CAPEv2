import logging
import os

from lib.cuckoo.common.integrations.file_extra_info_modules import (
    ExtractorReturnType,
    collect_extracted_filenames,
    extractor_ctx,
    time_tracker,
)
from lib.cuckoo.common.path_utils import path_write_file

# from base64 import b64encode


log = logging.getLogger(__name__)


@time_tracker
def extract_details(file, *, data_dictionary, **_) -> ExtractorReturnType:
    if not data_dictionary.get("pe", {}).get("overlay"):
        return {}

    data = ""
    overlay_size = int(data_dictionary["pe"]["overlay"]["size"], 16)
    # Extract out the overlay data
    try:
        with open(file, "rb") as f:
            f.seek(-overlay_size, os.SEEK_END)
            data = f.read()
        # data_dictionary["pe"]["overlay"]["data"] = b64encode(data[: min(overlay_size, 4096)])
    except Exception as e:
        log.error(e)

    with extractor_ctx(file, "overlay", prefix="overlay") as ctx:
        if data:
            tempdir = ctx["tempdir"]
            # You might need to change this 2 lines. See other examples in `file_extra_info.py`
            _ = path_write_file(os.path.join(tempdir, "overlay"), data)
            ctx["extracted_files"] = collect_extracted_filenames(tempdir)
    return ctx
