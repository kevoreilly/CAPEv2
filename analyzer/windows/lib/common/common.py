from __future__ import absolute_import
import logging
import os

log = logging.getLogger(__name__)


def check_file_extension(path: str, ext: str) -> str:
    # Check file extension.
    # If the file doesn't have the proper extension force it and rename it.
    if os.path.splitext(path)[-1].lower() != ext:
        os.rename(path, f"{path}{ext}")
        log.info(f"Submitted file is missing extension, adding {ext}")
        return path + ext
    return path
