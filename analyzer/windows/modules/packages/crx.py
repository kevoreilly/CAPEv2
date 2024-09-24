# Copyright (C) 2024 davidsb@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.common.abstracts import Package
from lib.common.exceptions import CuckooPackageError
from lib.common.zip_utils import extract_zip, get_infos, upload_extracted_files

log = logging.getLogger(__name__)


class CRX(Package):
    """CRX extensions analysis package."""

    PATHS = [
        ("ProgramFiles", "Google", "Chrome", "Application", "chrome.exe"),
        ("LOCALAPPDATA", "Chromium", "Application", "chrome.exe"),
    ]
    summary = "Load the crx sample in Google Chrome as extension."
    description = "Uses 'chrome.exe --load-extension=<extracted_path> \
                to load the supplied sample. Chrome should have developer \
                mode option enabled."

    def start(self, path):
        extracted_path = os.path.join(os.environ["TEMP"], "sample")
        file_names = []
        blank_url = "http://about:blank"  # prevent loading list of files in injected directory
        try:
            zipinfos = get_infos(path)
            extract_zip(zip_path=path, extract_path=extracted_path, recursion_depth=0)
            for f in zipinfos:
                file_names.append(f.filename)
        except CuckooPackageError as e:
            log.warning(e)
            raise

        if not len(file_names):
            raise CuckooPackageError("Empty CRX archive")

        upload_extracted_files(extracted_path, file_names)

        chrome = self.get_path("chrome.exe")
        args = [
            f"--load-extension={extracted_path}",
        ]
        args.append('"{}"'.format(blank_url))
        args = " ".join(args)
        return self.execute(chrome, args, path)
