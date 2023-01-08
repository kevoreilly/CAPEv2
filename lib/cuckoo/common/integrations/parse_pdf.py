# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
from pathlib import Path
from typing import Any, Dict

from lib.cuckoo.common.integrations.peepdf import peepdf_parse

try:
    HAVE_PDF = True
    from lib.cuckoo.common.integrations.pdftools.pdfid import PDFiD, PDFiD2JSON
except ImportError:
    HAVE_PDF = False


log = logging.getLogger(__name__)


class PDF:
    """PDF Analysis."""

    def __init__(self, file_path: str):
        self.file_path = file_path

    def _parse(self, filepath: str) -> Dict[str, Any]:
        """Parses the PDF for static information.
        @param filepath: Path to file to be analyzed.
        @return: results dict or None.
        """
        if not HAVE_PDF:
            return {}

        # Load the PDF with PDFiD and convert it to JSON for processing
        pdf_data = PDFiD(filepath, False, True)
        try:
            pdf_json = PDFiD2JSON(pdf_data, True)
            pdfid_data = json.loads(pdf_json)[0]
        except IndexError as e:
            log.error("parse_pdf: %s", str(e))
            return {}

        pdfresult = {
            "Info": {
                "PDF Header": pdfid_data["pdfid"]["header"],
                "Total Entropy": pdfid_data["pdfid"]["totalEntropy"],
                "Entropy In Streams": pdfid_data["pdfid"]["streamEntropy"],
                "Entropy Out Streams": pdfid_data["pdfid"]["nonStreamEntropy"],
                "Count %% EOF": pdfid_data["pdfid"]["countEof"],
                "Data After EOF": pdfid_data["pdfid"]["countChatAfterLastEof"],
            },
            # Note, PDFiD doesn't interpret some dates properly, specifically it doesn't
            # seem to be able to properly represent time zones that involve fractions of
            # an hour
            "Dates": pdfid_data["pdfid"]["dates"]["date"],
            # Get keywords, counts and format.
            "Keywords": {str(keyword["name"]): keyword["count"] for keyword in pdfid_data["pdfid"]["keywords"]["keyword"]},
        }
        pdfresult = peepdf_parse(self.file_path, pdfresult)

        return pdfresult

    def run(self) -> Dict[str, Any]:
        """Run analysis.
        @return: analysis results dict or None.
        """
        if not Path(self.file_path).exists():
            return None
        log.debug("Starting to load PDF")
        return self._parse(self.file_path)
