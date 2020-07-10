# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import logging

from subprocess import call
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

try:
    from weasyprint import HTML

    HAVE_WEASYPRINT = True
except ImportError:
    HAVE_WEASYPRINT = False


class ReportPDF(Report):
    """Stores report in PDF format."""

    # ensure we run after the summary HTML report
    order = 10

    def run(self, results):
        if not os.path.isfile(os.path.join(self.reports_path, "summary-report.html")):
            raise CuckooReportError(
                "Unable to open summary HTML report to convert to PDF: " "Ensure reporthtmlsummary is enabled in reporting.conf"
            )

        if os.path.exists("/usr/bin/xvfb-run") and os.path.exists("/usr/bin/wkhtmltopdf"):
            call(
                [
                    "/usr/bin/xvfb-run",
                    "--auto-servernum",
                    "--server-num",
                    "1",
                    "/usr/bin/wkhtmltopdf",
                    "-q",
                    os.path.join(self.reports_path, "summary-report.html"),
                    os.path.join(self.reports_path, "report.pdf"),
                ]
            )
            return True

        if not HAVE_WEASYPRINT:
            raise CuckooReportError("Failed to generate PDF report: " "Neither wkhtmltopdf nor Weasyprint Python library are installed")

        logger = logging.getLogger("weasyprint")
        logger.handlers = []
        logger.setLevel(logging.ERROR)

        HTML(os.path.join(self.reports_path, "summary-report.html")).write_pdf(os.path.join(self.reports_path, "report.pdf"))

        return True
