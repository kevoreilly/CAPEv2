# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import codecs
import logging
import os
import sys

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists

from django.conf import settings
from django.template import loader

# Configure Django settings lightly for template rendering, avoiding full app setup.
if not settings.configured:
    settings.configure(
        TEMPLATES=[
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "DIRS": [os.path.join(CUCKOO_ROOT, "web", "templates")],
                "OPTIONS": {
                    "libraries": {
                        "key_tags": "analysis.templatetags.key_tags",
                        "analysis_tags": "analysis.templatetags.analysis_tags",
                    }
                },
            },
        ]
    )

log = logging.getLogger(__name__)


class ReportHTML(Report):
    """Stores report in HTML format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """

        shots_path = os.path.join(self.analysis_path, "shots")
        if path_exists(shots_path) and self.options.screenshots:
            shots = []
            counter = 1
            for shot_name in os.listdir(shots_path):
                if not shot_name.endswith((".jpg", ".png")):
                    continue

                shot_path = os.path.join(shots_path, shot_name)

                if os.path.getsize(shot_path) == 0:
                    continue

                shot = {}
                shot["id"] = os.path.splitext(File(shot_path).get_name())[0]
                shot["data"] = base64.b64encode(open(shot_path, "rb").read()).decode()
                shots.append(shot)

                counter += 1

            shots.sort(key=lambda shot: shot["id"])
            results["shots"] = shots
        else:
            results["shots"] = []

        results["STATIC_URL"] = settings.STATIC_URL
        results["local_conf"] = self.options

        try:
            template = loader.get_template("report_standalone.html")
            html = template.render({"results": results, "summary_report": False, "config": self.options})
            with codecs.open(os.path.join(self.reports_path, "report.html"), "w", encoding="utf-8") as report:
                report.write(html)
        except Exception as e:
            log.exception("Failed to generate summary HTML report: %s", e)

        return True
