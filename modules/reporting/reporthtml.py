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

# Add the web directory to the Python path so that the 'analysis' app can be found.
sys.path.append(os.path.join(CUCKOO_ROOT, "web"))

from django.conf import settings
from django.template import loader

log = logging.getLogger(__name__)

# Configure Django for standalone script usage.
# This is required to discover and use template tags from the 'analysis' app.
if not settings.configured:
    settings.configure(
        INSTALLED_APPS=[
            "analysis",
            "django.contrib.contenttypes",
            "django.contrib.auth",
            "django.contrib.sessions",
            "django.contrib.messages",
            "django.contrib.staticfiles",
            "django.contrib.sites",
            "django_settings_export",
            "django.contrib.admin",
            "allauth.account",
        ],
        # The {% url %} template tag requires ROOT_URLCONF to be set.
        ROOT_URLCONF="web.urls",
        # CUCKOO_PATH is needed by analysis/views.py for sys.path.append.
        CUCKOO_PATH=CUCKOO_ROOT,
        # The following settings are accessed by templates.
        WEB_AUTHENTICATION=False,
        WEB_OAUTH=False,
        ZIPPED_DOWNLOAD_ALL=False,
        STATIC_URL="/static/",
        ANON_VIEW=True,
        COMMENTS=False,
        ADMIN=False,
        URL_ANALYSIS=False,
        DLNEXEC=False,
        MOLOCH_ENABLED=False,
        TEMP_PATH="/tmp",
        DEBUG=False,
        NOCAPTCHA=True,
        REMOTE_SESSION=False,
        ALLOW_DL_REPORTS_TO_ALL=True,
        OPT_ZER0M0N=False,
        SITE_ID=1,
        CRISPY_TEMPLATE_PACK="bootstrap4",
        TWOFA=False,
        TEMPLATES=[
            {
                "BACKEND": "django.template.backends.django.DjangoTemplates",
                "DIRS": [os.path.join(CUCKOO_ROOT, "web", "templates")],
                # APP_DIRS must be True to load template tags from INSTALLED_APPS.
                "APP_DIRS": True,
                "OPTIONS": {
                    "context_processors": [
                        "django.template.context_processors.request",
                        "django_settings_export.settings_export",
                    ],
                },
            },
        ]
    )
    import django
    try:
        # Populate the app registry.
        django.setup()
    except RuntimeError as e:
        # This may be called multiple times in the same process.
        log.warning("Ignoring Django setup error in reporthtml: %s", e)



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
