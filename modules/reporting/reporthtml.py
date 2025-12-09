# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import codecs
import logging
import os

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists
from web.analysis.templatetags.analysis_tags import flare_capa_attck, flare_capa_capabilities, flare_capa_mbc, malware_config
from web.analysis.templatetags.key_tags import dict2list, getkey, parentfixup, str2list
from web.analysis.templatetags.pdf_tags import datefmt

try:
    from jinja2.environment import Environment
    from jinja2.loaders import FileSystemLoader

    HAVE_JINJA2 = True
except ImportError:
    HAVE_JINJA2 = False

log = logging.getLogger(__name__)


class ReportHTML(Report):
    """Stores report in HTML format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        if not HAVE_JINJA2:
            raise CuckooReportError("Failed to generate HTML report: Jinja2 Python library is not installed")

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

        env = Environment(autoescape=True)
        env.filters.update(
            {
                "getkey": getkey,
                "str2list": str2list,
                "dict2list": dict2list,
                "parentfixup": parentfixup,
                "malware_config": malware_config,
                "flare_capa_capability": flare_capa_capabilities,
                "flare_capa_attck": flare_capa_attck,
                "flare_capa_mbc": flare_capa_mbc,
                "datefmt": datefmt,
            }
        )
        env.loader = FileSystemLoader(os.path.join(CUCKOO_ROOT, "data", "html"))
        results["local_conf"] = self.options

        try:
            tpl = env.get_template("report.html")
            html = tpl.render({"results": results, "summary_report": False})
            with codecs.open(os.path.join(self.reports_path, "report.html"), "w", encoding="utf-8") as report:
                report.write(html)
        except Exception as e:
            log.exception("Failed to generate summary HTML report: %s", e)

        return True
