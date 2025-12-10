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

        bingraph_path = os.path.join(self.analysis_path, "bingraph")
        if path_exists(bingraph_path):
            if "graphs" not in results:
                results["graphs"] = {}

            bingraph_dict_content = {}
            for file_name in os.listdir(bingraph_path):
                file_path = os.path.join(bingraph_path, file_name)
                sha256 = os.path.basename(file_path).split("-", 1)[0]
                with codecs.open(file_path, "r", encoding="utf-8") as f:
                    bingraph_dict_content[sha256] = f.read()

        if bingraph_dict_content:
                results["graphs"]["bingraph"] = {"enabled": True, "content": bingraph_dict_content}

        debugger_path = os.path.join(self.analysis_path, "debugger")
        debugger = {}
        if path_exists(debugger_path):
            try:
                for log_file in sorted(os.listdir(debugger_path)):
                    if not log_file.endswith(".log"):
                        continue

                    log_path = os.path.join(debugger_path, log_file)
                    if not os.path.isfile(log_path):
                        continue

                    try:
                        pid = log_file.strip(".log")
                        with open(log_path, "r") as f:
                            debugger[pid] = f.read()
                    except (ValueError, TypeError):
                        log.warning("Could not parse PID from debugger log file: %s", log_file)
            except Exception as e:
                log.warning("Could not read debugger logs for HTML report: %s", e)

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

        # Read assets for embedding
        template_path = os.path.join(CUCKOO_ROOT, "data", "html")
        with open(os.path.join(template_path, "css", "bootstrap", "bootstrap.min.css"), encoding="utf-8") as f:
            bootstrap_css = f.read()
        with open(os.path.join(template_path, "css", "fontawesome", "all.min.css"), encoding="utf-8") as f:
            fontawesome_css = f.read()
        with open(os.path.join(template_path, "css", "style.css"), encoding="utf-8") as f:
            style_css = f.read()
        with open(os.path.join(template_path, "js", "bootstrap", "bootstrap.bundle.min.js"), encoding="utf-8") as f:
            bootstrap_bundle_js = f.read()

        try:
            tpl = env.get_template("report.html")
            html = tpl.render(
                {
                    "results": results,
                    "summary_report": False,
                    "graphs": results.get("graphs", {}),
                    "debugger": debugger,
                    "bootstrap_css": bootstrap_css,
                    "fontawesome_css": fontawesome_css,
                    "style_css": style_css,
                    "bootstrap_bundle_js": bootstrap_bundle_js,
                }
            )
            with codecs.open(os.path.join(self.reports_path, "report.html"), "w", encoding="utf-8") as report:
                report.write(html)
        except Exception as e:
            log.exception("Failed to generate summary HTML report: %s", e)

        return True
