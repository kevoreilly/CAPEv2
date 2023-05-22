# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import base64
import codecs
import os
from contextlib import suppress
from io import BytesIO

import PIL
from PIL import Image

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_exists
from web.analysis.templatetags.analysis_tags import flare_capa_attck, flare_capa_capabilities, flare_capa_mbc, malware_config
from web.analysis.templatetags.key_tags import dict2list, getkey, parentfixup, str2list
from web.analysis.templatetags.pdf_tags import datefmt

try:
    from jinja2 import TemplateAssertionError, TemplateNotFound, TemplateSyntaxError, UndefinedError
    from jinja2.environment import Environment
    from jinja2.loaders import FileSystemLoader

    HAVE_JINJA2 = True
except ImportError:
    HAVE_JINJA2 = False


class ReportHTMLSummary(Report):
    """Stores summary report in HTML format."""

    def run(self, results):
        """Writes report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        if not HAVE_JINJA2:
            raise CuckooReportError("Failed to generate summary HTML report: Jinja2 Python library is not installed")

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

                with BytesIO() as output:
                    # resize the image to thumbnail size, as weasyprint can't handle resizing
                    with suppress(Exception):
                        img = Image.open(shot_path)
                        img = img.resize((150, 100), PIL.Image.ANTIALIAS)
                        img.save(output, format="JPEG")

                    shot = {}
                    shot["id"] = os.path.splitext(File(shot_path).get_name())[0]
                    shot["data"] = base64.b64encode(output.getvalue()).decode()
                    shots.append(shot)

                counter += 1

            shots.sort(key=lambda shot: shot["id"])
            results["shots"] = shots
        else:
            results["shots"] = []

        env = Environment(autoescape=True)
        env.globals["malware_config"] = malware_config
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
        try:
            tpl = env.get_template("report.html")
            html = tpl.render({"results": results, "summary_report": True})
        except UndefinedError as e:
            raise CuckooReportError(f"Failed to generate summary HTML report: {e}")
        except TemplateNotFound as e:
            raise CuckooReportError(f"Failed to generate summary HTML report: {e} on {e.name}")
        except (TemplateSyntaxError, TemplateAssertionError) as e:
            raise CuckooReportError(f"Failed to generate summary HTML report: {e} on {e.name}, line {e.lineno}")
        try:
            with codecs.open(os.path.join(self.reports_path, "summary-report.html"), "w", encoding="utf-8") as report:
                report.write(html)
        except (TypeError, IOError) as e:
            raise CuckooReportError(f"Failed to write summary HTML report: {e}")

        return True
