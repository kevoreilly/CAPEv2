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
from jinja2 import Environment, FileSystemLoader

log = logging.getLogger(__name__)

def getkey(d, key):
    """Jinja2 filter to get a key from a dictionary."""
    return d.get(key, "")

def str2list(value):
    """Jinja2 filter to convert a string to a list."""
    if isinstance(value, str):
        return [value]
    return value

def dict2list(value):
    """Jinja2 filter to convert a dictionary to a list if it's a dictionary."""
    if isinstance(value, dict):
        return [value]
    return value

def parentfixup(value):
    """Jinja2 filter for parent fixup logic."""
    if "file_size" in value:
        value["size"] = value["file_size"]
    if "name" not in value:
        value["name"] = value["sha256"]
    return value

def divisibleby(value, divisor):
    """Jinja2 filter to check if a value is divisible by a divisor."""
    return value % divisor == 0

def replace_filter(value, old, new):
    """Jinja2 filter to replace occurrences of a substring."""
    return value.replace(old, new)

def slice_filter(value, slice_str):
    """Jinja2 filter for slicing strings."""
    parts = slice_str.split(':')
    start = int(parts[0]) if parts[0] else 0
    end = int(parts[1]) if parts[1] else len(value)
    return value[start:end]

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
            for shot_name in sorted(os.listdir(shots_path)):
                if not shot_name.endswith((".jpg", ".png")):
                    continue
                shot_path = os.path.join(shots_path, shot_name)
                if os.path.getsize(shot_path) == 0:
                    continue
                
                shot = {
                    "id": os.path.splitext(shot_name)[0],
                    "data": base64.b64encode(open(shot_path, "rb").read()).decode(),
                }
                shots.append(shot)
            results["shots"] = shots
        else:
            results["shots"] = []

        # Set up Jinja2 environment
        template_dir = os.path.join(CUCKOO_ROOT, "data", "html") # Pointing to data/html
        env = Environment(loader=FileSystemLoader(template_dir))

        # Register Django-like filters and functions
        env.filters['getkey'] = getkey
        env.filters['str2list'] = str2list
        env.filters['dict2list'] = dict2list
        env.filters['parentfixup'] = parentfixup
        env.filters['divisibleby'] = divisibleby
        env.filters['replace'] = replace_filter
        env.filters['slice'] = slice_filter

        # Expose config options to the template context
        template_context = {
            "results": results,
            "summary_report": False,
            "config": self.options, # Self.options contains configurations
            "STATIC_URL": "/static/", # Default static URL
            "WEB_AUTHENTICATION": False,
            "WEB_OAUTH": False,
            "ZIPPED_DOWNLOAD_ALL": False,
            "ANON_VIEW": True,
            "COMMENTS": False,
            "ADMIN": False,
            "URL_ANALYSIS": False,
            "DLNEXEC": False,
            "MOLOCH_ENABLED": False,
            "TEMP_PATH": "/tmp",
            "DEBUG": False,
            "NOCAPTCHA": True,
            "REMOTE_SESSION": False,
            "ALLOW_DL_REPORTS_TO_ALL": True,
            "OPT_ZER0M0N": False,
            "SITE_ID": 1,
            "CRISPY_TEMPLATE_PACK": "bootstrap4",
            "TWOFA": False,
        }
        
        try:
            template = env.get_template("report.html") # Use report.html from data/html
            html = template.render(template_context)
            with codecs.open(os.path.join(self.reports_path, "report.html"), "w", encoding="utf-8") as report:
                report.write(html)
        except Exception as e:
            raise CuckooReportError(f"Failed to generate HTML report: {e}")

        return True
