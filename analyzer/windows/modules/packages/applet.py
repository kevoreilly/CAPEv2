# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import tempfile
from pathlib import Path

from lib.common.abstracts import CuckooPackageError, Package
from lib.common.constants import OPT_CLASS


class Applet(Package):
    """Java Applet analysis package."""

    PATHS = [
        ("ProgramFiles", "Mozilla Firefox", "firefox.exe"),
        ("ProgramFiles", "Internet Explorer", "iexplore.exe"),
    ]
    summary = "Open a java applet using firefox (or iexplore)."
    description = f"""Create an HTML wrapper around the applet file.
    The '{OPT_CLASS}' option is required; the applet will execute the
    named class.  Opens the HTML file with firefox, or iexplore if firefox
    is not available."""
    option_names = (OPT_CLASS,)

    def make_html(self, path, class_name):
        html = f"""
        <html>
            <body>
                <applet archive="{path}" code="{class_name}" width="1" height="1">
                </applet>
            </body>
        </html>
        """

        _, file_path = tempfile.mkstemp(suffix=".html")
        _ = Path(file_path).write_text(html)

        return file_path

    def start(self, path):
        try:
            browser = self.get_path("firefox.exe")
        except CuckooPackageError:
            browser = self.get_path("iexplore.exe")

        class_name = self.options.get(OPT_CLASS)
        html_path = self.make_html(path, class_name)
        return self.execute(browser, f'"{html_path}"', html_path)
