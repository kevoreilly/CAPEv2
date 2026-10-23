# Copyright (C) 2024 fdiaz@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import time
import webbrowser

from lib.common.abstracts import Package


class ChromiumExt(Package):
    """Chromium extension analysis package."""

    PATHS = [
        ("LOCALAPPDATA", "Chromium", "Application", "chrome.exe"),
        ("ProgramFiles", "Chromium", "Application", "chrome.exe"),
    ]
    summary = "Opens the URL in Chromium with loaded extension."
    description = """Runs Chromium preloaded with a custom extensios."""

    def start(self, url):
        webbrowser.register("chromium", None, webbrowser.BackgroundBrowser(self.get_path("chrome.exe")))
        chromium = webbrowser.get("chromium")
        chromium.open("about:blank")
        time.sleep(10)
        chromium.open(url)
        # Chromium is not injected, the extension monitors it. Return no PIDs so the analysis runs until
        # the timeout (webbrowser.open() returns a bool, which the analyzer would track as PID 1).
        return None
