# Copyright (C) 2024 fdiaz@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import time
import webbrowser

from lib.common.abstracts import Package


class ChromiumExt(Package):
    """Chrome analysis package."""

    PATHS = [
        ("LOCALAPPDATA", "Chromium", "chrome.exe"),
    ]
    summary = "Opens the URL in Google Chrome."
    description = """Uses 'chrome.exe --disable-features=RendererCodeIntegrity "<url>"' to open the supplied url."""

    def start(self, url):
        webbrowser.register(
            "chromium", None,
            webbrowser.BackgroundBrowser(self.get_path("chrome.exe")))
        chromium = webbrowser.get("chromium")
        chromium.open("about:blank")
        time.sleep(5)
        return chromium.open(url)
