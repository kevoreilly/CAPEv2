# Copyright (C) 2024 fdiaz@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import time
import webbrowser

from lib.common.abstracts import Package


class TorBrowserExt(Package):
    """TOR analysis package (with extension)."""

    PATHS = [
        ("LOCALAPPDATA", "Tor Browser", "Browser", "firefox.exe"),
    ]
    summary = "Opens the URL in firefox."
    description = """Spawns TOR's firefox.exe and opens the supplied URL."""

    def start(self, url):
        webbrowser.register("firefox", None, webbrowser.BackgroundBrowser(self.get_path("firefox.exe")))
        firefox = webbrowser.get("firefox")
        time.sleep(15)  # Rough estimate, change based on your setup times.
        firefox.open(url)
        time.sleep(15)  # Prevent analysis from finishing too early.
        return
