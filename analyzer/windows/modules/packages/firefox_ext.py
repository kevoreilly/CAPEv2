# Copyright (C) 2024 fdiaz@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import time
import webbrowser

from lib.common.abstracts import Package


class Firefox_Ext(Package):
    """Firefox analysis package (with extension)."""

    PATHS = [
        ("ProgramFiles", "Mozilla Firefox", "firefox.exe"),
    ]
    summary = "Opens the URL in firefox."
    description = """Spawns firefox.exe and opens the supplied URL."""

    def start(self, url):
        webbrowser.register("firefox", None, webbrowser.BackgroundBrowser(self.get_path("firefox.exe")))
        firefox = webbrowser.get("firefox")
        firefox.open("about:blank")
        time.sleep(7)  # Rough estimate, change based on your setup times.
        return firefox.open(url)
