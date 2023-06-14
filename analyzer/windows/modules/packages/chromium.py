# Copyright (C) 2023 Sean Whalen
# This file is part of CAPE Sandbox -https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class Chromium(Package):
    """Chromium analysis package."""

    PATHS = [
        ("LOCALAPPDATA", "Chromium", "Application", "chrome.exe"),
    ]

    def start(self, url):
        chrome = self.get_path("chrome.exe")
        # pass the URL instead of a filename in this case
        return self.execute(chrome, f'"{url}"', url)
