# Copyright (C) 2023 Sean Whalen
# This file is part of CAPE Sandbox -https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class Chromium(Package):
    """Chromium analysis package."""

    PATHS = [
        ("LOCALAPPDATA", "Chromium", "Application", "chrome.exe"),
        ("ProgramFiles", "Google", "Chrome", "Application", "chrome.exe"),
    ]
    summary = "Open the URL in Chromium."
    description = """Use 'chrome.exe --disable-features=RendererCodeIntegrity "<url>"' to open the supplied url."""

    def start(self, url):
        chrome = self.get_path("chrome.exe")
        args = [
            "--disable-features=RendererCodeIntegrity",
        ]
        args.append('"{}"'.format(url))
        args = " ".join(args)
        return self.execute(chrome, args, url)
