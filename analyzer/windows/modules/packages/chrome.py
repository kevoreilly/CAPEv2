# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.common.abstracts import Package


class Chrome(Package):
    """Chrome analysis package."""

    PATHS = [
        ("ProgramFiles", "Google", "Chrome", "Application", "chrome.exe"),
        ("LOCALAPPDATA", "Chromium", "Application", "chrome.exe"),
    ]
    summary = "Open the URL in Google Chrome."
    description = """Use 'chrome.exe --disable-features=RendererCodeIntegrity "<url>"' to open the supplied url."""

    def start(self, url):
        chrome = self.get_path("chrome.exe")
        args = [
            "--disable-features=RendererCodeIntegrity",
        ]
        args.append('"{}"'.format(url))
        args = " ".join(args)
        return self.execute(chrome, args, url)
