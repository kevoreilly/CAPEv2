# Copyright (C) 2024 fdiaz@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import base64
import logging
import os
import time
import webbrowser

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class Firefox_Ext(Package):
    """Firefox analysis package (with extension)."""

    PATHS = [
        ("ProgramFiles", "Mozilla Firefox", "firefox.exe"),
    ]
    summary = "Opens the URL in firefox."
    description = """Spawns firefox.exe and opens the supplied URL.

    Allows setting a custom user-agent string via the 'user_agent' option.
    The value should be provided base64-encoded.
    """

    # set your current firefox profile path (about:profiles)
    profile_path = None

    def start(self, url):
        user_agent = self.options.get("user_agent")
        log.debug("User agent option value: %s", user_agent)
        try:
            base64.b64decode(user_agent)
        except Exception:
            log.error("Invalid base64 encoded user agent provided.")
            user_agent = None
        if user_agent and self.profile_path:
            config = os.path.join(self.profile_path, 'prefs.js')
            ua_decoded = base64.b64decode(user_agent).decode('utf-8')
            ua_config = f'user_pref("general.useragent.override", "{ua_decoded}");\n'
            try:
                os.makedirs(os.path.dirname(config), exist_ok=True)
                with open(config, 'a') as file:
                    file.write(ua_config)
                log.info("Successfully appended user agent to prefs.js: %s", ua_decoded)
            except Exception as e:
                log.error("Failed to write user agent to prefs.js: %s", e)
        firefox_path = self.get_path("firefox.exe")
        webbrowser.register("firefox", None, webbrowser.BackgroundBrowser(firefox_path))
        firefox = webbrowser.get("firefox")
        firefox.open("about:blank")
        time.sleep(7)  # Rough estimate, change based on your setup times.
        return firefox.open(url)
