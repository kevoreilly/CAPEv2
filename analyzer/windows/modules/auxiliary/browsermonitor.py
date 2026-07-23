# Copyright (C) 2024 fdiaz@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import hashlib
import hmac
import json
import logging
import os
import subprocess
import tempfile
import time
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)


class Browsermonitor(Auxiliary, Thread):
    """Monitors Browser Extension request logs."""

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.do_run = False
        self.enabled = config.browsermonitor
        self.startupinfo = subprocess.STARTUPINFO()
        self.startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        self.browser_logfile = ""

    def _verify_signature(self, filepath):
        """Verify the HMAC signature the agent injected over the log payload.

        Returns True when auth is disabled (no token) so unsigned logs are
        still collected in non-secure setups.
        """
        expected_token = getattr(self.config, "token", "")
        if not expected_token:
            return True
        try:
            with open(filepath, "r") as f:
                data = json.load(f)
            signature = data.pop("signature", "")
            if not signature:
                return False
            canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
            expected = hmac.new(expected_token.encode(), canonical, hashlib.sha256).hexdigest()
            return hmac.compare_digest(signature, expected)
        except Exception as exc:
            log.debug("Failed to verify browser extension log signature %s: %s", filepath, exc)
        return False

    def _find_browser_extension(self):
        temp_dir = tempfile.gettempdir()
        while not self.browser_logfile and self.do_run:
            temp_dir_list = os.listdir(temp_dir)
            for directory in temp_dir_list:
                # TOR Browser saves directly to %temp%
                if directory.startswith("bext_") and directory.endswith(".json"):
                    filepath = os.path.join(temp_dir, directory)
                    if self._verify_signature(filepath):
                        log.debug("Found extension logs: %s", filepath)
                        self.browser_logfile = filepath
                        break
                    else:
                        log.warning("Discarding browser extension log with invalid signature: %s", filepath)
                        try:
                            os.remove(filepath)
                        except Exception as exc:
                            log.debug("Failed to remove unverified browser log %s: %s", filepath, exc)
                tmp_directory_path = os.path.join(temp_dir, directory)
                if not os.path.isdir(tmp_directory_path):
                    continue
                if not directory.startswith("tmp"):
                    continue
                tmp_dir_files = os.listdir(tmp_directory_path)
                for file in tmp_dir_files:
                    if file.startswith("bext_") and file.endswith(".json"):
                        filepath = os.path.join(temp_dir, directory, file)
                        if self._verify_signature(filepath):
                            self.browser_logfile = filepath
                            log.debug("Found extension logs: %s", filepath)
                            break
                        else:
                            log.warning("Discarding browser extension log with invalid signature: %s", filepath)
                            try:
                                os.remove(filepath)
                            except Exception as exc:
                                log.debug("Failed to remove unverified browser log %s: %s", filepath, exc)
            time.sleep(1)

    def _collect_browser_logs(self):
        upload_to_host(self.browser_logfile, "browser/requests.log")

    def run(self):
        self.do_run = True
        if self.enabled:
            self._find_browser_extension()

    def stop(self):
        if self.enabled:
            self.do_run = False
            if self.browser_logfile:
                self._collect_browser_logs()
        return True
