# Copyright (C) 2024 fdiaz@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import json
import logging
import os
import tempfile
import threading
import time

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_buffer_to_host

log = logging.getLogger(__name__)

LOG_PREFIX = "bext_"
LOG_SUFFIX = ".json"
UPLOAD_PATH = "browser/requests.log"
# Packages that open a browser with the extension from extra/browser_extension.
EXTENSION_PACKAGES = ("firefox_ext", "chromium_ext", "tor_browser")
POLL_INTERVAL = 1
FINAL_READ_ATTEMPTS = 5
FINAL_READ_DELAY = 0.5


def _is_extension_log(name):
    return name.startswith(LOG_PREFIX) and name.endswith(LOG_SUFFIX)


def _scandir(path):
    try:
        with os.scandir(path) as entries:
            return list(entries)
    except OSError:
        return []


class Browsermonitor(Auxiliary, threading.Thread):
    """Collects the requests logged by the browser extension (extra/browser_extension).

    The extension sends the requests to the agent (/browser_extension), which rewrites
    them on every update to %TEMP%\\<random folder>\\bext_<random>.json. Since agent
    0.20 the folder name no longer starts with "tmp". TOR Browser saves bext_*.json
    directly in %TEMP%.

    The last version of the log that is complete JSON is uploaded once, when the
    analysis ends, to browser/requests.log (see modules/reporting/browserext.py).
    """

    def __init__(self, options=None, config=None):
        if options is None:
            options = {}
        Auxiliary.__init__(self, options, config)
        threading.Thread.__init__(self)
        self.daemon = True
        self.enabled = bool(getattr(config, "browsermonitor", False))
        self.package = str(getattr(config, "package", "") or "")
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.temp_dir = tempfile.gettempdir()
        self.browser_logfile = ""
        self.last_read = None
        self.entries = None
        self.collected = False
        # Logs already present in the snapshot are ignored unless they are updated.
        self.snapshot_logs = self._find_logs() if self.enabled else {}

    def _find_logs(self):
        """Return {path: (mtime, size)} of the non-empty extension logs in %TEMP% and its subfolders."""
        logs = {}
        for entry in _scandir(self.temp_dir):
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            for candidate in _scandir(entry.path) if is_dir else [entry]:
                if not _is_extension_log(candidate.name):
                    continue
                try:
                    stat = os.stat(candidate.path)
                except OSError:
                    continue
                if stat.st_size:
                    logs[candidate.path] = (stat.st_mtime, stat.st_size)
        return logs

    def _read_log(self):
        """Read the log if it changed. Return False if it changed but is not complete JSON yet."""
        try:
            stat = os.stat(self.browser_logfile)
            if (stat.st_mtime, stat.st_size) == self.last_read:
                return True
            with open(self.browser_logfile, "rb") as f:
                data = f.read()
        except OSError:
            return False
        # Agents older than 0.23 write the log with the ANSI code page.
        for encoding in ("utf-8", "mbcs", "latin-1"):
            try:
                entries = json.loads(data.decode(encoding))
            except (LookupError, UnicodeDecodeError):
                continue
            except ValueError:
                # The agent is rewriting the file, keep the previous version.
                return False
            if not isinstance(entries, list):
                return False
            self.entries = entries
            self.last_read = (stat.st_mtime, stat.st_size)
            return True
        return False

    def _poll(self):
        """Find the extension log and read it. Return False if the latest version could not be read."""
        if not self.browser_logfile or not os.path.isfile(self.browser_logfile):
            new_logs = [(stat, path) for path, stat in self._find_logs().items() if self.snapshot_logs.get(path) != stat]
            if not new_logs:
                return True
            self.browser_logfile = max(new_logs)[1]
            self.last_read = None
            log.info("Found browser extension log: %s", self.browser_logfile)
        return self._read_log()

    def run(self):
        if not self.enabled:
            return
        while not self.stop_event.is_set():
            with self.lock:
                if self.collected:
                    break
                try:
                    self._poll()
                except Exception as e:
                    log.warning("Error reading the browser extension log: %s", e)
            self.stop_event.wait(POLL_INTERVAL)

    def stop(self):
        if not self.enabled:
            return True
        self.stop_event.set()
        with self.lock:
            if self.collected:
                return True
            self.collected = True
            try:
                self._collect()
            except Exception as e:
                log.warning("Error collecting the browser extension log: %s", e)
        return True

    def _collect(self):
        for _ in range(FINAL_READ_ATTEMPTS):
            if self._poll():
                break
            time.sleep(FINAL_READ_DELAY)
        if self.entries is None:
            level = logging.WARNING if self.package in EXTENSION_PACKAGES else logging.DEBUG
            log.log(level, "No browser extension log found in %s, is the extension installed and enabled?", self.temp_dir)
            return
        # Re-encoded as UTF-8 JSON, which is what modules/reporting/browserext.py expects.
        upload_buffer_to_host(json.dumps(self.entries).encode(), UPLOAD_PATH)
        log.info("Uploaded %d browser extension requests to %s", len(self.entries), UPLOAD_PATH)
