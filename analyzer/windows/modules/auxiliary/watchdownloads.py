# Copyright (C) 2025 Xiang Chen
# This file is part of CAPE Sandbox
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import time
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)

folders_to_monitor = [
    os.path.join(os.environ["HOMEPATH"], "downloads"),
]


HAVE_WATCHDOG = False
try:
    from watchdog.events import EVENT_TYPE_DELETED, FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer

    class MyEventHandler(FileSystemEventHandler):
        def __init__(self):
            super().__init__()
            self._uploaded = {}

        def on_any_event(self, event: FileSystemEvent) -> None:
            if event.is_directory or event.event_type in (EVENT_TYPE_DELETED, "opened"):
                return
            target_path = getattr(event, "dest_path", None) or event.src_path
            if not target_path:
                return
            try:
                filename = os.path.basename(target_path)
                if filename.endswith((".part", ".tmp", ".crdownload", "desktop.ini")):
                    return
                if not os.path.exists(target_path):
                    return
                st = os.stat(target_path)
                if st.st_size == 0:
                    return
                sig = (st.st_size, st.st_mtime)
                if self._uploaded.get(target_path) == sig:
                    return
                log.info("Monitor uploading %s", filename)
                upload_to_host(target_path, f"files/{filename}")
                self._uploaded[target_path] = sig
            except Exception as e:
                log.exception("Can't upload new file %s to host. %s", target_path, str(e))

    HAVE_WATCHDOG = True
except ImportError as e:
    log.debug("Could not load auxiliary module WatchDownloads due to '%s'", str(e))


class WatchDownloads(Auxiliary, Thread):
    """Collect CPU/memory usage info from monitored processes"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        Thread.__init__(self)
        self.enabled = self.config.watchdownloads
        self.do_run = True

    def stop(self):
        """Stop collecting info"""
        self.do_run = False

    def run(self):
        """Run capturing of info.
        @return: operation status.
        """
        if not self.enabled:
            return False

        event_handler = MyEventHandler()
        observer = Observer()
        for folder in folders_to_monitor:
            log.info("Monitoring %s", folder)
            observer.schedule(event_handler, folder, recursive=True)
        observer.start()

        try:
            while self.do_run:
                time.sleep(1)
        finally:
            observer.stop()
            observer.join()

        return True
