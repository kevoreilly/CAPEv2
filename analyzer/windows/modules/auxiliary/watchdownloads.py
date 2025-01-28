# Copyright (C) 2025 Xiang Chen
# This file is part of CAPE Sandbox
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
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
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer

    class MyEventHandler(FileSystemEventHandler):
        def on_created(self, event: FileSystemEvent) -> None:
            try:
                filename = os.path.basename(event.src_path)
                if not filename.endswith('.part'):
                    log.info("Monitor uploading %s", filename)
                    upload_to_host(event.src_path, f"files/{filename}")
            except Exception as e:
                log.exception("Can't upload new file %s to host", event.src_path)


    HAVE_WATCHDOG = True
except ImportError as e:
    log.debug(
        f"Could not load auxiliary module WatchDownloads due to '{e}'"
    )


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
