import hashlib
import logging
import os
import time
from threading import Thread

from lib.common.abstracts import Auxiliary
from lib.common.constants import ROOT
from lib.common.hashing import hash_file
from lib.common.results import upload_to_host

try:
    import pyinotify

    HAVE_PYINOTIFY = True
except ImportError:
    print("Missed pyinotify dependency")
    HAVE_PYINOTIFY = False

log = logging.getLogger(__name__)
DELAY = 1
BUFSIZE = 1024 * 1024


class FileCollector(Auxiliary, Thread):
    """Gets files."""

    def start(self):
        if not self.enabled:
            return False

        self.event_processor.do_collect = True

    def stop(self):
        if not self.enabled:
            return False

        time.sleep(2)  # wait a while to process stuff in the queue
        self.do_run = False
        self.thread.join(timeout=5)

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.filecollector
        self.do_run = self.enabled and HAVE_PYINOTIFY
        if self.enabled:
            self.initComplete = False
            self.thread = Thread(target=self.run)
            self.thread.start()
            while not self.initComplete:
                self.thread.join(0.5)

    def run(self):
        if not HAVE_PYINOTIFY:
            log.info("Missed dependency: pip3 install pyinotify")
            return False

        log.info("FileCollector run started")

        for method in EventProcessor._methods:
            self.process_generator(EventProcessor, method)

        self.watch_manager = pyinotify.WatchManager()
        self.event_processor = EventProcessor()
        self.event_notifier = pyinotify.Notifier(self.watch_manager, self.event_processor)

        self.event_processor.do_collect = False

        flags = (
            pyinotify.IN_CREATE | pyinotify.IN_MODIFY | pyinotify.IN_CLOSE_WRITE | pyinotify.IN_MOVED_TO | pyinotify.IN_MOVED_FROM
        )

        watch_this = os.path.abspath("/")
        self.watch_manager.add_watch(watch_this, flags, auto_add=True)

        ignore = [
            "proc",
            "sys",
            "usr",  # just too many dirs here
            "dev",
            "var",  # we don't want to collect log files
            "lib",
            "lib64",
            # "sbin",
            # "etc",
            "run",  # lots of spurious files
            # "bin",
            # "boot",
            # "media",
            # "srv"
        ]

        for filename in os.listdir("/"):
            if os.path.isdir(f"/{filename}") and filename not in ignore:
                log.info("FileCollector trying to watch dir %s", filename)
                watch_this = os.path.abspath(f"/{filename}")
                self.watch_manager.add_watch(watch_this, flags, rec=True, auto_add=True)

        log.info("FileCollector setup complete")
        self.initComplete = True

        try:
            while self.do_run:  # loop in case more events appear while we are processing
                self.event_notifier.process_events()
                if self.event_notifier.check_events():
                    self.event_notifier.read_events()
        except Exception as e:
            log.error("Exception in loop %s", e)

        log.info("FileCollector run completed")

        return True

    def process_generator(self, cls, method):
        # log.info("Generating message %s", method)

        # excluded files or directories
        noisy_content = ["sysmon", "gvfs-metadata"]

        def _method_name(self, event):
            try:
                # log.info("Got file %s %s", event.pathname, method)

                if not self.do_collect:
                    # log.info("Not currently set to collect %s", event.pathname)
                    return

                if event.pathname.startswith(ROOT):
                    # log.info("Skipping random base directory for file %s", event.pathname)
                    return

                if event.pathname.startswith("/tmp/#"):
                    # log.info("Skipping wierd file %s", event.pathname)
                    return

                if not os.path.isfile(event.pathname):
                    # log.info("Path is a directory or does not exist, ignoring: %s", event.pathname)
                    return

                if "strace.log" in os.path.basename(event.pathname):
                    return

                if any(noisy in event.pathname for noisy in noisy_content):
                    # log.info("Skipping noisy file %s", event.pathname)
                    return

                try:
                    # log.info("Trying to collect file %s", event.pathname)
                    sha256 = hash_file(hashlib.sha256, event.pathname)
                    if sha256 in self.uploadedHashes:
                        # log.info("Already collected file %s", event.pathname)
                        return
                    upload_path = os.path.join("files", sha256)
                    upload_to_host(event.pathname, upload_path)
                    self.uploadedHashes.append(sha256)
                    return
                except Exception as e:
                    log.info('Error dumping file from path "%s": %s', event.pathname, e)

                # log.info("Retrying %s", event.pathname)
                time.sleep(1)

            except Exception as e:
                log.error("Exception processing event %s", e)

        _method_name.__name__ = f"process_{method}"
        setattr(cls, _method_name.__name__, _method_name)


class EventProcessor(pyinotify.ProcessEvent):
    _methods = [
        "IN_CREATE",
        "IN_OPEN",
        "IN_ACCESS",
        "IN_ATTRIB",
        "IN_CLOSE_NOWRITE",
        "IN_CLOSE_WRITE",
        "IN_DELETE",
        "IN_DELETE_SELF",
        "IN_IGNORED",
        "IN_MODIFY",
        "IN_MOVE_SELF",
        "IN_MOVED_FROM",
        "IN_MOVED_TO",
        "IN_Q_OVERFLOW",
        "IN_UNMOUNT",
        "default",
    ]
    uploadedHashes = []
