#!/usr/bin/env python

import binascii
import functools
import logging
import os
import tempfile
import threading

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_buffer_to_host, upload_to_host

from .amsi import AMSI, jsonldump

logger = logging.getLogger(__name__)


class AMSICollector(Auxiliary, threading.Thread):
    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        threading.Thread.__init__(self)
        self.enabled = config.amsi
        self.stop_event = threading.Event()
        self.tmpfile = None
        self.upload_prefix = "aux/amsi"

    def handle_event(self, event, logfh=None):
        """
        Process the AMSI event by appending a line to amsi.jsonl file containing its metadata.
        That will get uploaded after we finish collecting events.

        Upload the content of the event as its own file to be stored.
        """
        # https://redcanary.com/blog/amsi/ has some useful info on the event record fields.
        content = event.pop("content", None)
        if not content:
            return

        if logfh:
            jsonldump(event, fp=logfh)

        dump_path = f"{self.upload_prefix}/{event['hash'][2:].lower()}"
        decoded_content = binascii.unhexlify(content[2:])
        if event.get("appname", "") in ("DotNet", "coreclr"):
            # The content is the full in-memory .NET assembly PE.
            pass
        else:
            # The content is UTF-16 encoded text. We'll store it as utf-8, just like all other text files.
            decoded_content = decoded_content.decode("utf-16", errors="replace").encode("utf-8")
        upload_buffer_to_host(decoded_content, dump_path)

    def stop(self):
        self.stop_event.set()

    def run(self):
        if not self.enabled:
            return

        try:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as fil:
                self.tmpfile = fil.name
                amsi = AMSI(event_callback=functools.partial(self.handle_event, logfh=fil))
                logger.info("AMSI: Starting to listen for events.")
                try:
                    with amsi:
                        self.stop_event.wait()
                        logger.info("AMSI: Stopping event consumer.")
                except PermissionError as err:
                    raise PermissionError(
                        "This module must be run with Administrator privilege in order to collect AMSI events."
                    ) from err
        except Exception:
            logger.exception("AMSI: Exception raised.")
            raise

    def finish(self):
        """Upload the file that contains the metadata for all of the events."""
        if not self.tmpfile or not os.path.exists(self.tmpfile):
            return
        try:
            if os.stat(self.tmpfile).st_size > 0:
                upload_to_host(self.tmpfile, f"{self.upload_prefix}/amsi.jsonl")
            else:
                logger.debug("AMSI: no AMSI events were collected.")
        except Exception:
            logger.exception("AMSI: Exception was raised while uploading amsi.jsonl")
            raise
        finally:
            os.unlink(self.tmpfile)
            self.tmpfile = None
