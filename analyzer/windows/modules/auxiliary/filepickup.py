import logging
import os

from lib.common.abstracts import Auxiliary
from lib.common.results import upload_to_host

log = logging.getLogger(__name__)


__author__ = "[Canadian Centre for Cyber Security] @CybercentreCanada"


class FilePickup(Auxiliary):
    """In cases where you want to run something with 'free=yes' but know that a file will be generated,
    you can use this aux module to tell CAPE to pick up the file"""

    def __init__(self, options, config):
        Auxiliary.__init__(self, options, config)
        self.enabled = config.file_pickup
        self.do_run = self.enabled

    def start(self):
        if not self.options.get("filepickup"):
            self.do_run = False
            return True

        self.file_to_get = self.options.get("filepickup")

    def stop(self):
        if hasattr(self, "file_to_get"):
            if self.file_to_get:
                log.info(f"Uploading {self.file_to_get}")
                upload_to_host(self.file_to_get, os.path.join("files", os.path.basename(self.file_to_get)))

        self.do_run = False
