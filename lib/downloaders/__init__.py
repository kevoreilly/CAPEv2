
import os
import logging

from lib.cuckoo.common.load_extra_modules import load_downloaders
from lib.cuckoo.common.constants import CUSTOM_ROOT
from lib.cuckoo.common.path_utils import path_exists, path_mkdir
from lib.cuckoo.common.config import Config

cfg = Config()
integrations_cfg = Config("integrations")
log = logging.getLogger(__name__)


class Downloaders(object):
    def __init__(self, destination_folder=None):
        self.downloaders = load_downloaders(CUSTOM_ROOT)
        if integrations_cfg.downloaders.order:
            self.downloaders_order = [k.strip() for k in self.downloaders.keys() if k.strip() in integrations_cfg.downloaders.order]
        else:
            self.downloaders_order = list(self.downloaders.keys())

        if destination_folder:
            self.destination_folder = destination_folder
        else:
            self.destination_folder = os.path.join(cfg.cuckoo.tmppath, "cape-external")
        if not path_exists(self.destination_folder):
            path_mkdir(self.destination_folder, exist_ok=True)

    def download(self, hash, apikey: str = None):
        sample = False
        for service in self.downloaders_order:
            try:
                if self.downloaders[service].is_supported(hash, apikey):
                    sample = self.downloaders[service].download(hash, apikey)
                    if sample:
                        return sample, self.downloaders[service].__name__
            except Exception as e:
                log.error("Error downloading sample from %s: %s", service, e)
        if not sample:
            return False, False

if __name__ == "__main__":
    import sys
    dl = Downloaders()
    sample, service = dl.download(sys.argv[1])
    if sample:
        print("Downloaded sample from %s" % service)
        with open(sys.argv[1], "wb") as f:
            f.write(sample)
