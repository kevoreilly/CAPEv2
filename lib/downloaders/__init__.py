
import logging
import os

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.load_extra_modules import load_downloaders
from lib.cuckoo.common.path_utils import path_exists, path_mkdir

cfg = Config()
integrations_cfg = Config("integrations")
log = logging.getLogger(__name__)


class Downloaders(object):
    """
    A class to manage and utilize various downloaders for downloading samples.

    Attributes:
        downloaders (dict): A dictionary of available downloaders.
        downloaders_order (list): A list of downloaders in the order specified by the configuration.
        destination_folder (str): The folder where downloaded samples will be stored.

    Methods:
        __init__(destination_folder=None):
            Initializes the Downloaders class with the specified destination folder.

        download(hash, apikey=None):
            Attempts to download a sample using the available downloaders in the specified order.
            Returns the sample and the downloader's name if successful, otherwise returns False, False.
    """
    def __init__(self, destination_folder=None):
        self.downloaders = load_downloaders(CUCKOO_ROOT)
        if integrations_cfg.downloaders.order:
            order_list = [item.strip() for item in integrations_cfg.downloaders.order.split(',')]
            self.downloaders_order = [k for k in order_list if k in self.downloaders.keys()]
        else:
            self.downloaders_order = list(self.downloaders.keys())

        if destination_folder:
            self.destination_folder = destination_folder
        else:
            self.destination_folder = os.path.join(cfg.cuckoo.tmppath, "cape-external")
        if not path_exists(self.destination_folder):
            path_mkdir(self.destination_folder, exist_ok=True)

    def download(self, hash, apikey: str = None):
        """
        Attempts to download a sample using the available downloaders in the specified order.

        Args:
            hash (str): The hash of the sample to be downloaded.
            apikey (str, optional): The API key to be used for the downloaders that require authentication. Defaults to None.

        Returns:
            tuple: A tuple containing the downloaded sample and the name of the downloader service used.
                If no sample is downloaded, returns (False, False).

        Raises:
            Exception: If an error occurs during the download process, it is logged and the next downloader is attempted.
        """
        sample = False
        for service in self.downloaders_order:
            try:
                if self.downloaders[service].is_supported(hash, apikey):
                    sample = self.downloaders[service].download(hash, apikey)
                    if sample:
                        return sample, self.downloaders[service].__name__
                else:
                    log.error("%s is not a valid hash for %s", hash, service)
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
