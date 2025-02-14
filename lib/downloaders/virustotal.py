import logging

import requests

from lib.cuckoo.common.config import Config

integrations_cfg = Config("integrations")
log = logging.getLogger(__name__)


def is_supported(hash: str, apikey: str) -> bool:
    """
    Checks if the hash is supported by the VirusTotal service.

    Args:
        hash (str): The hash to check.

    Returns:
        bool: True if the hash is supported by VirusTotal, False otherwise.
    """
    if len(hash) not in (32, 40, 64):
        log.error("%s is not a valid hash for VirusTotal", hash)
        return False
    elif not integrations_cfg.virustotal.apikey or not apikey:
        log.error("VirusTotal API key not configured. Configure it in integrations.conf")
        return False

    return True


def download(hash: str, apikey: str=None) -> bytes:
    """
    Downloads samples from VirusTotal using the provided API key.

    Args:
        samples (list): List of sample identifiers to download.
        details (dict): Dictionary containing details for the download process.
            Must include an 'apikey' if not provided in settings.
        opt_filename (str): Optional filename for the downloaded samples.
        settings (object): Settings object containing configuration, must include 'VTDL_KEY' if 'apikey' is not in details.

    Returns:
        dict: Updated details dictionary with headers set for the API key and service set to "VirusTotal".
    """

    url = f"https://www.virustotal.com/api/v3/files/{hash.lower()}/download"
    sample = b""
    try:
        r = requests.get(url, headers={"x-apikey": integrations_cfg.virustotal.apikey or apikey}, verify=False)
    except requests.exceptions.RequestException as e:
        logging.error(e)
        return
    if (
        r.status_code == 200
        and r.content != b"Hash Not Present"
        and b"The request requires higher privileges than provided by the access token" not in r.content
    ):
        sample = r.content
    elif r.status_code == 403:
        log.error("API key provided is not a valid VirusTotal key or is not authorized for downloads")
    elif r.status_code == 404:
        log.error("Hash not found on VirusTotal")
    else:
        log.error("Was impossible to download from VirusTotal")

    return sample
