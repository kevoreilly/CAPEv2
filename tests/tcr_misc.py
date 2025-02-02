#!/usr/bin/env python
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import logging
import os
import uuid

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings()

s = requests.Session()
retries = Retry(total=5, backoff_factor=0.1, status_forcelist=[404, 500, 502, 503, 504])

s.mount("http://", HTTPAdapter(max_retries=retries))
s.mount("https://", HTTPAdapter(max_retries=retries))


SAMPLE_STORAGE = "http://YOUR_MAGIC_REPO/"


def random_string():
    return str(uuid.uuid4()).split("-", 1)[0]


def get_filepaths(directory, ends=None, starts=None):
    """
    This function will generate the file names in a directory
    tree by walking the tree either top-down or bottom-up. For each
    directory in the tree rooted at directory top (including top itself),
    it yields a 3-tuple (dirpath, dirnames, filenames).
    """
    file_paths = []  # List which will store all of the full filepaths.

    # Walk the tree.
    for root, directories, files in os.walk(directory):
        for filename in files:
            basename = os.path.basename(filename)
            if ends and starts:
                if basename.startswith(starts) and basename.endswith(ends):
                    # Join the two strings in order to form the full filepath.
                    filepath = os.path.join(root, filename)
                    file_paths.append(filepath)  # Add it to the list.
            elif ends and not starts:
                if basename.endswith(starts):
                    filepath = os.path.join(root, filename)
                    file_paths.append(filepath)  # Add it to the list.
            elif not ends and starts:
                if basename.startswith(starts):
                    filepath = os.path.join(root, filename)
                    file_paths.append(filepath)  # Add it to the list.

    return file_paths  # Self-explanatory.


def get_malware_paths(path):
    return get_filepaths(path, starts="malware.", ends=".exe")


def get_sample(hash, download_location):
    if os.path.isfile(download_location) and hash == hashlib.sha256(open(download_location, "rb").read()).hexdigest():
        logging.warning("%s already there, skipping!", download_location)
    else:
        r = s.get(SAMPLE_STORAGE + hash, verify=False, timeout=10)
        if r and r.status_code == 200:
            sha256 = hashlib.sha256(r.content).hexdigest()
            if sha256 != hash:
                raise Exception("Hashes doens't match")
            with open(download_location, mode="wb+") as file:
                file.write(r.content)
                logging.warning("%s grabbed!", download_location)
        else:
            logging.warning("Status code: %d - content: %s", r.status_code, r.text)
            raise Exception("Non 200 status code")
