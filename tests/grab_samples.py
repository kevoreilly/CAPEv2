#!/usr/bin/env python

# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import json
import logging
import os

import urllib3
from tcr_misc import get_sample

urllib3.disable_warnings()

logging.basicConfig()


def get_filepaths(directory, args):
    """
    DEDUPE from tcr_misc.py
    This function will generate the file names in a directory
    tree by walking the tree either top-down or bottom-up. For each
    directory in the tree rooted at directory top (including top itself),
    it yields a 3-tuple (dirpath, dirnames, filenames).
    """
    file_paths = []  # List which will store all of the full filepaths.

    # Walk the tree.
    for root, directories, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".json"):
                # Join the two strings in order to form the full filepath.
                filepath = os.path.join(root, filename)
                file_paths.append(filepath)  # Add it to the list.

    if args.family:
        return filter(lambda path: args.family == os.path.dirname(path).rsplit("/", 1)[-1], file_paths)
    return file_paths  # Self-explanatory.


def load_sample_lists(args):
    sample_json_list = get_filepaths("tests/Extractors/StandAlone/unit_tests", args)
    for sample_json_location in sample_json_list:
        logging.warning("Found sample.json: " + sample_json_location)
        with open(sample_json_location, "r") as samples:
            sample_dict = json.load(samples)
            for hash_item in sample_dict["hashes"]:
                sample_name = "malware." + hash_item["hash"] + "." + hash_item.get("name", "none") + ".exe"
                try:
                    get_sample(hash_item["hash"], os.path.dirname(sample_json_location) + "/" + sample_name)
                except Exception as e:
                    logging.exception(e)


def run(args):
    load_sample_lists(args)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Grab malicious samples from sample.json files via https://10.203.112.173/centralrepo/"
    )

    parser.add_argument("--family", action="store", dest="family", type=str)
    args = parser.parse_args()

    run(args)
