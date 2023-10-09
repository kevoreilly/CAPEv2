# Copyright (C) 2021 CSIT
# This file is part of CAPE Sandbox - http://www.capesandbox.com
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import os
from json.decoder import JSONDecodeError

from lib.common.exceptions import CuckooPackageError

log = logging.getLogger(__name__)


def extract_json_data(json_directory: str, json_filename: str):
    """Extract data from json file
    @param json_directory: The directory where the JSON file resides
    @param json_filename: Name of the JSON file
    @return: Entire JSON data, or {} if there is no JSON file
    """
    try:
        json_path = os.path.join(json_directory, json_filename)
        with open(json_path) as json_config_file:
            return json.load(json_config_file)
    except FileNotFoundError:
        log.warning('JSON Config File "%s" not found inside ZIP Compound', json_filename)
        return {}
    except JSONDecodeError as e:
        raise CuckooPackageError(f"JSON decode error. Please check format in `{json_filename}` file") from e


def create_custom_folders(directory_path: str):
    """Create custom folders (recursively) given the full path."""
    if os.path.exists(directory_path):
        log.info("%s already exists, skipping creation", directory_path)
    else:
        try:
            os.makedirs(directory_path)
            log.info("%s created", directory_path)
        except OSError:
            log.error("Unable to create user-defined custom folder directory")
