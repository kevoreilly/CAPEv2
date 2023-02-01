# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
from lib.cuckoo.common.constants import CUCKOO_ROOT


def load_mitre(enabled: bool = False):
    mitre = False
    HAVE_MITRE = False

    if not enabled:
        return mitre, HAVE_MITRE

    try:
        from pyattck import Attck
        from pyattck.utils.version import __version_info__ as pyattck_version

        # Version is hardcoded due to possible changes in load of the library

        # Till fix https://github.com/swimlane/pyattck/pull/129
        from pyattck.configuration import Options, Configuration
        from pyattck.utils.exceptions import UnknownFileError
        old_read_from_disk = Options._read_from_disk
        import json, warnings, yaml
        def _read_from_disk(self, path):
            if os.path.exists(path) and os.path.isfile(path):
                try:
                    with open(path) as f:
                        if path.endswith(".json"):
                            return json.load(f)
                        elif path.endswith(".yml") or path.endswith(".yaml"):
                            return Configuration(**yaml.load(f, Loader=yaml.SafeLoader))
                        else:
                            raise UnknownFileError(provided_value=path, known_values=[".json", ".yml", ".yaml"])
                except Exception as e:
                    warnings.warn(
                        message=f"The provided config file {path} is not in the correct format. "
                        "Using default values instead."
                    )
                    pass
            elif os.path.isdir(path):
                raise Exception(f"The provided path is a directory and must be a file: {path}")
        Options._read_from_disk = _read_from_disk

        if pyattck_version == (7, 0, 0):
            mitre = Attck(
                nested_techniques=True,
                use_config=True,
                save_config=True,
                config_file_path=os.path.join(CUCKOO_ROOT, "data", "mitre", "config.yml"),
                data_path=os.path.join(CUCKOO_ROOT, "data", "mitre"),
                enterprise_attck_json=os.path.join(CUCKOO_ROOT, "data", "mitre", "enterprise_attck_json.json"),
                pre_attck_json=os.path.join(CUCKOO_ROOT, "data", "mitre", "pre_attck_json.json"),
                mobile_attck_json=os.path.join(CUCKOO_ROOT, "data", "mitre", "mobile_attck_json.json"),
                ics_attck_json=os.path.join(CUCKOO_ROOT, "data", "mitre", "ics_attck_json.json"),
                nist_controls_json=os.path.join(CUCKOO_ROOT, "data", "mitre", "nist_controls_json.json"),
                generated_nist_json=os.path.join(CUCKOO_ROOT, "data", "mitre", "generated_nist_json.json"),
            )
            HAVE_MITRE = True

    except ImportError:
        print("Missed pyattck dependency: check requirements.txt for exact pyattck version")

    return mitre, HAVE_MITRE
