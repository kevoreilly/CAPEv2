# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os

from lib.cuckoo.common.constants import CUCKOO_ROOT


def mitre_update():
    """Urls might change, for proper urls see https://github.com/swimlane/pyattck"""
    try:
        from pyattck import Attck
    except ImportError:
        print("Missed dependency: install pyattck library, see requirements for proper version")
        return

    mitre = Attck(
        nested_techniques=True,
        use_config=False,
        save_config=False,
        config_file_path=os.path.join(CUCKOO_ROOT, "data", "mitre", "config.yml"),
        data_path=os.path.join(CUCKOO_ROOT, "data", "mitre"),
        enterprise_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_enterprise_attck_v1.json",
        pre_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_pre_attck_v1.json",
        mobile_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_mobile_attck_v1.json",
        ics_attck_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_ics_attck_v1.json",
        nist_controls_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/merged_nist_controls_v1.json",
        generated_nist_json="https://swimlane-pyattck.s3.us-west-2.amazonaws.com/attck_to_nist_controls.json",
    )

    print("[+] Updating MITRE datasets")
    mitre.update()


def load_mitre(enabled: bool = False):
    mitre = False
    HAVE_MITRE = False
    pyattck_version = ()

    if not enabled:
        return mitre, HAVE_MITRE, pyattck_version

    try:
        from pyattck import Attck

        # Till fix https://github.com/swimlane/pyattck/pull/129
        from pyattck.configuration import Configuration, Options
        from pyattck.utils.exceptions import UnknownFileError
        from pyattck.utils.version import __version_info__ as pyattck_version

        _ = Options._read_from_disk
        import json  # noqa: E401
        import warnings

        import yaml

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
                except Exception:
                    warnings.warn(
                        message=f"The provided config file {path} is not in the correct format. " "Using default values instead."
                    )
                    pass
            elif os.path.isdir(path):
                raise Exception(f"The provided path is a directory and must be a file: {path}")

        Options._read_from_disk = _read_from_disk

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

    return mitre, HAVE_MITRE, pyattck_version
