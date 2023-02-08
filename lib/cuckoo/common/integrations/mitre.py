# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists, path_is_file

log = logging.getLogger("mitre")


def mitre_generate_attck(results, mitre):
    attck = {}
    ttp_dict = {}
    for ttp in results["ttps"]:
        ttp_dict.setdefault(ttp["ttp"], set()).add(ttp["signature"])
    try:
        for technique in sorted(mitre.enterprise.techniques, key=lambda x: x.technique_id):
            if technique.technique_id not in list(ttp_dict.keys()):
                continue
            for tactic in technique.tactics:
                attck.setdefault(tactic.name, []).append(
                    {
                        "t_id": technique.id,
                        "ttp_name": technique.name,
                        "description": technique.description,
                        "signature": list(ttp_dict[technique.technique_id]),
                    }
                )
    except FileNotFoundError:
        print("MITRE Att&ck data missed, execute: 'python3 utils/community.py -waf'")
    except Exception as e:
        # simplejson.errors.JSONDecodeError
        log.error(("Mitre", e))

    return attck


def init_mitre_attck(online: bool = False):
    config = False
    mitre = False

    try:
        from pyattck import Attck

        if online:
            from pyattck.configuration import Configuration

            config = Configuration()
    except ImportError:
        print("Missed dependency: install pyattck library, see requirements for proper version")
        return

    try:
        mitre = Attck(
            nested_techniques=True,
            use_config=False,
            save_config=False,
            config_file_path=os.path.join(CUCKOO_ROOT, "data", "mitre", "config.yml"),
            data_path=os.path.join(CUCKOO_ROOT, "data", "mitre"),
            enterprise_attck_json=config.enterprise_attck_json
            if online
            else os.path.join(CUCKOO_ROOT, "data", "mitre", "enterprise_attck_json.json"),
            pre_attck_json=config.pre_attck_json if online else os.path.join(CUCKOO_ROOT, "data", "mitre", "pre_attck_json.json"),
            mobile_attck_json=config.mobile_attck_json
            if online
            else os.path.join(CUCKOO_ROOT, "data", "mitre", "mobile_attck_json.json"),
            ics_attck_json=config.ics_attck_json if online else os.path.join(CUCKOO_ROOT, "data", "mitre", "ics_attck_json.json"),
            nist_controls_json=config.nist_controls_json
            if online
            else os.path.join(CUCKOO_ROOT, "data", "mitre", "nist_controls_json.json"),
            generated_nist_json=config.generated_nist_json
            if online
            else os.path.join(CUCKOO_ROOT, "data", "mitre", "generated_nist_json.json"),
        )
    except Exception as e:
        log.error("Can't initialize mitre's Attck class: %s", str(e))

    return mitre


def mitre_update():
    """Urls might change, for proper urls see https://github.com/swimlane/pyattck"""

    mitre = init_mitre_attck(online=True)
    if mitre:
        print("[+] Updating MITRE datasets")
        mitre.update()


def mitre_load(enabled: bool = False):
    mitre = False
    HAVE_MITRE = False
    pyattck_version = ()

    if not enabled:
        return mitre, HAVE_MITRE, pyattck_version

    try:
        # Till fix https://github.com/swimlane/pyattck/pull/129
        from pyattck.configuration import Configuration, Options
        from pyattck.utils.exceptions import UnknownFileError
        from pyattck.utils.version import __version_info__ as pyattck_version

        _ = Options._read_from_disk
        import json
        import warnings

        import yaml

        def _read_from_disk(self, path):
            if path_exists(path) and path_is_file(path):
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

        mitre = init_mitre_attck()
        HAVE_MITRE = True

    except ImportError:
        print("Missed pyattck dependency: check requirements.txt for exact pyattck version")

    return mitre, HAVE_MITRE, pyattck_version
