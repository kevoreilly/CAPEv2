# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os

from lib.cuckoo.common.constants import CUCKOO_ROOT

log = logging.getLogger("mitre")


def mitre_generate_attck(results, mitre):
    attck = {}
    ttp_dict = {}

    if not mitre or not hasattr(mitre, "enterprise"):
        print("Missed dependency: poetry run pip install git+https://github.com/CAPESandbox/pyattck")
        return attck

    # [{'signature': 'http_request', 'ttps': ['T1071']}, {'signature': 'modify_proxy', 'ttps': ['T1112']}, {'signature': 'recon_fingerprint', 'ttps': ['T1012', 'T1082']}]
    for ttp_block in results["ttps"]:
        for ttp in ttp_block.get("ttps", []):
            ttp_dict.setdefault(ttp, set()).add(ttp_block["signature"])
    try:
        for technique in mitre.enterprise.techniques:
            if technique.technique_id not in list(ttp_dict.keys()):
                continue
            for tactic in technique.tactics:
                attck.setdefault(tactic.name, []).append(
                    {
                        "t_id": technique.technique_id,
                        "ttp_name": technique.name,
                        "description": technique.description,
                        "signature": list(ttp_dict[technique.technique_id]),
                    }
                )
    except FileNotFoundError:
        print("MITRE Att&ck data missed, execute: 'poetry run python utils/community.py -waf --mitre'")
    except AttributeError:
        print("Missed dependency: poetry run pip install git+https://github.com/CAPESandbox/pyattck")
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
            enterprise_attck_json=(
                config.enterprise_attck_json if online else os.path.join(CUCKOO_ROOT, "data", "mitre", "enterprise_attck_json.json")
            ),
            pre_attck_json=config.pre_attck_json if online else os.path.join(CUCKOO_ROOT, "data", "mitre", "pre_attck_json.json"),
            mobile_attck_json=(
                config.mobile_attck_json if online else os.path.join(CUCKOO_ROOT, "data", "mitre", "mobile_attck_json.json")
            ),
            ics_attck_json=config.ics_attck_json if online else os.path.join(CUCKOO_ROOT, "data", "mitre", "ics_attck_json.json"),
            nist_controls_json=(
                config.nist_controls_json if online else os.path.join(CUCKOO_ROOT, "data", "mitre", "nist_controls_json.json")
            ),
            generated_nist_json=(
                config.generated_nist_json if online else os.path.join(CUCKOO_ROOT, "data", "mitre", "generated_nist_json.json")
            ),
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
        mitre = init_mitre_attck()
        HAVE_MITRE = True

    except ImportError:
        print("Missed pyattck dependency: check requirements.txt for exact pyattck version")

    return mitre, HAVE_MITRE, pyattck_version
