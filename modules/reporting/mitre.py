# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.abstracts import Report

log = logging.getLogger(__name__)


def generate_mitre_attck(results, mitre):
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


class MITRE_TTPS(Report):
    def run(self, results):
        if not results.get("ttps") or not hasattr(self, "mitre"):
            return

        attck = generate_mitre_attck(results, self.mitre)
        if attck:
            results["mitre_attck"] = attck
