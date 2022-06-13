import logging

from lib.cuckoo.common.abstracts import Report

log = logging.getLogger(__name__)


class MITRE_TTPS(Report):
    def run(self, results):
        if not results.get("ttps") or not hasattr(self, "mitre"):
            return

        attck = {}
        ttp_dict = {}
        for ttp in results["ttps"]:
            ttp_dict.setdefault(ttp["ttp"], []).append(ttp["signature"])
        try:
            for technique in sorted(self.mitre.enterprise.techniques, key=lambda x: x.id):
                if technique.id in list(ttp_dict.keys()):
                    for tactic in technique.tactics:
                        attck.setdefault(tactic.name, []).append(
                            {
                                "t_id": technique.id,
                                "ttp_name": technique.name,
                                "description": technique.description,
                                "signature": ttp_dict[technique.id],
                            }
                        )
            if attck:
                results["mitre_attck"] = attck
        except FileNotFoundError:
            print("MITRE Att&ck data missed, execute: 'python3 utils/community.py -waf'")
        except Exception as e:
            # simplejson.errors.JSONDecodeError
            log.error(("Mitre", e))
