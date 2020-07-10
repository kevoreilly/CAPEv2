from __future__ import absolute_import
from lib.cuckoo.common.abstracts import Report


class MITRE_TTPS(Report):
    def run(self, results):
        if not results.get("ttps") or not hasattr(self, "mitre"):
            return

        attck = dict()
        ttps = list(results["ttps"].keys())
        for technique in self.mitre.enterprise.techniques:
            if technique.id in ttps:
                for tactic in technique.tactics:
                    attck.setdefault(tactic.name, list())
                    attck[tactic.name].append(
                        {
                            "t_id": technique.id,
                            "ttp_name": technique.name,
                            "description": technique.description,
                            "signature": results["ttps"][technique.id],
                        }
                    )
        if attck:
            results["mitre_attck"] = attck
