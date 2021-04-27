from __future__ import absolute_import
from lib.cuckoo.common.abstracts import Report


class MITRE_TTPS(Report):
    def run(self, results):
        if not results.get("ttps") or not hasattr(self, "mitre"):
            return

        attck = dict()
        ttp_dict = {block["ttp"]: block["signature"] for block in results["ttps"]}
        for technique in self.mitre.enterprise.techniques:
            if technique.id in list(ttp_dict.keys()):
                for tactic in technique.tactics:
                    attck.setdefault(tactic.name, list())
                    attck[tactic.name].append(
                        {
                            "t_id": technique.id,
                            "ttp_name": technique.name,
                            "description": technique.description,
                            "signature": ttp_dict[technique.id],
                        }
                    )
        if attck:
            results["mitre_attck"] = attck
