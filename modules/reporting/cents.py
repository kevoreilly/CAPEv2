import os
import logging

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

log = logging.getLogger(__name__)

class Cents(Report):
    """TODO"""
    START_SID = 1  # start sid of suricata rules in output rule file

    def run(self, results):
        """TODO.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write rules file.
        """
        rule_list = []
        for config in results.get("CAPE", {}).get("configs", []):
            if not config or not isinstance(config, dict):
                continue
            for k, v in config.items():
                rules = None
                if k == "CobaltStrikeBeacon":
                    rules = self.cents_cobaltstrikebeacon(v)
                elif k == "Remcos":
                    rules = self.cents_remcos(v)
                else:
                    # config for this family not implemented yet
                    log.info(f"[CENTS] Config for family {k} not implemented yet")
                    continue

                if rules:
                    log.info(f"[CENTS] Created {len(rules)} rules for {k}")
                    rule_list += rules
                else:
                    log.warning(f"[CENTS] Found config for {k}, but couldn't create rules")

        try:
            with open(os.path.join(self.reports_path, "cents.rules"), "w") as f:
                # header lines
                f.write("# This ruleset has been automatically generated\n")
                f.write("# CENTS\n")
                f.write(f"# Created {len(rule_list)} rules.\n")
                # rules
                for line in rule_list:
                    f.write(line + "\n")
                log.info(f"[CENTS] Wrote {len(rule_list)} rules to rule file at: {f.name}")
        except IOError as e:
            raise CuckooReportError("Failed to generate CENTS report: %s" % e)

    def cents_cobaltstrikebeacon(self, config_dict={}):
        """TODO"""
        return []

    def cents_remcos(self, config_dict={}):
        """TODO"""
        if not config_dict:
            return []

        # not all configs look the same
        remcos_config_list = []
        remcos_config = dict((k.lower(), v) for k, v in config_dict.items())
        if remcos_config:
            version = remcos_config.get("version", "")
            control = remcos_config.get("control", [])
            domains = remcos_config.get("domains", [])
            if not version:
                log.debug("[CENTS] Remcos config found without version")
                return []

            else:
                if control:
                    for c in control:
                        if c and c.startswith("tcp://"):
                            tmp = c.replace("tcp://", "").split(":")
                            if tmp and len(tmp) == 2:
                                remcos_config_list.append(
                                    {
                                        "Version": version[0],
                                        "C2": tmp[0],
                                        "Port": tmp[1],
                                    }
                                )
                if domains:
                    for d1 in domains:
                        for d2 in d1:
                            c2 = d2.get("c2:", "")
                            port = d2.get("port", "")
                            if c2 and port:
                                remcos_config_list.append(
                                    {
                                        "Version": version[0],
                                        "C2": c2,
                                        "Port": port,
                                    }
                                )

        if not remcos_config_list:
            return []

        # Now we want to create Suricata rules finally
        rule_list = []
        for obj in remcos_config_list:
            version = obj.get("Version")
            c2 = obj.get("C2")
            port = obj.get("Port")
            rule = f"alert tcp $HOME_NET any -> $EXTERNAL_NET {port} (msg:\"ET MALWARE Remcos RAT (Version {version}) "\
               f"C2 Communication - CAPE sandbox config extraction\"; flow:established,to_server; " \
               f"content:\"{c2}\"; fast_pattern; sid:{self.START_SID}; rev:1;)"
            self.START_SID += 1
            rule_list.append(rule)
        return rule_list
