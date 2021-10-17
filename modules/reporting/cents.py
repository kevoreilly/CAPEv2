import os
import logging

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.utils import datetime_to_iso

from lib.cuckoo.common.cents.cents_remcos import cents_remcos
from lib.cuckoo.common.cents.cents_squirrelwaffle import cents_squirrelwaffle
from lib.cuckoo.common.cents.cents_trickbot import cents_trickbot

log = logging.getLogger(__name__)


class Cents(Report):
    """C.E.N.T.S Configuration Extraction to Network Traffic Signatures
    The CENTS reporting module is part of a project by @zoomequipd, @malwareforme and @klingerko (GitHub) that uses the
    extracted malware configuration from CAPEv2 runs and automatically creates Suricata rules where it makes sense.
    """

    def __init__(self):
        self.reporting_conf = Config("reporting")
        self.web_conf = Config("web")
        self.sid_counter = 1000000  # start sid of suricata rules in output rule file
        self.hostname = "https://127.0.0.1/"  # hostname of the cape instance
        if self.reporting_conf and self.reporting_conf.cents.start_sid:
            self.sid_counter = int(self.reporting_conf.cents.start_sid)
        if self.web_conf and self.web_conf.general.hostname:
            self.hostname = str(self.web_conf.general.hostname)

    def run(self, results):
        """CENTS reporting module
        - checks if we have a extracted config
        - checks if we have a parser for the malware family
        - if yes it proceeds and tries to create Suricata rules for the malware family
        - writes a new rule file to the reports_path

        :param results: Cuckoo results dict.
        :type results: `dict`
        :raise CuckooReportError: if fails to write rules file.
        """
        rule_list = []
        md5 = results.get("target", {}).get("file", {}).get("md5", "")  # md5 of the sample
        date = datetime_to_iso(results.get("info", {}).get("started", "")).split("T", 1)[0].replace("-", "_")  # timestamp of the sample run
        task_id = int(results.get("info", {}).get("id", 0))  # task id of the analysis run
        task_link = f"{self.hostname}/analysis/{task_id}/"
        if self.hostname.endswith("/"):
            task_link = f"{self.hostname}analysis/{task_id}/"
        configs = results.get("CAPE", {}).get("configs", [])
        results["info"]["has_cents_rules"] = False
        if not configs:
            # no config extracted, nothing to do for CENTS
            return

        # sometimes there is more than one extracted config that is identical
        configs_dedup = []
        for entry in configs:
            if entry in configs_dedup:
                continue
            configs_dedup.append(entry)

        for config in configs_dedup:
            if not config or not isinstance(config, dict):
                continue
            for config_name, config_dict in config.items():
                rules = None
                if config_name == "Remcos":
                    rules = cents_remcos(config_dict, self.sid_counter, md5, date, task_link)
                elif config_name == "SquirrelWaffle":
                    rules = cents_squirrelwaffle(config_dict, self.sid_counter, md5, date, task_link)
                elif config_name == "TrickBot":
                    rules = cents_trickbot(config_dict, results.get("suricata", {}), self.sid_counter, md5, date, task_link)
                else:
                    # config for this family not implemented yet
                    log.debug(f"[CENTS] Config for family {config_name} not implemented yet")
                    continue

                if rules:
                    log.debug(f"[CENTS] Created {len(rules)} rule(s) for {config_name}")
                    self.sid_counter += len(rules)
                    rule_list += rules
                else:
                    log.warning(f"[CENTS] Found config for {config_name}, but couldn't create rules")

        if not rule_list:
            # no rules have been created
            return

        try:
            with open(os.path.join(self.reports_path, "cents.rules"), "w") as f:
                # header lines
                f.write("# This ruleset has been automatically generated\n")
                f.write("# CENTS\n")
                f.write(f"# Created {len(rule_list)} rules.\n")
                # rules
                for line in rule_list:
                    f.write(line + "\n")
                log.info(f"[CENTS] Wrote {len(rule_list)} rule(s) to rule file at: {f.name}")
                results["info"]["has_cents_rules"] = True
        except IOError as e:
            raise CuckooReportError("Failed to generate CENTS report: %s" % e)
