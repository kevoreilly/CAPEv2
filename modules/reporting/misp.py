# -*- coding: utf-8 -*-
# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# Updated by doomedraven 30.11.2019 for NaxoneZ
# Updated by NaxoneZ 20.12.2019 for the rest of the world :)

import os
import json
import logging
from io import BytesIO
from collections import deque
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT

"""
  (1,"High","*high* means sophisticated APT malware or 0-day attack","Sophisticated APT malware or 0-day attack"),
  (2,"Medium","*medium* means APT malware","APT malware"),
  (3,"Low","*low* means mass-malware","Mass-malware"),
  (4,"Undefined","*undefined* no risk","No risk");
"""


try:
    from pymisp import MISPEvent, PyMISP, MISPObject
    from pymisp import logger as pymisp_logger
    HAVE_PYMISP = True
    pymisp_logger.setLevel(logging.ERROR)
except ImportError:
    HAVE_PYMISP = True
    print("pip3 install pymisp")

log = logging.getLogger(__name__)
logging.getLogger("pymisp").setLevel(logging.WARNING)

ttps_json = {}
mitre_json_path = os.path.join(CUCKOO_ROOT, "data", "mitre_attack.json")
if os.path.exists(mitre_json_path):
    ttps_json = json.load(open(mitre_json_path))
malpedia_json_path = os.path.join(CUCKOO_ROOT, "data", "malpedia.json")
if os.path.exists(malpedia_json_path):
    malpedia_json = json.load(open(os.path.join(CUCKOO_ROOT, "data", "malpedia.json")))
else:
    malpedia_json = False

# load whitelist if exists
whitelist = list()
if os.path.exists(os.path.join(CUCKOO_ROOT, "conf", "misp.conf")):
    whitelist = Config("misp").whitelist.whitelist
    if whitelist:
        whitelist = [ioc.strip() for ioc in whitelist.split(",")]

name_update_shema = {
    "Agenttesla": "Agent Tesla",
    "AgentTeslaV2": "Agent Tesla",
    "WarzoneRAT": "Ave Maria",
}


class MISP(Report):
    """MISP Analyzer."""

    order = 1

    def malpedia(self, results, event, malfamily):
        if malfamily in name_update_shema:
            malfamily = name_update_shema[malfamily]
        if malfamily in malpedia_json:
            self.misp.tag(event["uuid"], 'misp-galaxy:malpedia="{}"'.format(malfamily))

    def signature(self, results, event):
        for ttp in results.get("ttps", []) or []:
            for i in ttps_json.get("objects", []) or []:
                try:
                    if i["external_references"][0]["external_id"] == ttp:
                        self.misp.tag(event, f'misp-galaxy:mitre-attack-pattern="{i["name"]}-{ttp}"')
                except Exception:
                    pass

    def sample_hashes(self, results, event):
        if results.get("target", {}).get("file", {}):
            f = results["target"]["file"]
            misp_object = MISPObject("file")
            misp_object.comment = "File submitted to CAPEv2"
            misp_object.add_attribute("filename", value=f["name"], category="Payload delivery")
            misp_object.add_attribute("md5", value=f["md5"], category="Payload delivery")
            misp_object.add_attribute("sha1", value=f["sha1"], category="Payload delivery")
            misp_object.add_attribute("sha256", value=f["sha256"], category="Payload delivery")
            misp_object.add_attribute("ssdeep", value=f["ssdeep"], category="Payload delivery")
            self.misp.add_object(event, misp_object)

    def all_network(self, results, event):
        """All of the accessed URLS as per the PCAP."""
        urls = set()
        if self.options.get("network", False) and "network" in results.keys():
            urls = set()
            for req in results["network"].get("http", []):
                if "uri" in req and req["uri"] not in whitelist:
                    urls.add(req["uri"])
                if "user-agent" in req:
                    event.add_attribute("user-agent", req["user-agent"])

            domains, ips = {}, set()
            for domain in results.get("network", {}).get("domains", []):
                if domain["domain"] not in whitelist and domain["ip"] not in whitelist:
                    domains[domain["domain"]] = domain["ip"]
                    ips.add(domain["ip"])

            for block in results.get("network", {}).get("hosts", []):
                if block["ip"] not in whitelist:
                    ips.add(block["ip"])

            for block in results["network"].get("dns", []):  # Added DNS
                if block.get("request", "") and (block["request"] not in whitelist):
                    if block["request"] not in domains and block["request"] not in whitelist:
                        if block["answers"]:
                            domains[block["request"]] = block["answers"][0]["data"]
                            ips.add(domain[block["answers"][0]["data"]])

            # Added CAPE Addresses
            for section in results.get("CAPE", []) or []:
                try:
                    if section.get("cape_config", {}).get("address", []) or []:
                        for ip in section["cape_config"]["address"]:
                            if ip not in ips:
                                ips.add(ip.split(":")[0])
                except Exception as e:
                    print(e)

            for url in sorted(list(urls)):
                event.add_attribute("url", url)
            for ip in sorted(list(ips)):
                event.add_attribute("ip-dst", ip)
            for domain, ips in domains.items():
                obj = MISPObject("domain-ip")
                obj.add_attribute("domain", domain)
                for ip in ips:
                    obj.add_attribute("ip", ip)
                event.add_object(obj)
            self.misp.update_event(event)

    def dropped_files(self, results, event):
        """
        if self.options.get("dropped", False) and "dropped" in results:
            for entry in results["dropped"]:
                if entry["md5"] and  entry["md5"] not in whitelist:
                    self.misper["iocs"].append({"md5": entry["md5"]})
                    self.misper["iocs"].append({"sha1": entry["sha1"]})
                    self.misper["iocs"].append({"sha256": entry["sha256"]})
        """
        """
        Add all the dropped files as MISP attributes.
        """
        # Upload all the dropped files at once
        # TODO: Use expanded
        for r in results.get("dropped", []) or []:
            with open(r.get("path"), "rb") as f:
                event.add_attribute("malware-sample", value=os.path.basename(r.get("path")), data=BytesIO(f.read()), expand="binary")
        event.run_expansions()
        self.misp.update_event(event)
        """
        # Load the event from MISP (we cannot use event as it
        # does not contain the sample uploaded above, nor it is
        # a MISPEvent but a simple dict)
        e = MISPEvent()
        e.from_dict(Event=self.misp.get_event(event["Event"]["id"])["Event"])
        dropped_files = {
                f.get_attributes_by_relation("sha1")[0].value: f
                for f in e.objects if f["name"] == "file"
        }

        # Add further details on the dropped files
        for entry in results.get("dropped", []):
            # Find the corresponding object
            sha1 = entry.get("sha1")
            obj = dropped_files[sha1]

            # Add the real location of the dropped file (during the analysis)
            real_filepath = entry.get("guest_paths")
            obj.add_attribute("fullpath", real_filepath[0])

            # Add Yara matches if any
            for match in entry.get("yara", []):
                desc = match["meta"]["description"]
                obj.add_attribute("text", value=desc, comment="Yara match")

        # Update the event
        self.misp.update_event(event_id=event["Event"]["id"], event=e)
        """

    def run(self, results):
        """Run analysis.
        @return: MISP results dict.
        """

        url = self.options.get("url", "")
        apikey = self.options.get("apikey", "")

        if not url or not apikey:
            log.error("MISP URL or API key not configured.")
            return

        self.misp = PyMISP(url, apikey, False, "json")

        self.threads = self.options.get("threads", "")
        if not self.threads:
            self.threads = 5

        self.iocs = deque()
        self.misper = dict()

        try:
            if self.options.get("upload_iocs", False) and results.get("malscore", 0) >= self.options.get("min_malscore", 0):
                distribution = int(self.options.get("distribution", 0))
                threat_level_id = int(self.options.get("threat_level_id", 4))
                analysis = int(self.options.get("analysis", 0))
                tag = self.options.get("tag") or "CAPEv2"
                info = self.options.get("title", "")
                upload_sample = self.options.get("upload_sample")

                malfamily = ""
                if results.get("detections", ""):
                    malfamily = results["detections"]

                response = self.misp.search("attributes", value=results["target"]["file"]["sha256"], return_format="json", pythonify=True)
                if response:
                    event = self.misp.get_event(response[0].event_id, pythonify=True)
                else:
                    event = MISPEvent()
                    event.distribution = distribution
                    event.threat_level_id = threat_level_id
                    event.analysis = analysis
                    event.info = "{} {} - {}".format(info, malfamily, results.get("info", {}).get("id"))
                    event = self.misp.add_event(event, pythonify=True)

                # Add a specific tag to flag Cuckoo's event
                if tag:
                    self.misp.tag(event, tag)

                # malpedia galaxy
                if malpedia_json:
                    self.malpedia(results, event, malfamily)

                # ToDo?
                self.signature(results, event)

                self.sample_hashes(results, event)
                self.all_network(results, event)
                self.dropped_files(results, event)

                if upload_sample:
                    target = results.get("target", {})
                    f = target.get("file", {})
                    if target.get("category") == "file" and f:
                        with open(f["path"], "rb") as f:
                            event.add_attribute(
                                "malware-sample",
                                value=os.path.basename(f["path"]),
                                data=BytesIO(f.read()),
                                expand="binary",
                                comment="Sample run",
                            )

                if results.get("target", {}).get("url", "") and results["target"]["url"] not in whitelist:
                    event.add_attribute("url", results["target"]["url"])

                # ToDo migth be outdated!
                # if self.options.get("ids_files", False) and "suricata" in results.keys():
                #    for surifile in results["suricata"]["files"]:
                #        if "file_info" in surifile.keys():
                #            self.misper["iocs"].append({"md5": surifile["file_info"]["md5"]})
                #            self.misper["iocs"].append({"sha1": surifile["file_info"]["sha1"]})
                #            self.misper["iocs"].append({"sha256": surifile["file_info"]["sha256"]})

                if self.options.get("mutexes", False) and "behavior" in results and "summary" in results["behavior"]:
                    if "mutexes" in results.get("behavior", {}).get("summary", {}):
                        for mutex in results["behavior"]["summary"]["mutexes"]:
                            if mutex not in whitelist:
                                event.add_attribute("mutex", mutex)

                if self.options.get("registry", False) and "behavior" in results and "summary" in results["behavior"]:
                    if "read_keys" in results["behavior"].get("summary", {}):
                        for regkey in results["behavior"]["summary"]["read_keys"]:
                            event.add_attribute("regkey", regkey)

                event.run_expansions()
                self.misp.update_event(event)

                # Make event public
                if self.options.get("published", True):
                    self.misp.publish(event)

        except Exception as e:
            log.error("Failed to generate JSON report: %s" % e, exc_info=True)
