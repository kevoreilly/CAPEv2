# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
  (1,"High","*high* means sophisticated APT malware or 0-day attack","Sophisticated APT malware or 0-day attack"),
  (2,"Medium","*medium* means APT malware","APT malware"),
  (3,"Low","*low* means mass-malware","Mass-malware"),
  (4,"Undefined","*undefined* no risk","No risk");
"""

#Updated by doomedraven 22.11.2019 for NaxoneZ
#But due to frequent updates on misp server/api/client, im not maintaining it
#You need it you fix it!

import os
import logging
import warnings
import threading
from collections import deque
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from urlparse import urlsplit

log = logging.getLogger(__name__)

class MISP(Report):
    """MISP Analyzer."""

    order = 1

    def sample_hashes(self, results, event):
        if results.get("target", {}).get("file", {}):
            f = results["target"]["file"]
            self.misp.add_hashes(
                event,
                category="Payload delivery",
                filename=f["name"],
                md5=f["md5"],
                sha1=f["sha1"],
                sha256=f["sha256"],
                comment="File submitted to CAPEv2",
            )

    def all_network(self, results, event, whitelist):
        """All of the accessed URLS as per the PCAP."""
        urls = set()
        if self.options.get("network", False) and "network" in results.keys():
            urls = set()
            for req in results["network"].get("http", []):
                if "uri" in req and req["uri"] not in whitelist:
                    urls.add(req["uri"])
                if "user-agent" in req:
                    self.misp.add_useragent(event, req["user-agent"])

            domains, ips = {}, set()
            for domain in results.get("network", {}).get("domains", []):
                if domain["domain"] not in whitelist and domain["ip"] not in whitelist:
                    domains[domain["domain"]] = domain["ip"]
                    ips.add(domain["ip"])

            for block in results.get("network", {}).get("hosts", []):
                ips.add(block["ip"])

            for block in results["network"].get("dns", []): #Added DNS
                if block.get("request", "") and (block["request"] not in whitelist):# and block["request"] not in filtered_iocs):
                    #filtered_iocs.append(block["request"])
                    #self.misper["iocs"].append({"domain": block["request"]})
                    if block["request"] not in domains and block["request"] not in whitelist:
                        if block["answers"]:
                            domains[block["request"]] = block["answers"][0]["data"]
                            ips.add(domain[block["answers"][0]["data"]])

            for i in range(0, len(results["CAPE"])): #Added CAPE Addresses
                for section in results["CAPE"][i]:
                    try:
                        if results["CAPE"][i].get("cape_config", {}).get("address", []) or []:
                            for ip in results["CAPE"][i]["cape_config"]["address"]:
                                if ip not in ips:
                                    ips.add(ip)
                    except Exception as e:
                        print(e)

            if urls:
                self.misp.add_url(event, sorted(list(urls)))
            if domains:
                self.misp.add_domains_ips(event, domains)
            if ips:
                self.misp.add_ipdst(event, sorted(list(ips)))

    def dropped_files(self, results, event, whitelist):
        if self.options.get("dropped", False) and "dropped" in results:
            for entry in results["dropped"]:
                if entry["md5"] and  entry["md5"] not in whitelist:
                    self.misper["iocs"].append({"md5": entry["md5"]})
                    self.misper["iocs"].append({"sha1": entry["sha1"]})
                    self.misper["iocs"].append({"sha256": entry["sha256"]})

        """
        Add all the dropped files as MISP attributes.
        """
        from pymisp import MISPEvent

        # Upload all the dropped files at once
        filepaths = [r.get("path") for r in results.get("dropped", [])]
        if not filepaths:
            return

        try:
            self.misp.upload_samplelist(
                    filepaths=filepaths,
                    event_id=event["Event"]["id"],
                    category="Artifacts dropped",
                    comment="Dropped file",
            )
        except:
            log.error(
                "Couldn't upload the dropped file, maybe "
                "the max upload size has been reached."
            )
            return False

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


    def run(self, results):
        """Run analysis.
        @return: MISP results dict.
        """

        url = self.options.get("url", "")
        apikey = self.options.get("apikey", "")

        if not url or not apikey:
            log.error("MISP URL or API key not configured.")
            return

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            import pymisp

        self.misp = pymisp.PyMISP(url, apikey, False, "json")

        self.threads = self.options.get("threads", "")
        if not self.threads:
            self.threads = 5

        whitelist = list()
        self.iocs = deque()
        self.misper = dict()
        self.misp_full_report = dict()
        self.lock = threading.Lock()

        try:
            # load whitelist if exists
            if os.path.exists(os.path.join(CUCKOO_ROOT, "conf", "misp.conf")):
                whitelist = Config("misp").whitelist.whitelist
                if whitelist:
                    whitelist = [ioc.strip() for ioc in whitelist.split(",")]

            if self.options.get("upload_iocs", False) and results.get("malscore", 0) >= self.options.get("min_malscore", 0):
                distribution = int(self.options.get("distribution", 0))
                threat_level_id = int(self.options.get("threat_level_id", 4))
                analysis = int(self.options.get("analysis", 0))
                tag = self.options.get("tag") or "CAPEv2"
                info = self.options.get("title", "")
                upload_sample = self.options.get("upload_sample")

                malfamily = ""
                filtered_iocs = deque()
                if results.get("malfamily", ""):
                    malfamily = results["malfamily"]

                event = self.misp.new_event(
                    distribution=distribution,
                    threat_level_id=threat_level_id,
                    analysis=analysis,
                    info="{} {} - {}".format(info, malfamily, results.get('info', {}).get('id'))
                )

                # Add a specific tag to flag Cuckoo's event
                if tag:
                    mispresult = self.misp.tag(event["Event"]["uuid"], tag)
                    if mispresult.has_key("message"):
                        log.debug("tag event: %s" % mispresult["message"])


                #ToDo?
                #self.signature(results, event)

                self.sample_hashes(results, event)
                self.all_network(results, event, whitelist)
                self.dropped_files(results, event, whitelist)


                #ToDo add? upload sample
                """
                if upload_sample:
                    target = results.get("target", {})
                    f = target.get("file", {})
                    if target.get("category") == "file" and f:
                        self.misp.upload_sample(
                            filename=os.path.basename(f["name"]),
                            filepath_or_bytes=f["path"],
                            event_id=event["Event"]["id"],
                            category="Payload delivery",
                            comment="Sample run",
                        )
                """
                self.misper.setdefault("iocs", list())

                #if results.get("target", {}).get("url", "") and results["target"]["url"] not in whitelist:
                #    filtered_iocs.append(results["target"]["url"])
                #    #parsed = urlsplit(results["target"]["url"])

                # ToDo migth be outdated!
                #if self.options.get("ids_files", False) and "suricata" in results.keys():
                #    for surifile in results["suricata"]["files"]:
                #        if "file_info" in surifile.keys():
                #            self.misper["iocs"].append({"md5": surifile["file_info"]["md5"]})
                #            self.misper["iocs"].append({"sha1": surifile["file_info"]["sha1"]})
                #            self.misper["iocs"].append({"sha256": surifile["file_info"]["sha256"]})

                if self.options.get("mutexes", False) and "behavior" in results and "summary" in results["behavior"]:
                    if "mutexes" in results.get("behavior", {}).get("summary", {}):
                        for mutex in results["behavior"]["summary"]["mutexes"]:
                            if mutex not in whitelist:
                               self.misp.add_mutex(event, mutex)

                if self.options.get("registry", False) and "behavior" in results and "summary" in results["behavior"]:
                    if "read_keys" in results["behavior"].get("summary", {}):
                        for regkey in results["behavior"]["summary"]["read_keys"]:
                            self.misp.add_regkey(event, regkey)

        except Exception as e:
            log.error("Failed to generate JSON report: %s" % e, exc_info=True)
