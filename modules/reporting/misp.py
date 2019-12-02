# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
  (1,"High","*high* means sophisticated APT malware or 0-day attack","Sophisticated APT malware or 0-day attack"),
  (2,"Medium","*medium* means APT malware","APT malware"),
  (3,"Low","*low* means mass-malware","Mass-malware"),
  (4,"Undefined","*undefined* no risk","No risk");
"""

#Updated by doomedraven 30.11.2019 for NaxoneZ

import os
import logging
from io import BytesIO
from collections import deque
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from urllib.parse import urlsplit

try:
    import pymisp
    from pymisp import MISPEvent, MISPAttribute
    HAVE_PYMISP = True
except ImportError:
    HAVE_PYMISP = True
    print("pip3 install pymisp")

log = logging.getLogger(__name__)
logging.getLogger('pymisp').setLevel(logging.WARNING)

class MISP(Report):
    """MISP Analyzer."""

    order = 1

    #DeprecationWarning: Call to deprecated method add_hashes. (Use ExpandedPyMISP.add_attribute and MISPAttribute)
    def sample_hashes(self, results, event):
        if results.get("target", {}).get("file", {}):
            f = results["target"]["file"]
            """
            file_data = MISPAttribute()
            file_data.md5 = f["md5"]
            file_data.sha1 = f["sha1"]
            file_data.sha256 = f["sha256"]
            file_data.filename = f["name"]
            file_data.comment = "File submitted to CAPEv2"
            self.misp.add_attribute(event, file_data)
            #file_data.add_attribute('sha1', value=f["sha1"], comment="File submitted to CAPEv2")
            #file_data.add_attribute('sha256', value=f["sha256"], comment="File submitted to CAPEv2")
            """
            self.misp.add_hashes(
                event,
                category="Payload delivery",
                filename=f["name"],
                md5=f["md5"],
                sha1=f["sha1"],
                sha256=f["sha256"],
                comment="File submitted to CAPEv2",
            )
            #"""

        #return event

    def all_network(self, results, event, whitelist):
        """All of the accessed URLS as per the PCAP."""
        urls = set()
        if self.options.get("network", False) and "network" in results.keys():
            urls = set()
            for req in results["network"].get("http", []):
                if "uri" in req and req["uri"] not in whitelist:
                    urls.add(req["uri"])
                if "user-agent" in req:
                    #self.misp.add_useragent(event, req["user-agent"])
                    self.misp.add_named_attribute(event, 'user-agent', req["user-agent"])#, category, to_ids, comment, distribution, proposal, **kwargs)

            domains, ips = {}, set()
            for domain in results.get("network", {}).get("domains", []):
                if domain["domain"] not in whitelist and domain["ip"] not in whitelist:
                    domains[domain["domain"]] = domain["ip"]
                    ips.add(domain["ip"])

            for block in results.get("network", {}).get("hosts", []):
                ips.add(block["ip"])

            for block in results["network"].get("dns", []): #Added DNS
                if block.get("request", "") and (block["request"] not in whitelist):
                    if block["request"] not in domains and block["request"] not in whitelist:
                        if block["answers"]:
                            domains[block["request"]] = block["answers"][0]["data"]
                            ips.add(domain[block["answers"][0]["data"]])

            #Added CAPE Addresses
            for section in results.get("CAPE", []) or []:
                try:
                    if section.get("cape_config", {}).get("address", []) or []:
                        for ip in section["cape_config"]["address"]:
                            if ip not in ips:
                                ips.add(ip)
                except Exception as e:
                    print(e)

            if urls:
                self.misp.add_named_attribute(event, 'url', sorted(list(urls)))
            if domains:
                self.misp.add_domains_ips(event, domains)
            if ips:
                self.misp.add_named_attribute(event, 'ip-dst', sorted(list(ips)))#, category, to_ids, comment, distribution, proposal, **kwargs)

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
        # Upload all the dropped files at once
        for r in results.get("dropped", []) or []:
            with open(r.get("path"), 'rb') as f:
                event.add_attribute('malware-sample', value=os.path.basename(r.get("path")), data=BytesIO(f.read()), expand='binary')
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

        self.misp = pymisp.ExpandedPyMISP(url, apikey, False, "json")

        self.threads = self.options.get("threads", "")
        if not self.threads:
            self.threads = 5

        whitelist = list()
        self.iocs = deque()
        self.misper = dict()

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
                if results.get("malfamily", ""):
                    malfamily = results["malfamily"]

                event = MISPEvent()
                event.distribution = distribution
                event.threat_level_id = threat_level_id
                event.analysis = analysis
                event.info = "{} {} - {}".format(info, malfamily, results.get('info', {}).get('id'))
                event = self.misp.add_event(event, pythonify=True)

                # Add a specific tag to flag Cuckoo's event
                if tag:
                    self.misp.tag(event["uuid"], tag)


                #ToDo?
                #self.signature(results, event)

                self.sample_hashes(results, event)
                self.all_network(results, event, whitelist)
                self.dropped_files(results, event, whitelist)

                #DeprecationWarning: Call to deprecated method upload_samplelist. (Use MISPEvent.add_attribute with the expand='binary' key)
                if upload_sample:
                    target = results.get("target", {})
                    f = target.get("file", {})
                    if target.get("category") == "file" and f:
                        with open(f["path"], 'rb') as f:
                            event.add_attribute('malware-sample', value=os.path.basename(f["path"]), data=BytesIO(f.read()), expand='binary', comment="Sample run",)

                if results.get("target", {}).get("url", "") and results["target"]["url"] not in whitelist:
                    self.misp.add_named_attribute(event, 'url', [results["target"]["url"]])

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
