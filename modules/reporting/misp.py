# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
  (1,"High","*high* means sophisticated APT malware or 0-day attack","Sophisticated APT malware or 0-day attack"),
  (2,"Medium","*medium* means APT malware","APT malware"),
  (3,"Low","*low* means mass-malware","Mass-malware"),
  (4,"Undefined","*undefined* no risk","No risk");
"""

#partially updated by doomedraven 22.11.2019 for NaxoneZ
#But due to frequent updates on misp server/api/client, im not maintaining it
#You need it you fix it!
#MISP server 2.4.118
#PyMISP 2.4.117.2

import os
import json
import logging
import threading
from collections import deque
from datetime import datetime
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from urllib.parse import urlsplit



PYMISP = False
try:
    from pymisp import ExpandedPyMISP, MISPObject, MISPEvent
    PYMISP = True
except ImportError:
    pass

log = logging.getLogger(__name__)

class MISP(Report):
    """MISP Analyzer."""

    order = 1

    def cuckoo2misp(self, results, whitelist):

        distribution = int(self.options.get("distribution", 0))
        threat_level_id = int(self.options.get("threat_level_id", 2))
        analysis = int(self.options.get("analysis", 2))

        malfamily = ""
        filtered_iocs = deque()
        threads_list = list()

        misp_objects = []

        if results.get("malfamily", ""):
            malfamily = results["malfamily"]

        cuckoo_id = results.get('info', {}).get('id')
        info = self.options.get("title", "")
        comment = f"{info}"

        if results.get("target", {}).get("url", "") and results["target"]["url"] not in whitelist:
            filtered_iocs.append(results["target"]["url"])
            parsed = urlsplit(results["target"]["url"])
            url_object = MISPObject(name="url")
            url_object.add_attribute("url", value=parsed.geturl())
            url_object.add_attribute("host", value=parsed.hostname)
            url_object.add_attribute("scheme", value=parsed.scheme)
            url_object.add_attribute("port", value=parsed.port)
            misp_objects.append(url_object)

        if self.options.get("network", False) and "network" in results.keys():
            for block in results["network"].get("hosts", []):
                if block.get("hostname", "") and (block["hostname"] not in whitelist and block["hostname"] not in filtered_iocs):
                    hostname_object = MISPObject(name="hostname")
                    hostname_object.add_attribute("domain", value=block["hostname"])
                    misp_objects.append(hostname_object)
                    filtered_iocs.append(block["hostname"])

                if block.get("ip", "") and (block["ip"] not in whitelist and block["ip"] not in filtered_iocs):
                    filtered_iocs.append(block["ip"])
                    ip_object = MISPObject(name="ip")
                    ip_object.add_attribute("ip", value=block["ip"])
                    misp_objects.append(ip_object)

            for req in results["network"].get("http", []):
                if "uri" in req and req["uri"] not in whitelist:
                    if req["uri"] not in filtered_iocs:
                        filtered_iocs.append(req["uri"])
                        parsed = urlsplit(req["uri"])
                        url_object = MISPObject(name="url")
                        url_object.add_attribute("url", value=parsed.geturl())
                        url_object.add_attribute("host", value=parsed.hostname)
                        url_object.add_attribute("scheme", value=parsed.scheme)
                        url_object.add_attribute("port", value=parsed.port)
                        misp_objects.append(url_object)

                    if "user-agent" in req and req["user-agent"] not in filtered_iocs:
                        filtered_iocs.append(req["user-agent"])
                        url_object = MISPObject(name="user-agent")
                        url_object.add_attribute("ua", value=req["user-agent"])
                        misp_objects.append(url_object)

            for block in results["network"].get("dns", []): #Added DNS
                if block.get("request", "") and (block["request"] not in whitelist and block["request"] not in filtered_iocs):
                    filtered_iocs.append(block["request"])
                    hostname_object = MISPObject(name="domain")
                    hostname_object.add_attribute("domain", value=block["request"])
                    misp_objects.append(hostname_object)
                    filtered_iocs.append(block["request"])

            for i in range(0, len(results["CAPE"])): #Added CAPE Addresses
                for section in results["CAPE"][i]:
                    try:
                        for ip in results.get("CAPE", {}).get(i, {}).get("cape_config", {}).get("address", [])  or []:
                            ip_object = MISPObject(name="ip")
                            ip_object.add_attribute("ip", value=ip.split(":")[0])
                            misp_objects.append(ip_object)
                    except:
                        pass

        # ToDo migth be outdated!
        if self.options.get("ids_files", False) and "suricata" in results.keys():
            for surifile in results["suricata"]["files"]:
                if "file_info" in surifile.keys():
                    file_object = MISPObject(name="Suricata file")
                    file_object.add_attribute("md5", value=surifile["file_info"]["md5"]),
                    file_object.add_attribute("sha1", value=surifile["file_info"]["sha1"]),
                    file_object.add_attribute("sha256", value=surifile["file_info"]["sha256"]),
                    misp_objects.append(file_object)

        if self.options.get("mutexes", False) and "behavior" in results and "summary" in results["behavior"]:
            if "mutexes" in results.get("behavior", {}).get("summary", {}):
                for mutex in results["behavior"]["summary"]["mutexes"]:
                    if mutex not in whitelist and mutex not in filtered_iocs:
                        filtered_iocs.append(mutex)
                        mutex_object = MISPObject(name="Mutex")
                        mutex_object.add_attribute("mutex", value=mutex),
                        misp_objects.append(mutex_object)

        if self.options.get("dropped", False) and "dropped" in results:
            for entry in results["dropped"]:
                if entry["md5"] and (entry["md5"] not in filtered_iocs and entry["md5"] not in whitelist):
                    filtered_iocs.append(entry["md5"])
                    file_object = MISPObject(name="Dropped")
                    file_object.add_attribute("md5", value=entry.get('md5')),
                    file_object.add_attribute("sha1", value=entry.get('sha1')),
                    file_object.add_attribute("sha256", value=entry.get('sha256')),
                    misp_objects.append(file_object)

        if self.options.get("registry", False) and "behavior" in results and "summary" in results["behavior"]:
            if "read_keys" in results["behavior"].get("summary", {}):
                for regkey in results["behavior"]["summary"]["read_keys"]:
                    if regkey not in whitelist and regkey not in filtered_iocs:
                        filtered_iocs.append(regkey)
                        regkey_object = MISPObject(name="Dropped")
                        regkey_object.add_attribute("regkey", value=regkey),
                        misp_objects.append(regkey_object)

        if misp_objects and "Malicious" not in malfamily and results["ttps"]:
            response = self.misp.search("attributes", value=results.get('target').get('file').get('sha256'), return_format="json")

            if response.get("Attribute", []):
                misp_event = self.misp.get_event(response["Attribute"][0]["event_id"])
            else:
                misp_event = self.misp.add_event(distribution, threat_level_id, analysis, comment,  date=datetime.now().strftime('%Y-%m-%d'), published=True)
                event = MISPEvent()
                event.distribution = misp_dict["distribution"]
                event.threat_level_id = misp_dict["threat_level_id"]
                event.analysis = misp_dict["analysis"]
                event.info = misp_dict["comment"]
                event.date = datetime.now()#.strftime('%Y-%m-%d')
                event.published = True
            event_id = response["Attribute"][0]["event_id"]

            self.misp.tag(event["Event"]["uuid"], ''.join(e for e in malfamily if e.isalnum()).replace("-",""))

            for ttp in results["ttps"]: #Added TTPs
                with open(os.path.join(CUCKOO_ROOT, 'data', 'mitre_attack.json')) as json_file:
                     data = json.load(json_file)
                     for i in data["objects"]:
                         try:
                             if i["external_references"][0]["external_id"] == ttp:
                                 self.misp.tag(event["Event"]["uuid"],'misp-galaxy:mitre-attack-pattern="'+i["name"]+' - '+ttp+'"')
                         except Exception as e:
                             pass

            # Add Payload delivery hash about the details of the analyzed file
            file_object = MISPObject(name="Payload delivery")
            file_object.add_attribute("name", value=results.get('target').get('file').get('name')),
            file_object.add_attribute("md5", value=results.get('target').get('file').get('md5')),
            file_object.add_attribute("sha1", value=results.get('target').get('file').get('sha1')),
            file_object.add_attribute("sha256", value=results.get('target').get('file').get('sha256')),
            file_object.add_attribute("ssdeep", value=results.get('target').get('file').get('ssdeep'))
            file_object.add_attribute("comment", value='File: {} uploaded to cuckoo'.format(results.get('target').get('file').get('name')))
            misp_objects.append(file_object)

            for misp_object in misp_objects:
                self.misp.add_object(event_id, misp_object)

    def misper_thread(self, url):
        while self.iocs:
            ioc = self.iocs.pop()
            try:
                response = self.misp.search("attributes", value=ioc, return_format="json")
                if not response or not response.get("response", {}):
                    continue
                self.lock.acquire()
                try:
                    for res in response.get("response", {}):
                        event = res.get("Event", {})

                        self.misp_full_report.setdefault(ioc, list())
                        self.misp_full_report[ioc].append(event)

                        eid = event.get("id", 0)
                        if eid:
                            if eid in self.misper and ioc not in self.misper[eid]["iocs"]:
                                self.misper[eid]["iocs"].append(ioc)
                            else:
                                tmp_misp = dict()
                                tmp_misp.setdefault(eid, dict())
                                date = event.get("date", "")
                                if "iocs" not in tmp_misp[eid]:
                                    tmp_misp[eid].setdefault("iocs", list())
                                tmp_misp[eid]["iocs"].append(ioc)
                                tmp_misp[eid].setdefault("eid", eid)
                                tmp_misp[eid].setdefault("url", os.path.join(url, "events/view/"))
                                tmp_misp[eid].setdefault("date", date)
                                tmp_misp[eid].setdefault("level", event.get("threat_level_id",""))
                                tmp_misp[eid].setdefault("info", event.get("info", "").strip())
                                self.misper.update(tmp_misp)
                finally:
                    self.lock.release()
            except Exception as e:
                log.error(e)

    def run(self, results):
        """Run analysis.
        @return: MISP results dict.
        """

        if not PYMISP:
            log.error("pyMISP dependency is missing.")
            return

        url = self.options.get("url", "")
        apikey = self.options.get("apikey", "")

        if not url or not apikey:
            log.error("MISP URL or API key not configured.")
            return

        self.threads = self.options.get("threads", "")
        if not self.threads:
            self.threads = 5

        whitelist = list()
        self.iocs = deque()
        self.misper = dict()
        threads_list = list()
        self.misp_full_report = dict()
        self.lock = threading.Lock()

        try:
            # load whitelist if exists
            if os.path.exists(os.path.join(CUCKOO_ROOT, "conf", "misp.conf")):
                whitelist = Config("misp").whitelist.whitelist
                if whitelist:
                    whitelist = [ioc.strip() for ioc in whitelist.split(",")]

            self.misp = ExpandedPyMISP(url, apikey, False, "json")
            for drop in results.get("dropped", []):
                if drop.get("md5", "") and drop["md5"] not in self.iocs and drop["md5"] not in whitelist:
                    self.iocs.append(drop["md5"])
            if results.get("target", {}).get("file", {}).get("md5", "") and results["target"]["file"]["md5"] not in whitelist:
                self.iocs.append(results["target"]["file"]["md5"])
            for block in results.get("network", {}).get("hosts", []):
                if block.get("ip", "") and block["ip"] not in self.iocs and block["ip"] not in whitelist:
                    self.iocs.append(block["ip"])
                if block.get("hostname", "") and block["hostname"] not in self.iocs and block["hostname"] not in whitelist:
                    self.iocs.append(block["hostname"])

            if not self.iocs:
                return

            if self.options.get("extend_context", ""):
                for thread_id in xrange(int(self.threads)):
                    thread = threading.Thread(target=self.misper_thread, args=(url,))
                    thread.daemon = True
                    thread.start()

                    threads_list.append(thread)

                for thread in threads_list:
                    thread.join()

                if self.misper:
                    results["misp"] = sorted(self.misper.values(), key=lambda x: datetime.strptime(x["date"], "%Y-%m-%d"), reverse=True)
                    misp_report_path = os.path.join(self.reports_path, "misp.json")
                    full_report = open(misp_report_path, "wb")
                    full_report.write(json.dumps(self.misp_full_report))
                    full_report.close()

            if self.options.get("upload_iocs", False) and results.get("malscore", 0) >= self.options.get("min_malscore", 0):
                self.cuckoo2misp(results, whitelist)

        except Exception as e:
            log.error("Failed to generate JSON report: %s" % e, exc_info=True)
