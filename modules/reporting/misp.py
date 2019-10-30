# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
  (1,"High","*high* means sophisticated APT malware or 0-day attack","Sophisticated APT malware or 0-day attack"),
  (2,"Medium","*medium* means APT malware","APT malware"),
  (3,"Low","*low* means mass-malware","Mass-malware"),
  (4,"Undefined","*undefined* no risk","No risk");
"""

import os
import json
import logging
import threading
from collections import deque
from datetime import datetime
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT

PYMISP = False
try:
    from pymisp import PyMISP
    PYMISP = True
except ImportError:
    pass

log = logging.getLogger(__name__)

class MISP(Report):
    """MISP Analyzer."""

    order = 1

    def cuckoo2misp_thread(self, iocs, event):

        while iocs:

            ioc = iocs.pop()
            if ioc.get("md5"):
                self.misp.add_hashes(event,
                                 md5=ioc["md5"],
                                 sha1=ioc["sha1"],
                                 sha256=ioc["sha256"]
                )
            elif ioc.get("domain", ""):
                self.misp.add_domain(event, ioc["domain"])
            elif ioc.get("ip", ""):
                self.misp.add_ipdst(event, ioc["ip"])
            elif ioc.get("uri", ""):
                self.misp.add_url(event, ioc["uri"])
            elif ioc.get("ua", ""):
                self.misp.add_useragent(event, ioc["ua"])
            elif ioc.get("mutex", ""):
                self.misp.add_mutex(event, ioc["mutex"])
            elif ioc.get("regkey", ""):
                self.misp.add_regkey(event, ioc["regkey"])

    def cuckoo2misp(self, results, whitelist):

        distribution = int(self.options.get("distribution", 0))
        threat_level_id = int(self.options.get("threat_level_id", 2))
        analysis = int(self.options.get("analysis", 2))

        iocs = deque()
        malfamily = ""
        filtered_iocs = deque()
        threads_list = list()

        if results.get("malfamily", ""):
            malfamily = " - {}".format(results["malfamily"])

        comment = "{} {}{}".format(self.options.get("title", ""), results.get('info', {}).get('id'), malfamily)


        if results.get("target", {}).get("url", "") and results["target"]["url"] not in whitelist:
            iocs.append({"uri": results["target"]["url"]})
            filtered_iocs.append(results["target"]["url"])

        if self.options.get("network", False) and "network" in results.keys():
            for block in results["network"].get("hosts", []):
                if block.get("hostname", "") and (block["hostname"] not in whitelist and block["hostname"] not in filtered_iocs):
                    iocs.append({"domain": block["hostname"]})
                    filtered_iocs.append(block["hostname"])
                if block.get("ip", "") and (block["ip"] not in whitelist and block["ip"] not in filtered_iocs):
                    iocs.append({"ip": block["ip"]})
                    filtered_iocs.append(block["ip"])

            for req in results["network"].get("http", []):
                if "uri" in req and req["uri"] not in whitelist:
                    if req["uri"] not in filtered_iocs:
                        iocs.append({"uri": req["uri"]})
                        filtered_iocs.append(req["uri"])
                    if "user-agent" in req and req["user-agent"] not in filtered_iocs:
                        iocs.append({"ua": req["user-agent"]})
                        filtered_iocs.append(req["user-agent"])

            for block in results["network"].get("dns", []): #Added DNS
                if block.get("request", "") and (block["request"] not in whitelist and block["request"] not in filtered_iocs):
                    iocs.append({"domain": block["request"]})
                    filtered_iocs.append(block["request"])

            for i in range(0,len(results["CAPE"])): #Added CAPE Addresses
                for section in results["CAPE"][i]:
                    try:
                        if(results["CAPE"][i]["cape_config"]["address"]):
                            for ip in results["CAPE"][i]["cape_config"]["address"]:
                                iocs.append({"ip": ip.split(":")[0]})
                    except:
                        pass

        if self.options.get("ids_files", False) and "suricata" in results.keys():
            for surifile in results["suricata"]["files"]:
                if "file_info" in surifile.keys():
                    iocs.append({"md5": surifile["file_info"]["md5"],
                                "sha1": surifile["file_info"]["sha1"],
                                "sha256": surifile["file_info"]["sha256"]
                    })

        if self.options.get("mutexes", False) and "behavior" in results and "summary" in results["behavior"]:
            if "mutexes" in results.get("behavior", {}).get("summary", {}):
                for mutex in results["behavior"]["summary"]["mutexes"]:
                    if mutex not in whitelist and mutex not in filtered_iocs:
                        iocs.append({"mutex": mutex})
                        filtered_iocs.append(mutex)

        if self.options.get("dropped", False) and "dropped" in results:
            for entry in results["dropped"]:
                if entry["md5"] and (entry["md5"] not in filtered_iocs and entry["md5"] not in whitelist):
                    filtered_iocs.append(entry["md5"])
                    iocs.append({"md5": entry["md5"],
                                "sha1": entry["sha1"],
                                "sha256": entry["sha256"]
                    })

        if self.options.get("registry", False) and "behavior" in results and "summary" in results["behavior"]:
            if "read_keys" in results["behavior"].get("summary", {}):
                for regkey in results["behavior"]["summary"]["read_keys"]:
                    if regkey not in whitelist and regkey not in filtered_iocs:
                        iocs.append({"regkey": regkey})
                        filtered_iocs.append(regkey)

        if iocs and "Malicious" not in malfamily and results["ttps"]:
            response = self.misp.search_all(results.get('target').get('file').get('sha256'))

            if (len(response["response"])>0):
                    event = response["response"][0]
            else:
                    event = self.misp.new_event(0,4,0,"[Malware] " + malfamily)
            self.misp.tag(event["Event"]["uuid"], ''.join(e for e in malfamily if e.isalnum()).replace("-",""))

            for ttp in results["ttps"]: #Added TTPs
                with open(os.path.join(CUCKOO_ROOT, 'data', 'mitre_attack.json')) as json_file:
                     data = json.load(json_file)
                     for i in data["objects"]:
                         try:
                             if (i["external_references"][0]["external_id"] == ttp):
                                 self.misp.tag(event["Event"]["uuid"],'misp-galaxy:mitre-attack-pattern="'+i["name"]+' - '+ttp+'"')
                         except:
                             pass

            # Add Payload delivery hash about the details of the analyzed file
            self.misp.add_hashes(event, category='Payload delivery',
                                        filename=results.get('target').get('file').get('name'),
                                        md5=results.get('target').get('file').get('md5'),
                                        sha1=results.get('target').get('file').get('sha1'),
                                        sha256=results.get('target').get('file').get('sha256'),
                                        ssdeep=results.get('target').get('file').get('ssdeep'),
                                        comment='File: {} uploaded to cuckoo'.format(results.get('target').get('file').get('name')))

            for thread_id in xrange(int(self.threads)):
                thread = threading.Thread(target=self.cuckoo2misp_thread, args=(iocs, event))
                thread.daemon = True
                thread.start()

                threads_list.append(thread)

            for thread in threads_list:
                thread.join()

    def misper_thread(self, url):
        while self.iocs:
            ioc = self.iocs.pop()
            try:
                response = self.misp.search_all(ioc)
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

            self.misp = PyMISP(url, apikey, False, "json")

            if self.options.get("extend_context", ""):
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
            log.error("Failed to generate JSON report: %s" % e)


