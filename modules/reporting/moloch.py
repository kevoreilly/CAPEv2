# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import copy
import json
import logging
import os
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Tuple

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.abstracts import Report

log = logging.getLogger(__name__)


class Moloch(Report):

    """Moloch processing."""

    def cmd_wrapper(self, cmd) -> Tuple[int, bytes, bytes]:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = p.communicate()
        return (p.returncode, stdout, stderr)

    # This was useful http://blog.alejandronolla.com/2013/04/06/moloch-capturing-and-indexing-network-traffic-in-realtime/
    def update_tags(self, tags, expression):
        # support cases where we might be doing basic auth through a proxy
        if self.MOLOCH_AUTH == "basic":
            auth_handler = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            auth_handler.add_password(None, self.MOLOCH_URL, self.MOLOCH_USER, self.MOLOCH_PASSWORD)
            handler = urllib.request.HTTPBasicAuthHandler(auth_handler)
            opener = urllib.request.build_opener(handler)
        else:
            auth_handler = urllib.request.HTTPDigestAuthHandler()
            auth_handler.add_password(self.MOLOCH_REALM, self.MOLOCH_URL, self.MOLOCH_USER, self.MOLOCH_PASSWORD)
            opener = urllib.request.build_opener(auth_handler)

        data = urllib.parse.urlencode({"tags": tags})
        qstring = urllib.parse.urlencode({"date": "-1", "expression": expression})
        TAG_URL = f"{self.MOLOCH_URL}addTags?{qstring}"
        try:
            response = opener.open(TAG_URL, data=data)
            if response.code == 200:
                plain_answer = response.read()
                json.loads(plain_answer)
        except Exception as e:
            log.warning("Moloch: Unable to update tags %s", e)

    def run(self, results):
        """Run Moloch to import pcap
        @return: nothing
        """
        self.key = "moloch"
        self.alerthash = {}
        self.fileshash = {}
        self.MOLOCH_CAPTURE_BIN = self.options.get("capture")
        self.MOLOCH_CAPTURE_CONF = self.options.get("captureconf")
        self.CUCKOO_INSTANCE_TAG = self.options.get("node")
        self.MOLOCH_USER = self.options.get("user")
        self.MOLOCH_PASSWORD = self.options.get("pass")
        self.MOLOCH_REALM = self.options.get("realm")
        self.MOLOCH_AUTH = self.options.get("auth", "digest")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        self.MOLOCH_URL = self.options.get("base")
        self.task_id = results["info"]["id"]
        self.custom = None
        if "name" in results["info"].get("machine", {}):
            self.machine_name = re.sub(r"[\W]", "_", str(results["info"]["machine"]["name"]))
        else:
            self.machine_name = "Unknown"
        self.gateway = "Default"

        if "options" in results["info"] and "custom" in results["info"]:
            self.custom = re.sub(r"[\W]", "_", str(results["info"]["custom"]))

        if not os.path.exists(self.MOLOCH_CAPTURE_BIN):
            log.warning("Unable to Run moloch-capture: BIN File %s Does Not Exist", self.MOLOCH_CAPTURE_BIN)
            return

        if not os.path.exists(self.MOLOCH_CAPTURE_CONF):
            log.warning("Unable to Run moloch-capture Conf File %s Does Not Exist", self.MOLOCH_CAPTURE_CONF)
            return
        try:
            cmd = f"{self.MOLOCH_CAPTURE_BIN} -c {self.MOLOCH_CAPTURE_CONF} -r {self.pcap_path} -n {self.CUCKOO_INSTANCE_TAG} -t {self.CUCKOO_INSTANCE_TAG}:{self.task_id} -t cuckoo_jtype:{self.task['category']} -t cuckoo_machine:{self.machine_name} -t cuckoo_gw:{self.gateway}"
            if self.custom:
                cmd += f" -t custom:{self.custom}"
        except Exception as e:
            log.warning("Unable to Build Basic Moloch CMD: %s", e)

        if self.task["category"] == "file":
            try:
                for key in results.get("virustotal", {}).get("scans", {}):
                    if results["virustotal"]["scans"][key]["result"]:
                        cmd += f' -t "VT:{key}:{results["virustotal"]["scans"][key]["result"]}"'
            except Exception as e:
                log.warning("Unable to Get VT Results For Moloch: %s", e)

            if results["target"]["file"].get("md5"):
                cmd += f' -t "md5:{results["target"]["file"]["md5"]}"'
            if results["target"]["file"].get("sha256"):
                cmd += f' -t "sha256:{results["target"]["file"]["sha256"]}"'
            if results["target"]["file"].get("clamav"):
                cmd += ' -t "clamav:{}"'.format(re.sub(r"[\W]", "_", results["target"]["file"]["clamav"]))
            if results.get("static", {}).get("pe_imphash", {}):
                cmd += f' -t "pehash:{results["static"]["pe_imphash"]}"'
            for entry in results["target"]["file"].get("yara", {}):
                cmd += f' -t "yara:{entry["name"]}"'
        for entry in results.get("signatures", {}):
            cmd += ' -t "cuckoosig:{}:{}"'.format(
                re.sub(r"[\W]", "_", str(entry["name"])), re.sub(r"[\W]", "_", str(entry["severity"]))
            )
        try:
            log.debug("moloch: running import command %s", cmd)
            ret, _, stderr = self.cmd_wrapper(cmd)
            if ret == 0:
                log.debug("moloch: imported pcap %s", self.pcap_path)
            else:
                log.warning("moloch-capture returned an exit value other than zero: %s", stderr)
        except Exception as e:
            log.warning("Unable to Run moloch-capture: %s", e)

        time.sleep(1)

        if "suricata" in results and results["suricata"]:
            if "alerts" in results["suricata"]:
                for alert in results["suricata"]["alerts"]:
                    proto = alert["protocol"]
                    if proto:
                        if proto in {"UDP", "TCP", "6", "17"}:
                            tmpdict = {
                                "srcip": alert["srcip"],
                                "srcport": alert["srcport"],
                                "dstip": alert["dstip"],
                                "dstport": alert["dstport"],
                            }
                            if proto in {"UDP", "17"}:
                                tmpdict["cproto"] = "udp"
                                tmpdict["nproto"] = 17
                            else:
                                tmpdict["cproto"] = "tcp"
                                tmpdict["nproto"] = 6
                            tmpdict[
                                "expression"
                            ] = f'ip=={tmpdict["srcip"]} && ip=={tmpdict["dstip"]} && port=={tmpdict["srcport"]} && port=={tmpdict["dstport"]} && tags=="{self.CUCKOO_INSTANCE_TAG}:{self.task_id}" && ip.protocol=={tmpdict["cproto"]}'
                            tmpdict["hash"] = (
                                tmpdict["nproto"]
                                + struct.unpack("!L", socket.inet_aton(tmpdict["srcip"]))[0]
                                + tmpdict["srcport"]
                                + struct.unpack("!L", socket.inet_aton(tmpdict["dstip"]))[0]
                                + tmpdict["dstport"]
                            )
                        elif proto in {"ICMP", "1"}:
                            tmpdict = {
                                "srcip": alert["srcip"],
                                "dstip": alert["dstip"],
                                "cproto": "icmp",
                                "nproto": 1,
                                "expression": f'ip=={alert["srcip"]} && ip=={alert["dstip"]} && tags=="{self.CUCKOO_INSTANCE_TAG}:{self.task_id}" && ip.protocol==icmp',
                                "hash": 1
                                + struct.unpack("!L", socket.inet_aton(alert["srcip"]))[0]
                                + struct.unpack("!L", socket.inet_aton(alert["dstip"]))[0],
                            }
                        if alert["sid"] not in self.alerthash.get(tmpdict["hash"], {}).get("sids", []):
                            self.alerthash.setdefault(tmpdict["hash"], copy.deepcopy(tmpdict)).setdefault("sids", []).append(
                                f"suri_sid:{alert['sid']}"
                            )
                            self.alerthash[tmpdict["hash"]].setdefault("msgs", []).append(
                                "suri_msg:{}".format(re.sub(r"[\W]", "_", alert["signature"]))
                            )
                for entry in self.alerthash:
                    tags = ",".join(map(str, self.alerthash[entry]["sids"] + self.alerthash[entry]["msgs"]))
                    if tags:
                        log.debug("moloch: updating alert tags %s", self.alerthash[entry]["expression"])
                        self.update_tags(tags, self.alerthash[entry]["expression"])

            if "files" in results["suricata"]:
                for entry in results["suricata"]["files"]:
                    if "file_info" in entry:
                        proto = entry["protocol"]
                        if proto:
                            tmpdict = {
                                "cproto": "tcp",
                                "nproto": 6,
                                "srcip": entry["srcip"],
                                "srcport": entry["sp"],
                                "dstip": entry["dstip"],
                                "dstport": entry["dp"],
                                "expression": f'ip=={entry["srcip"]} && ip=={entry["dstip"]} && port=={entry["sp"]} && port=={entry["dp"]} && tags=="{self.CUCKOO_INSTANCE_TAG}:{self.task_id}" && ip.protocol==tcp',
                                "hash": 6
                                + struct.unpack("!L", socket.inet_aton(entry["srcip"]))[0]
                                + entry["sp"]
                                + struct.unpack("!L", socket.inet_aton(entry["dstip"]))[0]
                                + entry["dp"],
                            }
                            if tmpdict["hash"] not in self.fileshash:
                                self.fileshash[tmpdict["hash"]] = copy.deepcopy(tmpdict)
                                self.fileshash[tmpdict["hash"]]["clamav"] = []
                                self.fileshash[tmpdict["hash"]]["md5"] = []
                                self.fileshash[tmpdict["hash"]]["sha256"] = []
                                self.fileshash[tmpdict["hash"]]["yara"] = []
                            if (
                                entry["file_info"]["clamav"]
                                and entry["file_info"]["clamav"] not in self.fileshash[tmpdict["hash"]]["clamav"]
                            ):
                                self.fileshash[tmpdict["hash"]]["clamav"].append(
                                    "clamav:{}".format(re.sub(r"[\W]", "_", entry["file_info"]["clamav"]))
                                )
                            if (
                                entry["file_info"]["md5"]
                                and entry["file_info"]["md5"] not in self.fileshash[tmpdict["hash"]]["md5"]
                            ):
                                self.fileshash[tmpdict["hash"]]["md5"].append(f"md5:{entry['file_info']['md5']}")
                            if (
                                entry["file_info"]["sha256"]
                                and entry["file_info"]["sha256"] not in self.fileshash[tmpdict["hash"]]["sha256"]
                            ):
                                self.fileshash[tmpdict["hash"]]["sha256"].append(f"sha256:{entry['file_info']['sha256']}")
                            for sign in entry["file_info"]["yara"]:
                                if sign["name"] not in self.fileshash[tmpdict["hash"]]["yara"]:
                                    self.fileshash[tmpdict["hash"]]["yara"].append(f"yara:{sign['name']}")

                for entry in self.fileshash:
                    tags = ",".join(
                        map(
                            str,
                            self.fileshash[entry]["clamav"]
                            + self.fileshash[entry]["md5"]
                            + self.fileshash[entry]["sha256"]
                            + self.fileshash[entry]["yara"],
                        )
                    )
                    if tags:
                        log.debug("moloch: updating file tags %s", self.fileshash[entry]["expression"])
                        self.update_tags(tags, self.fileshash[entry]["expression"])
        return {}
