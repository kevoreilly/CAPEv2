# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import logging
import subprocess
import json
import sys
import urllib.request, urllib.error, urllib.parse
import urllib.request, urllib.parse, urllib.error
import time
import socket
import struct
import copy
import base64
from six.moves import map

try:
    import re2 as re
except ImportError:
    import re

from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.abstracts import Report

log = logging.getLogger(__name__)

class Moloch(Report):

    """Moloch processing."""
    def cmd_wrapper(self,cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout,stderr = p.communicate()
        return (p.returncode, stdout, stderr)

    # This was useful http://blog.alejandronolla.com/2013/04/06/moloch-capturing-and-indexing-network-traffic-in-realtime/
    def update_tags(self,tags,expression):
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

        data = urllib.parse.urlencode({'tags' : tags})
        qstring = urllib.parse.urlencode({'date' : "-1",'expression' : expression})
        TAG_URL = self.MOLOCH_URL + 'addTags?' + qstring
        try:
            response = opener.open(TAG_URL,data=data)
            if response.code == 200:
                plain_answer = response.read()
                json_data = json.loads(plain_answer)
        except Exception as e:
            log.warning("Moloch: Unable to update tags %s" % (e))

    def run(self,results):
        """Run Moloch to import pcap
        @return: nothing
        """
        self.key = "moloch"
        self.alerthash ={}
        self.fileshash ={}
        self.MOLOCH_CAPTURE_BIN = self.options.get("capture", None)
        self.MOLOCH_CAPTURE_CONF = self.options.get("captureconf",None)
        self.CUCKOO_INSTANCE_TAG = self.options.get("node",None)
        self.MOLOCH_USER = self.options.get("user",None)
        self.MOLOCH_PASSWORD = self.options.get("pass",None)
        self.MOLOCH_REALM = self.options.get("realm",None)
        self.MOLOCH_AUTH = self.options.get("auth","digest")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        self.MOLOCH_URL = self.options.get("base",None)
        self.task_id = results["info"]["id"]
        self.custom = None
        if "machine" in results["info"] and results["info"]["machine"] and "name" in results["info"]["machine"]:
            self.machine_name = re.sub(r"[\W]","_",str(results["info"]["machine"]["name"]))
        else:
            self.machine_name = "Unknown"
        self.gateway = "Default"

        if "options" in results["info"] and "custom" in results["info"]:
            self.custom = re.sub(r"[\W]","_",str(results["info"]["custom"]))

        if not os.path.exists(self.MOLOCH_CAPTURE_BIN):
            log.warning("Unable to Run moloch-capture: BIN File %s Does Not Exist" % (self.MOLOCH_CAPTURE_BIN))
            return

        if not os.path.exists(self.MOLOCH_CAPTURE_CONF):
            log.warning("Unable to Run moloch-capture Conf File %s Does Not Exist" % (self.MOLOCH_CAPTURE_CONF))
            return
        try:
            cmd = "%s -c %s -r %s -n %s -t %s:%s -t cuckoo_jtype:%s -t cuckoo_machine:%s -t cuckoo_gw:%s" % (self.MOLOCH_CAPTURE_BIN,self.MOLOCH_CAPTURE_CONF,self.pcap_path,self.CUCKOO_INSTANCE_TAG,self.CUCKOO_INSTANCE_TAG,self.task_id,self.task["category"],self.machine_name,self.gateway)
            if self.custom:
                cmd = cmd + " -t custom:%s" % (self.custom)
        except Exception as e:
            log.warning("Unable to Build Basic Moloch CMD: %s" % e)

        if self.task["category"] == "file":
            try:
                if "virustotal" in results and "scans" in results["virustotal"]:
                    for key in results["virustotal"]["scans"]:
                        if results["virustotal"]["scans"][key]["result"]:
                            cmd = cmd + " -t \"VT:%s:%s\"" % (key,results["virustotal"]["scans"][key]["result"])
            except Exception as e:
                log.warning("Unable to Get VT Results For Moloch: %s" % e)


            if "md5" in results["target"]["file"] and results["target"]["file"]["md5"]:
                cmd = cmd + " -t \"md5:%s\"" % (results["target"]["file"]["md5"])
            if "sha256" in results["target"]["file"] and results["target"]["file"]["sha256"]:
                cmd = cmd + " -t \"sha256:%s\"" % (results["target"]["file"]["sha256"])
            if "clamav" in results["target"]["file"] and results["target"]["file"]["clamav"]:
                cmd = cmd + " -t \"clamav:%s\"" % (re.sub(r"[\W]","_",results["target"]["file"]["clamav"]))
            if "static" in results and "pe_imphash" in results["static"] and results["static"]["pe_imphash"]:
                cmd = cmd + " -t \"pehash:%s\"" % (results["static"]["pe_imphash"])
            if "yara" in results["target"]["file"]:
                for entry in results["target"]["file"]["yara"]:
                    cmd = cmd + " -t \"yara:%s\"" % entry["name"]
        if "signatures" in results and results["signatures"]:
            for entry in results["signatures"]:
                cmd = cmd + " -t \"cuckoosig:%s:%s\"" % (re.sub(r"[\W]","_",str(entry["name"])),re.sub(r"[\W]","_",str(entry["severity"])))
        try:
            log.debug("moloch: running import command %s " % (cmd))
            ret,stdout,stderr = self.cmd_wrapper(cmd)
            if ret == 0:
               log.debug("moloch: imported pcap %s" % (self.pcap_path))
            else:
                log.warning("moloch-capture returned a Exit Value Other than Zero %s" % (stderr))
        except Exception as e:
            log.warning("Unable to Run moloch-capture: %s" % e)

        time.sleep(1)

        if "suricata" in results and results["suricata"]:
           if "alerts" in results["suricata"]:
               for alert in results["suricata"]["alerts"]:
                       proto =  alert["protocol"]
                       if proto:
                           tmpdict = {}
                           cproto = ""
                           if proto == "UDP" or proto == "TCP" or proto == "6" or proto == "17":
                               tmpdict['srcip'] = alert['srcip']
                               tmpdict['srcport'] = alert['srcport']
                               tmpdict['dstip'] = alert['dstip']
                               tmpdict['dstport'] = alert['dstport']
                               if proto == "UDP" or proto == "17":
                                   tmpdict['cproto'] = "udp"
                                   tmpdict['nproto'] = 17
                               elif proto == "TCP" or proto == "6":
                                   tmpdict['cproto'] = "tcp"
                                   tmpdict['nproto'] = 6
                               tmpdict['expression'] = "ip==%s && ip==%s && port==%s && port==%s && tags==\"%s:%s\" && ip.protocol==%s" % (tmpdict['srcip'],tmpdict['dstip'],tmpdict['srcport'],tmpdict['dstport'],self.CUCKOO_INSTANCE_TAG,self.task_id,tmpdict['cproto'])
                               tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['srcip']))[0] + tmpdict['srcport'] + struct.unpack('!L',socket.inet_aton(tmpdict['dstip']))[0] + tmpdict['dstport']
                           elif proto == "ICMP" or proto == "1":
                               tmpdict['srcip'] = alert['srcip']
                               tmpdict['dstip'] = alert['dstip']
                               tmpdict['cproto'] = "icmp"
                               tmpdict['nproto'] = 1
                               tmpdict['expression'] = "ip==%s && ip==%s && tags==\"%s:%s\" && ip.protocol==%s" % (tmpdict['srcip'],tmpdict['dstip'],self.CUCKOO_INSTANCE_TAG,self.task_id,tmpdict['cproto'])
                               tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['srcip']))[0] + struct.unpack('!L',socket.inet_aton(tmpdict['dstip']))[0]

                           if tmpdict['hash'] in self.alerthash:
                               if  alert["sid"] not in self.alerthash[tmpdict['hash']]['sids']:
                                   self.alerthash[tmpdict['hash']]['sids'].append("suri_sid:%s" % (alert["sid"]))
                                   self.alerthash[tmpdict['hash']]['msgs'].append("suri_msg:%s" % (re.sub(r"[\W]","_",alert["signature"])))
                           else:
                               self.alerthash[tmpdict['hash']] = copy.deepcopy(tmpdict)
                               self.alerthash[tmpdict['hash']]['sids']=[]
                               self.alerthash[tmpdict['hash']]['msgs']=[]
                               self.alerthash[tmpdict['hash']]['sids'].append("suri_sid:%s" % (alert["sid"]))
                               self.alerthash[tmpdict['hash']]['msgs'].append("suri_msg:%s" % (re.sub(r"[\W]","_",alert["signature"])))
               for entry in self.alerthash:
                   tags = ','.join(list(map(str,self.alerthash[entry]['sids'])) + list(map(str,self.alerthash[entry]['msgs'])))
                   if tags:
                       log.debug("moloch: updating alert tags %s" % (self.alerthash[entry]['expression']))
                       self.update_tags(tags,self.alerthash[entry]['expression'])

           if "files" in results["suricata"]:
               for entry in results["suricata"]["files"]:
                   if "file_info" in entry:
                       proto = entry["protocol"]
                       if proto:
                           tmpdict = {}
                           cproto = ""
                           tmpdict['cproto'] = "tcp"
                           tmpdict['nproto'] = 6
                           tmpdict['srcip'] = entry['srcip']
                           tmpdict['srcport'] = entry['sp']
                           tmpdict['dstip'] = entry['dstip']
                           tmpdict['dstport'] = entry['dp']
                           tmpdict['expression'] = "ip==%s && ip==%s && port==%s && port==%s && tags==\"%s:%s\" && ip.protocol==%s" % (tmpdict['srcip'],tmpdict['dstip'],tmpdict['srcport'],tmpdict['dstport'],self.CUCKOO_INSTANCE_TAG,self.task_id,tmpdict['cproto'])
                           tmpdict['hash'] = tmpdict['nproto'] + struct.unpack('!L',socket.inet_aton(tmpdict['srcip']))[0] + tmpdict['srcport'] + struct.unpack('!L',socket.inet_aton(tmpdict['dstip']))[0] + tmpdict['dstport']

                           if tmpdict['hash'] not in self.fileshash:
                               self.fileshash[tmpdict['hash']] = copy.deepcopy(tmpdict)
                               self.fileshash[tmpdict['hash']]['clamav']=[]
                               self.fileshash[tmpdict['hash']]['md5']=[]
                               self.fileshash[tmpdict['hash']]['sha256']=[]
                               self.fileshash[tmpdict['hash']]['yara']=[]
                           if entry["file_info"]["clamav"] and entry["file_info"]["clamav"] not in self.fileshash[tmpdict['hash']]['clamav']:
                               self.fileshash[tmpdict['hash']]['clamav'].append("clamav:%s" % (re.sub(r"[\W]","_",entry["file_info"]["clamav"])))
                           if entry["file_info"]["md5"] and entry["file_info"]["md5"] not in self.fileshash[tmpdict['hash']]['md5']:
                               self.fileshash[tmpdict['hash']]['md5'].append("md5:%s" % (entry["file_info"]["md5"]))
                           if entry["file_info"]["sha256"] and entry["file_info"]["sha256"] not in self.fileshash[tmpdict['hash']]['sha256']:
                               self.fileshash[tmpdict['hash']]['sha256'].append("sha256:%s" % (entry["file_info"]["sha256"]))
                           if entry["file_info"]["yara"]:
                                  for sign in entry["file_info"]["yara"]:
                                      if sign["name"] not in self.fileshash[tmpdict['hash']]['yara']:
                                          self.fileshash[tmpdict['hash']]['yara'].append("yara:%s" % (sign["name"]))

               for entry in self.fileshash:
                   tags = ','.join(list(map(str,self.fileshash[entry]['clamav'])) + list(map(str,self.fileshash[entry]['md5'])) + list(map(str,self.fileshash[entry]['sha256'])) + list(map(str,self.fileshash[entry]['yara'])))
                   if tags:
                       log.debug("moloch: updating file tags %s" % (self.fileshash[entry]['expression']))
                       self.update_tags(tags,self.fileshash[entry]['expression'])
        return {}
