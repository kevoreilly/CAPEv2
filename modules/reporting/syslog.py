# Copyright (C) 2010-2016 Cuckoo Foundation, KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""Add the following to your $CUCKOO_PATH/conf/reporting.conf
[syslog]
enabled = yes         # yes/no
host = x.x.x.x        # IP of your syslog server/listener
port = 514            # Port of your syslog server/listener
protocol = tcp        # Protocol to send data over
logfile = yes         # Store logfile in reports directory?
logname = syslog.log  # if yes, what logname? [Default: syslog.txt]

-KillerInstinct
"""

import os
import socket

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.exceptions import CuckooReportError

ipwhitelist = [
    "131.107.255.255",  # msftncsi
    "134.170.51.254",  # M$
    "157.56.106.189",  # teredo
    "178.255.83.1",  # ocsp
    "192.168.",  # internal IP's
    "204.93.38.138",  # windows update
    "239.255.255.250",  # Multicast IP in captures...
    "4.2.2.2",  # DNS
    "64.4.10.33",  # M$
    "65.55.56.206",  # M$
    "66.198.8.96",  # msftncsi
    "74.125.228.",  # google
    "8.8.4.4",  # DNS
    "8.8.8.8",  # DNS
]

dnwhitelist = [
    ".google.com",
    ".gmail.com",
    ".gstatic.com",
    ".youtube.com",
    ".googleusercontent.com",
    ".microsoft.com",
    ".msftncsi.com",
    ".windowsupdate.com",
    "ocsp.usertrust.com",
    "ocsp.comodoca.com",
]


class Syslog(Report):
    """Creates the syslog data to be sent.
    @param results: Cuckoo results dict
    @return: String containing syslog data built from the results dict.
    """

    def createLog(self, results):
        syslog = ""
        syslog += f'Timestamp="{results["info"]["started"].replace("-", "/")}" '
        syslog += f'id="{results["info"]["id"]}" '
        submittype = results["target"]["category"]
        syslog += f'Submission="{submittype}" '
        if submittype == "file":
            syslog += f'MD5="{results["target"]["file"]["md5"]}" '
            syslog += f'SHA1="{results["target"]["file"]["sha1"]}" '
            syslog += f'File_Name="{results["target"]["file"]["name"]}" '
            syslog += f'File_Size="{results["target"]["file"]["size"]}" '
            syslog += f'File_Type="{results["target"]["file"]["type"]}" '
            if "PDF" in str(results["target"]["file"]["type"]):
                if results["static"]["pdf"].get("Keywords", {}).get("obj", 0):
                    syslog += f'Object_Count="{results["static"]["pdf"]["Keywords"]["obj"]}" '
                else:
                    syslog += 'Object_Count="0" '
                if results["static"]["pdf"].get("JSStreams", []):
                    syslog += f'Total_Streams="{len(results["static"]["pdf"]["JSStreams"])}" '
                else:
                    syslog += 'Total_Streams="0" '
        elif results["target"]["category"] == "url":
            syslog += f'URL="{results["target"]["url"]}" '
        # Here you can process the custom field if need be. My example stores
        # usernames and ticket numbers in the Custom field. I parse and output
        # it for syslog translation. Fields in custom are seperated by ";" and
        # key/value pairs are seperated by ":".
        # custom = results["info"]["custom"]
        # Set default value of "-"
        # ticket = 'ticket="-" '
        # uname = 'User="-" '
        # Parse custom, check for a new value.
        # for option in custom.split(';'):
        #    if "user:" in option:
        #        uname = f'User="{option.rsplit(":", 1)[-1]}" '
        #    if "ticket:" in option:
        #        ticket = f'ticket="{option.rsplit(":", 1)[-1]}" '
        # syslog += uname
        # syslog += ticket

        if "malscore" in results:
            syslog += f'MalScore="{results["malscore"]}" '
        if results.get("malfamily"):
            syslog += f'MalFamily="{results["malfamily"]}" '

        if "network" in results:
            if "hosts" in results["network"]:
                goodips = []
                # Walks the IP exception list, appends to a multi-value ";" delimited field.
                for ip in results["network"]["hosts"]:
                    if ip["ip"] not in ipwhitelist:
                        goodips.append(ip["ip"])
                if goodips == []:
                    syslog += 'Related_IPs="-" '
                else:
                    syslog += f'Related_IPs="{";".join(goodips)}" '
            else:
                syslog += 'Related_IPs="-" '

            if "domains" in results["network"]:
                resultsdms = []
                baddms = []
                gooddms = []
                # Walks the domain exception list, appends to a multi-value ";" delimited field.
                for domain in results["network"]["domains"]:
                    if domain["domain"] not in dnwhitelist:
                        resultsdms.append(domain["domain"])
                        for a in dnwhitelist:
                            if domain["domain"].endswith(a):
                                baddms.append(domain["domain"])
                for domain in resultsdms:
                    if domain not in baddms:
                        gooddms.append(domain)
                if gooddms == []:
                    syslog += 'Related_Domains="-" '
                else:
                    syslog += f'Related_Domains="{";".join(gooddms)}" '
            else:
                syslog += 'Related_Domains="-" '
            # Some network stats...
            if "tcp" in results["network"]:
                syslog += f'Total_TCP="{len(results["network"]["tcp"])}" '
            else:
                syslog += 'Total_TCP="0" '
            if "udp" in results["network"]:
                syslog += f'Total_UDP="{len(results["network"]["udp"])}" '
            else:
                syslog += 'Total_UDP="0" '
        # VT stats if available
        if "virustotal" in results:
            if all(val in list(results["virustotal"].keys()) for val in ("positives", "total")):
                VT_bad = str(results["virustotal"]["positives"])
                VT_total = str(results["virustotal"]["total"])
                syslog += f'Virustotal="{VT_bad}/{VT_total}" '
            else:
                syslog += 'Virustotal="Not Found" '
            # Vendor specific detections here. Included two examples.
            # if submittype == "file":
            #    if results["virustotal"]["scans"]["Symantec"]["detected"]:
            #        svirus = results["virustotal"]["scans"]["Symantec"]["result"]
            #        syslog += f'Symantec="{svirus}" '
            #    else:
            #        syslog += 'Symantec="No Detection" '
            #    if results["virustotal"]["scans"]["McAfee"]["detected"]:
            #        mvirus = results["virustotal"]["scans"]["McAfee"]["result"]
            #        syslog += f'McAfee="{mvirus}" '
            #    else:
            #        syslog += 'McAfee="No Detection" '
        else:
            syslog += 'Virustotal="Not Checked" '
            # Vendor specific case when there is no detection
            # if submittype == "file":
            #    syslog += 'Symantec="N/A" '
            #    syslog += 'McAfee="N/A" '
        sigs = []
        for sig in results["signatures"]:
            sigs.append(sig["name"])
        if sigs == []:
            syslog += 'Cuckoo_Sigs="-" '
        else:
            # Ignore all sigs EXCEPT Virustotal for URL analysis
            # (FP's is signatures for IE mechanics)
            if submittype == "url" and "antivirus_virustotal" in sigs:
                syslog += 'Cuckoo_Sigs="antivirus_virustotal" '
            # Otherwise generate the multi-value field.
            elif submittype == "file":
                syslog += f'Cuckoo_Sigs="{";".join(sigs)}" '
            else:
                syslog += 'Cuckoo_Sigs="-" '
        # Creates a multi-value ";" delimited field for yara signatures
        # (File analysis)
        if submittype == "file":
            yara = []
            if results["target"]["file"].get("yara", []):
                for rule in results["target"]["file"]["yara"]:
                    yara.append(rule["name"])
            if yara == []:
                syslog += 'Yara="-" '
            else:
                syslog += f'Yara="{";".join(yara)}" '

        return syslog

    def run(self, results):
        """Sends report.
        @param results: Cuckoo results dict.
        @raise CuckooReportError: if fails to write report.
        """
        # Get server options from reporting.conf
        server = self.options.get("host")
        port = self.options.get("port")
        proto = self.options.get("protocol").lower()
        # A few validations...
        if not server:
            raise CuckooReportError("Syslog Server IP not defined")
        if not port:
            raise CuckooReportError("Syslog Server port not defined")
        if not proto:
            raise CuckooReportError("Syslog Protocol not defined")
        if proto != "tcp" and proto != "udp":
            raise CuckooReportError("Syslog Protocol configuration error, protocol must be TCP or UDP")
        # Generate the syslog string
        try:
            result = self.createLog(results)
        except Exception:
            raise CuckooReportError("Error creating syslog formatted log")

        # Check if the user wants it stored in the reports directory as well
        do_log = self.options.get("logfile")
        if do_log:
            logfile = self.options.get("logname", "syslog.txt")
            # Log syslog results to the reports directory
            try:
                syslogfile = open(str(os.path.join(self.reports_path, logfile)), "w")
                syslogfile.write(result)
            except Exception:
                raise CuckooReportError("Error writing the syslog output file")
            finally:
                syslogfile.close()
        # Attempt to connect to the syslog server
        try:
            server_address = (server, port)
            if proto == "tcp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(server_address)
                # Attempt to send the syslog string to the syslog server
                try:
                    sock.sendall(bytes(result, encoding="UTF-8"))
                except Exception:
                    raise CuckooReportError("Failed to send data to syslog server")
                finally:
                    sock.close()
            elif proto == "udp":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.sendto(bytes(result, encoding="UTF-8"), server_address)
                except Exception:
                    raise CuckooReportError("Failed to send data to syslog server")
        except (UnicodeError, TypeError, IOError) as e:
            raise CuckooReportError(f"Failed to send syslog data: {e}")
