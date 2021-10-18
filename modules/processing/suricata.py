# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import datetime
import logging
import os
import json
import shutil
import subprocess
import sys
import time

try:
    import re2 as re
except ImportError:
    import re

try:
    import orjson
    HAVE_ORJSON = True
except ImportError:
    HAVE_ORJSON = False

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger(__name__)


class Suricata(Processing):
    """Suricata processing."""

    def cmd_wrapper(self, cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = p.communicate()
        return (p.returncode, stdout, stderr)

    def sort_by_timestamp(self, unsorted):
        # Convert time string into a datetime object for sorting
        for item in unsorted:
            oldtime = item["timestamp"]
            newtime = datetime.datetime.strptime(oldtime[:-5], "%Y-%m-%d %H:%M:%S.%f")
            item["timestamp"] = newtime

        tmp = sorted(unsorted, key=lambda k: k["timestamp"])
        # Iterate sorted, converting datetime object back to string for display later
        for item in tmp:
            item["timestamp"] = datetime.datetime.strftime(item["timestamp"], "%Y-%m-%d %H:%M:%S.%f")[:-3]

        return tmp

    def json_default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode('utf8')
        raise TypeError

    def run(self):
        """Run Suricata.
        @return: hash with alerts
        """
        self.key = "suricata"
        # General
        SURICATA_CONF = self.options.get("conf", None)
        SURICATA_EVE_LOG = self.options.get("evelog", None)
        SURICATA_ALERT_LOG = self.options.get("alertlog", None)
        SURICATA_TLS_LOG = self.options.get("tlslog", None)
        SURICATA_HTTP_LOG = self.options.get("httplog", None)
        SURICATA_SSH_LOG = self.options.get("sshlog", None)
        SURICATA_DNS_LOG = self.options.get("dnslog", None)
        SURICATA_FILE_LOG = self.options.get("fileslog", None)
        SURICATA_FILES_DIR = self.options.get("filesdir", None)
        SURICATA_RUNMODE = self.options.get("runmode", None)
        SURICATA_FILE_BUFFER = self.options.get("buffer", 8192)
        Z7_PATH = self.options.get("7zbin", None)
        FILES_ZIP_PASS = self.options.get("zippass", None)

        # Socket
        SURICATA_SOCKET_PATH = self.options.get("socket_file", None)

        # Command Line
        SURICATA_BIN = self.options.get("bin", None)

        suricata = dict()
        suricata["alerts"] = []
        suricata["tls"] = []
        suricata["perf"] = []
        suricata["files"] = []
        suricata["http"] = []
        suricata["dns"] = []
        suricata["ssh"] = []
        suricata["fileinfo"] = []

        suricata["eve_log_full_path"] = None
        suricata["alert_log_full_path"] = None
        suricata["tls_log_full_path"] = None
        suricata["http_log_full_path"] = None
        suricata["file_log_full_path"] = None
        suricata["ssh_log_full_path"] = None
        suricata["dns_log_full_path"] = None

        tls_items = [
            "fingerprint", "issuerdn", "version", "subject", "sni", "ja3", "ja3s", "serial", "notbefore", "notafter"
        ]

        SURICATA_ALERT_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_ALERT_LOG)
        SURICATA_TLS_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_TLS_LOG)
        SURICATA_HTTP_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_HTTP_LOG)
        SURICATA_SSH_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_SSH_LOG)
        SURICATA_DNS_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_DNS_LOG)
        SURICATA_EVE_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_EVE_LOG)
        SURICATA_FILE_LOG_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_FILE_LOG)
        SURICATA_FILES_DIR_FULL_PATH = "%s/%s" % (self.logs_path, SURICATA_FILES_DIR)

        separate_log_paths = [
            ("alert_log_full_path", SURICATA_ALERT_LOG_FULL_PATH),
            ("tls_log_full_path", SURICATA_TLS_LOG_FULL_PATH),
            ("http_log_full_path", SURICATA_HTTP_LOG_FULL_PATH),
            ("ssh_log_full_path", SURICATA_SSH_LOG_FULL_PATH),
            ("dns_log_full_path", SURICATA_DNS_LOG_FULL_PATH),
        ]

        # handle reprocessing
        all_log_paths = [x[1] for x in separate_log_paths] + [SURICATA_EVE_LOG_FULL_PATH, SURICATA_FILE_LOG_FULL_PATH]
        for log_path in all_log_paths:
            if os.path.exists(log_path):
                try:
                    os.unlink(log_path)
                except:
                    pass
        if os.path.isdir(SURICATA_FILES_DIR_FULL_PATH):
            try:
                shutil.rmtree(SURICATA_FILES_DIR_FULL_PATH, ignore_errors=True)
            except:
                pass

        if not os.path.exists(SURICATA_CONF):
            log.warning("Unable to Run Suricata: Conf File {} Does Not Exist".format(SURICATA_CONF))
            return suricata
        if not os.path.exists(self.pcap_path):
            log.warning("Unable to Run Suricata: Pcap file {} Does Not Exist".format(self.pcap_path))
            return suricata

        # Add to this if you wish to ignore any SIDs for the suricata alert logs
        # Useful for ignoring SIDs without disabling them. Ex: surpress an alert for
        # a SID which is a dependent of another. (Bad TCP data for HTTP(S) alert)
        sid_blacklist = [
            # SURICATA FRAG IPv6 Fragmentation overlap
            2200074,
            # ET INFO InetSim Response from External Source Possible SinkHole
            2017363,
            # SURICATA UDPv4 invalid checksum
            2200075,
            # ET POLICY SSLv3 outbound connection from client vulnerable to POODLE attack
            2019416,
        ]

        if SURICATA_RUNMODE == "socket":
            try:
                # from suricatasc import SuricataSC
                from lib.cuckoo.common.suricatasc import SuricataSC
            except Exception as e:
                log.warning("Failed to import suricatasc lib {}".format(e))
                return suricata

            loopcnt = 0
            maxloops = 24
            loopsleep = 5

            args = dict()
            args["filename"] = self.pcap_path
            args["output-dir"] = self.logs_path

            suris = SuricataSC(SURICATA_SOCKET_PATH)
            try:
                suris.connect()
                suris.send_command("pcap-file", args)
            except Exception as e:
                log.warning("Failed to connect to socket and send command {}: {}".format(SURICATA_SOCKET_PATH, e))
                return suricata
            while loopcnt < maxloops:
                try:
                    pcap_flist = suris.send_command("pcap-file-list")
                    current_pcap = suris.send_command("pcap-current")
                    log.debug("pcapfile list: {} current pcap: {}".format(pcap_flist, current_pcap))

                    if self.pcap_path not in pcap_flist["message"]["files"] and current_pcap["message"] != self.pcap_path:
                        log.debug("Pcap not in list and not current pcap lets assume it's processed")
                        break
                    else:
                        loopcnt = loopcnt + 1
                        time.sleep(loopsleep)
                except Exception as e:
                    log.warning("Failed to get pcap status breaking out of loop {}".format(e))
                    break

            if loopcnt == maxloops:
                logstr = "Loop timeout of {} sec occurred waiting for file {} to finish processing"
                log.warning(logstr.format(maxloops * loopsleep, current_pcap))
                return suricata
        elif SURICATA_RUNMODE == "cli":
            if not os.path.exists(SURICATA_BIN):
                log.warning("Unable to Run Suricata: Bin File {} Does Not Exist".format(SURICATA_CONF))
                return suricata["alerts"]
            cmdstr = "{} -c {} -k none -l {} -r {}"
            cmd = cmdstr.format(SURICATA_BIN, SURICATA_CONF, self.logs_path, self.pcap_path)
            ret, _, stderr = self.cmd_wrapper(cmd)
            if ret != 0:
                log.warning("Suricata returned a Exit Value Other than Zero {}".format(stderr))
                return suricata

        else:
            log.warning("Unknown Suricata Runmode")
            return suricata

        datalist = []
        if os.path.exists(SURICATA_EVE_LOG_FULL_PATH):
            suricata["eve_log_full_path"] = SURICATA_EVE_LOG_FULL_PATH
            with open(SURICATA_EVE_LOG_FULL_PATH, "rb") as eve_log:
                datalist.append(eve_log.read())
        else:
            for path in separate_log_paths:
                if os.path.exists(path[1]):
                    suricata[path[0]] = path[1]
                    with open(path[1], "rb") as the_log:
                        datalist.append(the_log.read())

        if not datalist:
            log.warning("Suricata: Failed to find usable Suricata log file")

        parsed_files = []
        for data in datalist:
            for line in data.splitlines():
                try:
                    parsed = json.loads(line)
                except:
                    log.warning("Suricata: Failed to parse line {} as json".format(line))
                    continue

                if "event_type" in parsed:
                    if parsed["event_type"] == "alert":
                        if parsed["alert"]["signature_id"] not in sid_blacklist and not parsed["alert"]["signature"].startswith(
                            "SURICATA STREAM"
                        ):
                            alog = dict()
                            if parsed["alert"]["gid"] == "":
                                alog["gid"] = "None"
                            else:
                                alog["gid"] = parsed["alert"]["gid"]
                            if parsed["alert"]["rev"] == "":
                                alog["rev"] = "None"
                            else:
                                alog["rev"] = parsed["alert"]["rev"]
                            if parsed["alert"]["severity"] == "":
                                alog["severity"] = "None"
                            else:
                                alog["severity"] = parsed["alert"]["severity"]
                            alog["sid"] = parsed["alert"]["signature_id"]
                            try:
                                alog["srcport"] = parsed["src_port"]
                            except:
                                alog["srcport"] = "None"
                            alog["srcip"] = parsed["src_ip"]
                            try:
                                alog["dstport"] = parsed["dest_port"]
                            except:
                                alog["dstport"] = "None"
                            alog["dstip"] = parsed["dest_ip"]
                            alog["protocol"] = parsed["proto"]
                            alog["timestamp"] = parsed["timestamp"].replace("T", " ")
                            if parsed["alert"]["category"] == "":
                                alog["category"] = "None"
                            else:
                                alog["category"] = parsed["alert"]["category"]
                            alog["signature"] = parsed["alert"]["signature"]
                            suricata["alerts"].append(alog)

                    elif parsed["event_type"] == "http":
                        hlog = dict()
                        hlog["srcport"] = parsed["src_port"]
                        hlog["srcip"] = parsed["src_ip"]
                        hlog["dstport"] = parsed["dest_port"]
                        hlog["dstip"] = parsed["dest_ip"]
                        hlog["timestamp"] = parsed["timestamp"].replace("T", " ")
                        keyword = ("uri", "length", "hostname", "status", "http_method", "contenttype", "ua", "referrer")
                        keyword_suri = (
                            "url",
                            "length",
                            "hostname",
                            "status",
                            "http_method",
                            "http_content_type",
                            "http_user_agent",
                            "http_refer",
                        )
                        for key, key_s in zip(keyword, keyword_suri):
                            try:
                                hlog[key] = parsed["http"].get(key_s, "None")
                            except:
                                hlog[key] = "None"
                        suricata["http"].append(hlog)

                    elif parsed["event_type"] == "tls":
                        tlog = dict()
                        tlog["srcport"] = parsed["src_port"]
                        tlog["srcip"] = parsed["src_ip"]
                        tlog["dstport"] = parsed["dest_port"]
                        tlog["dstip"] = parsed["dest_ip"]
                        tlog["timestamp"] = parsed["timestamp"].replace("T", " ")
                        for key in tls_items:
                            if key in parsed["tls"]:
                                tlog[key] = parsed["tls"][key]
                        suricata["tls"].append(tlog)

                    elif parsed["event_type"] == "ssh":
                        suricata["ssh"].append(parsed)
                    elif parsed["event_type"] == "dns":
                        suricata["dns"].append(parsed)
                    elif parsed["event_type"] == "fileinfo":
                        flog = dict()
                        flog["http_host"] = parsed.get("http", {}).get("hostname", "")
                        flog["http_uri"] = parsed.get("http", {}).get("url", "")
                        flog["http_referer"] = parsed.get("http", {}).get("referer", "")
                        flog["http_user_agent"] = parsed.get("http", {}).get("http_user_agent", "")
                        flog["protocol"] = parsed.get("proto", "")
                        flog["magic"] = parsed.get("fileinfo", {}).get("magic", "")
                        flog["size"] = parsed.get("fileinfo", {}).get("size", "")
                        flog["stored"] = parsed.get("fileinfo", {}).get("stored", "")
                        flog["sha256"] = parsed.get("fileinfo", {}).get("sha256", "")
                        flog["md5"] = parsed.get("fileinfo", {}).get("md5", "")
                        flog["filename"] = parsed.get("fileinfo", {}).get("filename", "")
                        flog["file_info"] = dict()
                        if "/" in flog["filename"]:
                            flog["filename"] = flog["filename"].split("/")[-1]
                        parsed_files.append(flog)

        if parsed_files:
            for sfile in parsed_files:
                if sfile.get("stored", False):
                    filename = sfile["sha256"]
                    src_file = "{}/{}/{}".format(SURICATA_FILES_DIR_FULL_PATH, filename[0:2], filename)
                    dst_file = "{}/{}".format(SURICATA_FILES_DIR_FULL_PATH, filename)
                    if os.path.exists(src_file):
                        try:
                            shutil.move(src_file, dst_file)
                        except OSError as e:
                            log.warning("Unable to move suricata file: {}".format(e))
                            break
                        file_info, pefile_object = File(file_path=dst_file).get_all()
                        if pefile_object:
                            self.results.setdefault("pefiles", {})
                            self.results["pefiles"].setdefault(file_info["sha256"], pefile_object)
                        try:
                            with open(file_info["path"], "r") as drop_open:
                                filedata = drop_open.read(SURICATA_FILE_BUFFER + 1)
                            if len(filedata) > SURICATA_FILE_BUFFER:
                                file_info["data"] = convert_to_printable(filedata[:SURICATA_FILE_BUFFER] + " <truncated>")
                            else:
                                file_info["data"] = convert_to_printable(filedata)
                        except UnicodeDecodeError as e:
                            pass
                        if file_info:
                            sfile["file_info"] = file_info
                    suricata["files"].append(sfile)

            if HAVE_ORJSON:
                with open(SURICATA_FILE_LOG_FULL_PATH, "wb") as drop_log:
                    drop_log.write(orjson.dumps(suricata["files"], option=orjson.OPT_INDENT_2, default=self.json_default)) # orjson.OPT_SORT_KEYS |
            else:
                with open(SURICATA_FILE_LOG_FULL_PATH, "w") as drop_log:
                    json.dump(suricata["files"], drop_log, indent=4)

            # Cleanup file subdirectories left behind by messy Suricata
            for d in [
                dirpath
                for (dirpath, dirnames, filenames) in os.walk(SURICATA_FILES_DIR_FULL_PATH)
                if len(dirnames) == 0 and len(filenames) == 0
            ]:
                try:
                    shutil.rmtree(d)
                except OSError as e:
                    log.warning("Unable to delete suricata file subdirectories: {}".format(e))

        if SURICATA_FILES_DIR_FULL_PATH and os.path.exists(SURICATA_FILES_DIR_FULL_PATH) and Z7_PATH and os.path.exists(Z7_PATH):
            # /usr/bin/7z a -pinfected -y files.zip files-json.log files
            cmdstr = "cd {} && {} a -p{} -y files.zip {} {}"
            cmd = cmdstr.format(self.logs_path, Z7_PATH, FILES_ZIP_PASS, SURICATA_FILE_LOG, SURICATA_FILES_DIR)
            ret, stdout, stderr = self.cmd_wrapper(cmd)
            if ret > 1:
                log.warning("Suricata: Failed to create {}/files.zip - Error {}".format(self.logs_path, ret))

        suricata["alerts"] = self.sort_by_timestamp(suricata["alerts"])
        suricata["http"] = self.sort_by_timestamp(suricata["http"])
        suricata["tls"] = self.sort_by_timestamp(suricata["tls"])

        return suricata
