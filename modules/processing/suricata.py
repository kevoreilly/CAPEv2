# Copyright (C) 2010-2012 Cuckoo Sandbox Developers.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import json
import logging
import os
import shutil
import subprocess
import time
from contextlib import suppress

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_write_file
from lib.cuckoo.common.suricata_detection import et_categories, get_suricata_family
from lib.cuckoo.common.utils import add_family_detection, convert_to_printable_and_truncate

processing_cfg = Config("processing")

try:
    import orjson

    HAVE_ORJSON = True
except ImportError:
    HAVE_ORJSON = False

log = logging.getLogger(__name__)


class Suricata(Processing):
    """Suricata processing."""

    def cmd_wrapper(self, cmd):
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = p.communicate()
        return p.returncode, stdout, stderr

    def sort_by_timestamp(self, unsorted):
        # Convert time string into a datetime object for sorting
        return sorted(unsorted, key=lambda k: datetime.datetime.strptime(k["timestamp"][:-5], "%Y-%m-%d %H:%M:%S.%f"))

    def json_default(self, obj):
        if isinstance(obj, bytes):
            return obj.decode()
        raise TypeError

    def run(self):
        """Run Suricata.
        @return: hash with alerts
        """
        self.key = "suricata"
        # General
        SURICATA_CONF = self.options.get("conf")
        SURICATA_EVE_LOG = self.options.get("evelog")
        SURICATA_ALERT_LOG = self.options.get("alertlog")
        SURICATA_TLS_LOG = self.options.get("tlslog")
        SURICATA_HTTP_LOG = self.options.get("httplog")
        SURICATA_SSH_LOG = self.options.get("sshlog")
        SURICATA_DNS_LOG = self.options.get("dnslog")
        SURICATA_FILE_LOG = self.options.get("fileslog")
        SURICATA_FILES_DIR = self.options.get("filesdir")
        SURICATA_RUNMODE = self.options.get("runmode")
        SURICATA_FILE_BUFFER = self.options.get("buffer", 8192)
        Z7_PATH = self.options.get("7zbin")
        FILES_ZIP_PASS = self.options.get("zippass")

        # Socket
        SURICATA_SOCKET_PATH = self.options.get("socket_file")

        # Command Line
        SURICATA_BIN = self.options.get("bin")

        suricata = {
            "alerts": [],
            "tls": [],
            "perf": [],
            "files": [],
            "http": [],
            "dns": [],
            "ssh": [],
            "fileinfo": [],
            "eve_log_full_path": None,
            "alert_log_full_path": None,
            "tls_log_full_path": None,
            "http_log_full_path": None,
            "file_log_full_path": None,
            "ssh_log_full_path": None,
            "dns_log_full_path": None,
        }

        tls_items = ("fingerprint", "issuerdn", "version", "subject", "sni", "ja3", "ja3s", "serial", "notbefore", "notafter")

        SURICATA_ALERT_LOG_FULL_PATH = f"{self.logs_path}/{SURICATA_ALERT_LOG}"
        SURICATA_TLS_LOG_FULL_PATH = f"{self.logs_path}/{SURICATA_TLS_LOG}"
        SURICATA_HTTP_LOG_FULL_PATH = f"{self.logs_path}/{SURICATA_HTTP_LOG}"
        SURICATA_SSH_LOG_FULL_PATH = f"{self.logs_path}/{SURICATA_SSH_LOG}"
        SURICATA_DNS_LOG_FULL_PATH = f"{self.logs_path}/{SURICATA_DNS_LOG}"
        SURICATA_EVE_LOG_FULL_PATH = f"{self.logs_path}/{SURICATA_EVE_LOG}"
        SURICATA_FILE_LOG_FULL_PATH = f"{self.logs_path}/{SURICATA_FILE_LOG}"
        SURICATA_FILES_DIR_FULL_PATH = f"{self.logs_path}/{SURICATA_FILES_DIR}"

        separate_log_paths = (
            ("alert_log_full_path", SURICATA_ALERT_LOG_FULL_PATH),
            ("tls_log_full_path", SURICATA_TLS_LOG_FULL_PATH),
            ("http_log_full_path", SURICATA_HTTP_LOG_FULL_PATH),
            ("ssh_log_full_path", SURICATA_SSH_LOG_FULL_PATH),
            ("dns_log_full_path", SURICATA_DNS_LOG_FULL_PATH),
        )

        # handle reprocessing
        all_log_paths = [x[1] for x in separate_log_paths] + [SURICATA_EVE_LOG_FULL_PATH, SURICATA_FILE_LOG_FULL_PATH]
        for log_path in all_log_paths:
            if path_exists(log_path):
                with suppress(Exception):
                    path_delete(log_path)
        if os.path.isdir(SURICATA_FILES_DIR_FULL_PATH):
            with suppress(Exception):
                shutil.rmtree(SURICATA_FILES_DIR_FULL_PATH, ignore_errors=True)

        if not path_exists(SURICATA_CONF):
            log.warning("Unable to Run Suricata: Conf File %s does not exist", SURICATA_CONF)
            return suricata
        if not path_exists(self.pcap_path):
            log.debug(
                "Unable to Run Suricata: Pcap file %s does not exist. Did you run analysis with live connection?", self.pcap_path
            )
            return suricata

        # Add to this if you wish to ignore any SIDs for the suricata alert logs
        # Useful for ignoring SIDs without disabling them. Ex: surpress an alert for
        # a SID which is a dependent of another. (Bad TCP data for HTTP(S) alert)
        sid_blacklist = (
            # SURICATA FRAG IPv6 Fragmentation overlap
            2200074,
            # ET INFO InetSim Response from External Source Possible SinkHole
            2017363,
            # SURICATA UDPv4 invalid checksum
            2200075,
            # ET POLICY SSLv3 outbound connection from client vulnerable to POODLE attack
            2019416,
        )

        if SURICATA_RUNMODE == "socket":
            try:
                # from suricatasc import SuricataSC
                from lib.cuckoo.common.suricatasc import SuricataSC
            except Exception as e:
                log.warning("Failed to import suricatasc lib: %s", e)
                return suricata

            loopcnt = 0
            maxloops = 24
            loopsleep = 5

            args = {
                "filename": self.pcap_path,
                "output-dir": self.logs_path,
            }

            suris = SuricataSC(SURICATA_SOCKET_PATH)
            try:
                suris.connect()
                suris.send_command("pcap-file", args)
            except Exception as e:
                log.warning("Failed to connect to socket and send command %s: %s", SURICATA_SOCKET_PATH, e)
                return suricata
            while loopcnt < maxloops:
                try:
                    pcap_flist = suris.send_command("pcap-file-list")
                    current_pcap = suris.send_command("pcap-current")
                    log.debug("pcapfile list: %s current pcap: %s", pcap_flist, current_pcap)

                    if self.pcap_path not in pcap_flist["message"]["files"] and current_pcap["message"] != self.pcap_path:
                        log.debug("Pcap not in list and not current pcap lets assume it's processed")
                        break
                    else:
                        loopcnt += 1
                        time.sleep(loopsleep)
                except Exception as e:
                    log.warning("Failed to get pcap status breaking out of loop: %s", e)
                    break

            if loopcnt == maxloops:
                log.warning(
                    "Loop timeout of %d sec occurred waiting for file %s to finish processing", maxloops * loopsleep, current_pcap
                )
                return suricata
        elif SURICATA_RUNMODE == "cli":
            if not path_exists(SURICATA_BIN):
                log.warning("Unable to Run Suricata: Bin File %s does not exist", SURICATA_CONF)
                return suricata["alerts"]
            cmd = f"{SURICATA_BIN} -c {SURICATA_CONF} -k none -l {self.logs_path} -r {self.pcap_path}"
            ret, _, stderr = self.cmd_wrapper(cmd)
            if ret != 0:
                log.warning("Suricata returned a Exit Value Other than Zero: %s", stderr)
                return suricata

        else:
            log.warning("Unknown Suricata Runmode")
            return suricata

        datalist = []
        if path_exists(SURICATA_EVE_LOG_FULL_PATH):
            suricata["eve_log_full_path"] = SURICATA_EVE_LOG_FULL_PATH
            with open(SURICATA_EVE_LOG_FULL_PATH, "rb") as eve_log:
                datalist.append(eve_log.read())
        else:
            for path in separate_log_paths:
                if path_exists(path[1]):
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
                except Exception:
                    log.warning("Suricata: Failed to parse line %s as json", line)
                    continue

                if "event_type" in parsed:
                    if (
                        parsed["event_type"] == "alert"
                        and parsed["alert"]["signature_id"] not in sid_blacklist
                        and not parsed["alert"]["signature"].startswith("SURICATA STREAM")
                    ):
                        alog = {
                            "gid": parsed["alert"]["gid"] or "None",
                            "rev": parsed["alert"]["rev"] or "None",
                            "severity": parsed["alert"]["severity"] or "None",
                            "sid": parsed["alert"]["signature_id"],
                        }
                        try:
                            alog["srcport"] = parsed["src_port"]
                        except Exception:
                            alog["srcport"] = "None"
                        alog["srcip"] = parsed["src_ip"]
                        try:
                            alog["dstport"] = parsed["dest_port"]
                        except Exception:
                            alog["dstport"] = "None"
                        alog["dstip"] = parsed["dest_ip"]
                        alog["protocol"] = parsed["proto"]
                        alog["timestamp"] = parsed["timestamp"].replace("T", " ")
                        alog["category"] = parsed["alert"]["category"] or "None"
                        alog["signature"] = parsed["alert"]["signature"]
                        suricata["alerts"].append(alog)

                    elif parsed["event_type"] == "http":
                        hlog = {
                            "srcport": parsed["src_port"],
                            "srcip": parsed["src_ip"],
                            "dstport": parsed["dest_port"],
                            "dstip": parsed["dest_ip"],
                            "timestamp": parsed["timestamp"].replace("T", " "),
                        }
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
                            except Exception:
                                hlog[key] = "None"
                        suricata["http"].append(hlog)

                    elif parsed["event_type"] == "tls":
                        tlog = {
                            "srcport": parsed["src_port"],
                            "srcip": parsed["src_ip"],
                            "dstport": parsed["dest_port"],
                            "dstip": parsed["dest_ip"],
                            "timestamp": parsed["timestamp"].replace("T", " "),
                        }
                        for key in tls_items:
                            if key in parsed["tls"]:
                                tlog[key] = parsed["tls"][key]
                        suricata["tls"].append(tlog)

                    elif parsed["event_type"] == "ssh":
                        suricata["ssh"].append(parsed)
                    elif parsed["event_type"] == "dns":
                        suricata["dns"].append(parsed)
                    elif parsed["event_type"] == "fileinfo":
                        flog = {
                            "http_host": parsed.get("http", {}).get("hostname", ""),
                            "http_uri": parsed.get("http", {}).get("url", ""),
                            "http_referer": parsed.get("http", {}).get("referer", ""),
                            "http_user_agent": parsed.get("http", {}).get("http_user_agent", ""),
                            "protocol": parsed.get("proto", ""),
                            "magic": parsed.get("fileinfo", {}).get("magic", ""),
                            "size": parsed.get("fileinfo", {}).get("size", ""),
                            "stored": parsed.get("fileinfo", {}).get("stored", ""),
                            "sha256": parsed.get("fileinfo", {}).get("sha256", ""),
                            "md5": parsed.get("fileinfo", {}).get("md5", ""),
                            "filename": parsed.get("fileinfo", {}).get("filename", ""),
                            "file_info": {},
                        }
                        if "/" in flog["filename"]:
                            flog["filename"] = flog["filename"].rsplit("/", 1)[-1]
                        parsed_files.append(flog)

        if parsed_files:
            for sfile in parsed_files:
                if sfile.get("stored", False):
                    filename = sfile["sha256"]
                    src_file = f"{SURICATA_FILES_DIR_FULL_PATH}/{filename[0:2]}/{filename}"
                    dst_file = f"{SURICATA_FILES_DIR_FULL_PATH}/{filename}"
                    if path_exists(src_file):
                        try:
                            shutil.move(src_file, dst_file)
                        except OSError as e:
                            log.warning("Unable to move suricata file: %s", e)
                            break
                        file_info, pefile_object = File(file_path=dst_file).get_all()
                        if pefile_object:
                            self.results.setdefault("pefiles", {})
                            self.results["pefiles"].setdefault(file_info["sha256"], pefile_object)
                        with suppress(UnicodeDecodeError):
                            with open(file_info["path"], "r") as drop_open:
                                filedata = drop_open.read(SURICATA_FILE_BUFFER + 1)
                            file_info["data"] = convert_to_printable_and_truncate(filedata, SURICATA_FILE_BUFFER)
                        if file_info:
                            sfile["file_info"] = file_info
                    suricata["files"].append(sfile)

            if HAVE_ORJSON:
                _ = path_write_file(
                    SURICATA_FILE_LOG_FULL_PATH,
                    orjson.dumps(suricata["files"], option=orjson.OPT_INDENT_2, default=self.json_default),
                )  # orjson.OPT_SORT_KEYS |
            else:
                with open(SURICATA_FILE_LOG_FULL_PATH, "w") as drop_log:
                    json.dump(suricata["files"], drop_log, indent=4)

            # Cleanup file subdirectories left behind by messy Suricata
            for d in (
                dirpath
                for dirpath, dirnames, filenames in os.walk(SURICATA_FILES_DIR_FULL_PATH)
                if len(dirnames) == 0 == len(filenames)
            ):
                try:
                    shutil.rmtree(d)
                except OSError as e:
                    log.warning("Unable to delete suricata file subdirectories: %s", e)

        if SURICATA_FILES_DIR_FULL_PATH and path_exists(SURICATA_FILES_DIR_FULL_PATH) and Z7_PATH and path_exists(Z7_PATH):
            # /usr/bin/7z a -pinfected -y files.zip files-json.log files
            cmdstr = f"cd {self.logs_path} && {Z7_PATH} a -p{FILES_ZIP_PASS} -y files.zip {SURICATA_FILE_LOG} {SURICATA_FILES_DIR}"
            ret, _, stderr = self.cmd_wrapper(cmdstr)
            if ret > 1:
                log.warning("Suricata: Failed to create %s/files.zip - Error %d", self.logs_path, ret)

        suricata["alerts"] = self.sort_by_timestamp(suricata["alerts"])
        suricata["http"] = self.sort_by_timestamp(suricata["http"])
        suricata["tls"] = self.sort_by_timestamp(suricata["tls"])

        if processing_cfg.detections.suricata:
            for alert in suricata.get("alerts", []):
                if alert.get("signature", "").startswith(et_categories):
                    family = get_suricata_family(alert["signature"])
                    if family:
                        add_family_detection(self.results, family, "Suricata", alert["signature"])

        return suricata
