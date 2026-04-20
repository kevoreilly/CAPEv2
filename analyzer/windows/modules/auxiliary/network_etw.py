import json
import logging
import os
import shutil
import socket
import time
from threading import Thread

from lib.common.results import upload_to_host
from lib.common.rand import random_string
from lib.core.config import Config
from lib.common.etw_utils import (
    ETWAuxiliaryWrapper,
    ETWProviderWrapper,
    HAVE_ETW,
    ProviderInfo,
    GUID,
    et,
    encode,
)

log = logging.getLogger(__name__)

__author__ = "DNS-GEE-O (@wmetcalf)"

KERNEL_NETWORK_GUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}"

CONNECT_EVENT_IDS = [12, 15, 28, 31, 42, 58]

EVENT_NAMES = {
    12: "tcp_connect_v4",
    15: "tcp_accept_v4",
    28: "tcp_connect_v6",
    31: "tcp_accept_v6",
    42: "udp_send_v4",
    58: "udp_send_v6",
}

# Periodic upload interval in seconds
UPLOAD_INTERVAL = 15


if HAVE_ETW:

    class NetworkETWProvider(ETWProviderWrapper):
        def __init__(
            self,
            level=et.TRACE_LEVEL_INFORMATION,
            logfile=None,
            no_conout=False,
            any_keywords=None,
            all_keywords=None,
            filter_ips=None,
            filter_ports=None,
        ):
            self._filter_ips = filter_ips or set()
            self._filter_ports = filter_ports or set()

            providers = [
                ProviderInfo(
                    "Microsoft-Windows-Kernel-Network",
                    GUID(KERNEL_NETWORK_GUID),
                    level,
                    any_keywords or 0x30,
                    all_keywords,
                )
            ]
            super().__init__(
                session_name="ETW_KernelNetwork",
                providers=providers,
                event_id_filters=CONNECT_EVENT_IDS,
                logfile=logfile,
                no_conout=no_conout,
            )

        def _should_filter(self, event, event_id):
            src_ip = str(event.get("saddr", ""))
            dst_ip = str(event.get("daddr", ""))
            src_port = event.get("sport", 0)
            dst_port = event.get("dport", 0)

            # Try int conversion for port comparison
            try:
                src_port = int(src_port)
            except (ValueError, TypeError):
                pass
            try:
                dst_port = int(dst_port)
            except (ValueError, TypeError):
                pass

            if dst_ip in self._filter_ips:
                return True
            if event_id in (15, 31) and src_ip in self._filter_ips:
                return True
            if dst_port in self._filter_ports or src_port in self._filter_ports:
                return True
            if dst_ip in ("127.0.0.1", "::1", "0.0.0.0", ""):
                return True
            return False

        def on_event(self, event_tufo):
            event_id, event = event_tufo
            if event_id not in self.event_id_filters:
                return
            if self._should_filter(event, event_id):
                return
            if self.logfile:
                self.write_to_log(self.logfile, event_id, event)

        def write_to_log(self, file_handle, event_id, event):
            header = event.get("EventHeader", {})
            pid = event.get("PID") or header.get("ProcessId", 0)
            proto = "TCP" if event_id in (12, 15, 28, 31) else "UDP"
            direction = "outbound" if event_id in (12, 28, 42, 58) else "inbound"

            entry = {
                "event_type": EVENT_NAMES.get(event_id, "unknown"),
                "event_id": event_id,
                "pid": pid,
                "protocol": proto,
                "direction": direction,
                "src_ip": str(event.get("saddr", "")),
                "src_port": event.get("sport", 0),
                "dst_ip": str(event.get("daddr", "")),
                "dst_port": event.get("dport", 0),
                "timestamp": str(header.get("TimeStamp", "")),
            }
            connid = event.get("connid")
            if connid:
                entry["connid"] = connid

            json.dump(entry, file_handle)
            file_handle.write("\n")


class Network_ETW(ETWAuxiliaryWrapper):
    """Captures TCP/UDP connection events via Microsoft-Windows-Kernel-Network ETW.

    Provides process-to-network 5-tuple mapping.
    Periodically uploads captured data to ensure availability if analysis
    terminates unexpectedly.

    Output: aux/network_etw.json (NDJSON)
    """

    # Stop AFTER capemon-related modules so late-firing network calls get attributed
    start_priority = 0
    stop_priority = -20

    def __init__(self, options, config):
        super().__init__(options, config, "network_etw")

        self.output_dir = os.path.join("C:\\", random_string(5, 10))
        try:
            os.mkdir(self.output_dir)
        except FileExistsError:
            pass

        self.log_file_path = os.path.join(self.output_dir, "%s.log" % random_string(5, 10))
        self.log_file = None
        self._do_periodic = False
        self._periodic_thread = None

        if HAVE_ETW and self.enabled:
            filter_ips = set()
            filter_ports = set()

            try:
                analysis_cfg = Config(cfg="analysis.conf")
                host_ip = getattr(analysis_cfg, "ip", "")
                if host_ip:
                    filter_ips.add(host_ip)
                rs_port = getattr(analysis_cfg, "port", 0)
                if rs_port:
                    filter_ports.add(int(rs_port))
            except Exception as e:
                log.debug("Could not read analysis config for filters: %s", e)

            filter_ports.add(8000)
            filter_ports.add(53)

            log.info("NetworkETW filters: ips=%s ports=%s", filter_ips, filter_ports)

            try:
                self.log_file = open(self.log_file_path, "w", encoding="utf-8")
                self.capture = NetworkETWProvider(
                    logfile=self.log_file,
                    level=255,
                    no_conout=True,
                    filter_ips=filter_ips,
                    filter_ports=filter_ports,
                )
            except Exception as e:
                log.error("Failed to open Network ETW log file: %s", e)

    def start(self):
        result = super().start()
        # Start periodic upload thread
        if self.enabled and self.log_file:
            self._do_periodic = True
            self._periodic_thread = Thread(target=self._periodic_upload, daemon=True)
            self._periodic_thread.start()
        return result

    def _periodic_upload(self):
        """Periodically flush and upload current data."""
        while self._do_periodic:
            for _ in range(UPLOAD_INTERVAL):
                if not self._do_periodic:
                    break
                time.sleep(1)
            if self._do_periodic and self.log_file:
                try:
                    self.log_file.flush()
                    # Copy the file so we don't interfere with ongoing writes
                    snap_path = self.log_file_path + ".snap"
                    shutil.copy2(self.log_file_path, snap_path)
                    upload_to_host(snap_path, os.path.join("aux", "network_etw.json"))
                    log.debug("Periodic network_etw upload: %d bytes", os.path.getsize(snap_path))
                    os.remove(snap_path)
                except Exception as e:
                    log.debug("Periodic network_etw upload failed: %s", e)

    def upload_results(self):
        """Final upload on stop."""
        self._do_periodic = False
        if self._periodic_thread:
            self._periodic_thread.join(timeout=5)

        if self.log_file:
            try:
                self.log_file.close()
            except Exception:
                pass
            self.log_file = None

        if os.path.isfile(self.log_file_path) and os.path.getsize(self.log_file_path) > 0:
            try:
                upload_to_host(self.log_file_path, os.path.join("aux", "network_etw.json"))
            except Exception as e:
                log.error("Final network_etw upload failed: %s", e)
