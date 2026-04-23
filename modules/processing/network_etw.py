# Process→Network attribution for CAPE.
#
# Consumes every process-to-network signal captured during analysis and feeds
# it into a single AttributionIndex. Each enrichment target (suricata alerts,
# tls, http, files; network.tcp/udp/dns/hosts; sigma detections) queries the
# index through one of four methods — no target-specific lookup tables.
#
# Signal sources, highest-confidence first:
#   1. Sysmon EID 3 (NetworkConnect) — from evtx.zip. Full image path.
#   2. Kernel-Network ETW (aux/network_etw.json) — periodic uploads.
#   3. Sigma EID 3 matched_events — tertiary (catches late-fire flows).
#   4. DNS-Client ETW (aux/dns_etw.json) — originating-process DNS. Used with
#      resolution data (#5) to attribute by resolved IP. Avoids svchost bias.
#   5. Sysmon EID 22 (DnsQuery) — parallel to #4, covers queries that happened
#      before DNS-Client ETW subscribed (common miss for early CDN resolutions).
#   6. Sigma EID 22 matched_events — subset of #5, has Image in the record.
#   7. Resolution data — suricata.dns, network.dns, network.hosts, sigma EID 22
#      QueryResults. Used to turn hostnames into IPs for the DNS cross-reference.
#   8. Sysmon EID 1 (ProcessCreate) — pid→image map for processes that made
#      queries but aren't in behavior (capemon not attached).

import json
import logging
import os
import shutil
import tempfile
import xml.etree.ElementTree as ET
import zipfile

from lib.cuckoo.common.abstracts import Processing

# Sysmon Event XML lives in this namespace; ElementTree returns tag names
# already qualified, so we strip the prefix when reading element names.
EVT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

log = logging.getLogger(__name__)

try:
    import Evtx.Evtx as EvtxParser
    HAVE_EVTX = True
except ImportError:
    HAVE_EVTX = False


def _clean_ip(s):
    if not s:
        return ""
    s = s.strip()
    if s.startswith("::ffff:"):
        s = s[7:]
    return s


def _clean_host(s):
    if not s:
        return ""
    return s.strip().rstrip(".").lower()


class AttributionIndex:
    """Centralized process-to-network attribution index.

    Call order:
        idx = AttributionIndex()
        idx.add_pid_name(...)         # any number of times
        idx.add_connection(...)       # any number of times
        idx.add_dns_query(...)
        idx.add_resolution(...)
        idx.finalize()
        idx.for_flow(...)             # query API
        ...
        idx.set_http_owner(...)       # after suricata.http enrichment
        idx.for_http(...)             # for files lookup
    """

    def __init__(self):
        self._pid_to_name = {}       # pid_str -> basename
        self._by_ip = {}             # ip -> [{pid, process_name, dst_port, protocol, source}]
        self._dns_host_to_pid = {}   # host -> (pid_str, name, source)
        self._host_to_ips = {}       # host -> set(ip)
        self._ip_via_dns = {}        # ip -> [(pid_str, host)]
        self._http_by_uri = {}       # (host, uri) -> (pid_str, name)
        self._http_by_host = {}      # host -> (pid_str, name)
        # Counters surfaced via .stats() for logging
        self.stats_counters = {"dns_etw": 0, "sysmon_eid22": 0,
                               "sigma_eid22": 0, "direct": 0,
                               "resolutions": 0}

    # ------------------------------------------------------------------ seed
    def add_pid_name(self, pid, image_or_name):
        if not pid or not image_or_name:
            return
        pid = str(pid)
        name = os.path.basename(image_or_name)
        self._pid_to_name.setdefault(pid, name)
        for entries in self._by_ip.values():
            for entry in entries:
                if entry["pid"] == pid and not entry["process_name"]:
                    entry["process_name"] = self._pid_to_name[pid]

    def name_of(self, pid):
        return self._pid_to_name.get(str(pid), "") if pid else ""

    def pid_names(self):
        """Read-only view of the pid->name map. Callers that need to seed
        another helper with the current names should use this rather than
        the underscored attribute."""
        return dict(self._pid_to_name)

    def add_connection(self, pid, dst_ip, dst_port=None, src_ip="",
                       src_port=None, protocol="", process_name="", source=""):
        """Direct connection observed (kernel-ETW, sysmon EID 3, sigma EID 3).
        src_port is the disambiguator when multiple processes share a (dst_ip,
        dst_port) — every TCP flow has a unique client-side ephemeral port."""
        if not pid or not dst_ip:
            return
        pid = str(pid)
        dst_ip = _clean_ip(dst_ip)
        if not dst_ip or dst_ip in ("127.0.0.1", "::1", "0.0.0.0", "::"):
            return
        if process_name:
            self.add_pid_name(pid, process_name)
        name = self._pid_to_name.get(pid, process_name or "")
        entry = {
            "pid": pid,
            "process_name": name,
            "src_ip": _clean_ip(src_ip),
            "src_port": str(src_port) if src_port is not None and src_port != "" else "",
            "dst_port": str(dst_port) if dst_port is not None and dst_port != "" else "",
            "protocol": (protocol or "").upper(),
            "source": source,
        }
        bucket = self._by_ip.setdefault(dst_ip, [])
        # Dedupe on (pid, src_port, dst_port, protocol) so the same connection
        # observed by multiple sources doesn't multiply, but distinct flows
        # from the same process (different src_ports) stay separate.
        dedup_key = (pid, entry["src_port"], entry["dst_port"], entry["protocol"])
        for existing in bucket:
            if (existing["pid"], existing["src_port"], existing["dst_port"],
                existing["protocol"]) == dedup_key:
                return
        bucket.append(entry)
        self.stats_counters["direct"] += 1

    def add_dns_query(self, pid, hostname, image_or_name="", source=""):
        """pid asked for hostname (DNS-Client ETW / sysmon EID 22 / sigma EID 22)."""
        if not pid or not hostname:
            return
        pid = str(pid)
        h = _clean_host(hostname)
        if not h:
            return
        if image_or_name:
            self.add_pid_name(pid, image_or_name)
        name = self._pid_to_name.get(pid, "")
        # Skip positively-identified svchost (dnscache doing a delegated lookup
        # isn't the real owner). Unknown names are kept — PID alone is still
        # useful attribution.
        if name and "svchost" in name.lower():
            return
        self._dns_host_to_pid.setdefault(h, (pid, name, source))
        if source in self.stats_counters:
            self.stats_counters[source] += 1

    def add_resolution(self, hostname, ip):
        """hostname resolves to ip (suricata.dns, network.dns, network.hosts, sigma EID 22)."""
        h = _clean_host(hostname)
        ip = _clean_ip(ip)
        if not h or not ip:
            return
        # Basic garbage filter
        if ":" in ip and ip.count(":") < 2:
            return
        self._host_to_ips.setdefault(h, set()).add(ip)
        self.stats_counters["resolutions"] += 1

    # --------------------------------------------------------------- finalize
    def finalize(self):
        """Cross-reference DNS queries × resolutions into ip_via_dns."""
        for host, (pid, name, source) in self._dns_host_to_pid.items():
            for ip in self._host_to_ips.get(host, ()):
                self._ip_via_dns.setdefault(ip, []).append((pid, host))

    # --------------------------------------------------------------- queries
    def for_ip(self, ip, dst_port=None, src_port=None):
        """Best process for a connection to `ip`. Match priority:
            1. exact 5-tuple match by src_port (each TCP flow has unique
               client ephemeral port — disambiguates multi-process cases)
            2. dst_port match (when src_port unknown or not in index)
            3. first known process (when no port info available)
            4. DNS-resolved IP fallback (process asked for a hostname that
               resolved to this IP, but we never saw the connect)
        Returns {pid, process_name, source, ...} or None."""
        ip = _clean_ip(ip)
        if not ip:
            return None
        procs = self._by_ip.get(ip)
        if procs:
            # 1. src_port match — most specific
            if src_port is not None and src_port != "":
                for p in procs:
                    if p["src_port"] == str(src_port):
                        return dict(p)
            # 2. dst_port match
            if dst_port is not None and dst_port != "":
                for p in procs:
                    if p["dst_port"] == str(dst_port):
                        return dict(p)
            # 3. first known
            return dict(procs[0])
        # 4. DNS fallback
        dns_hits = self._ip_via_dns.get(ip)
        if dns_hits:
            pid, host = dns_hits[0]
            name = self._pid_to_name.get(pid, "")
            if name and "svchost" in name.lower():
                return None
            return {
                "pid": pid,
                "process_name": name,
                "src_port": "",
                "dst_port": str(dst_port) if dst_port is not None else "",
                "protocol": "TCP",
                "source": "dns-fallback",
                "resolved_hostname": host,
            }
        return None

    def for_flow(self, dstip="", dstport=None, srcip="", srcport=None):
        """Bidirectional flow attribution with full 5-tuple matching when
        available. Tries dst-side first (outbound-favored), then src-side
        for ingress alerts where dst is the local VM."""
        # On the outbound interpretation, srcport is the local ephemeral
        # port — that's the disambiguator. On the ingress interpretation
        # (alert dst=VM), dstport is the local ephemeral port.
        return (self.for_ip(dstip, dst_port=dstport, src_port=srcport)
                or self.for_ip(srcip, dst_port=srcport, src_port=dstport))

    def for_host(self, hostname):
        """(pid, name) that queried this hostname, or None. Used for files
        and network.dns records."""
        h = _clean_host(hostname)
        if not h:
            return None
        rec = self._dns_host_to_pid.get(h)
        if not rec:
            return None
        pid, name, _src = rec
        return (pid, name)

    def for_http(self, host, uri):
        """(pid, name) from an already-enriched HTTP transaction. Prefer an
        exact (host, uri) match; fall back to host alone; finally DNS.
        Hostnames are normalised to lowercase per RFC 4343."""
        host = host.lower() if host else ""
        if host and uri:
            hit = self._http_by_uri.get((host, uri))
            if hit:
                return hit
        if host:
            hit = self._http_by_host.get(host)
            if hit:
                return hit
        return self.for_host(host)

    def set_http_owner(self, host, uri, pid, name):
        """Register an attributed HTTP transaction for subsequent files lookup."""
        if not pid:
            return
        pid = str(pid)
        host = host.lower() if host else ""
        if host and uri:
            self._http_by_uri.setdefault((host, uri), (pid, name))
        if host:
            self._http_by_host.setdefault(host, (pid, name))

    def all_processes_for(self, ip):
        """Return every distinct (pid, name) seen for an IP — direct + DNS.
        Used by network.hosts where multiple processes may share a dst."""
        ip = _clean_ip(ip)
        if not ip:
            return []
        seen = set()
        out = []
        for p in self._by_ip.get(ip, ()):
            key = (p["pid"], p["process_name"])
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "pid": p["pid"],
                "process_name": p["process_name"],
                "dst_port": p["dst_port"],
                "protocol": p["protocol"],
                "source": p["source"],
            })
        for pid, host in self._ip_via_dns.get(ip, ()):
            key = (pid, self._pid_to_name.get(pid, ""))
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "pid": pid,
                "process_name": self._pid_to_name.get(pid, ""),
                "dst_port": "",
                "protocol": "",
                "source": "dns-fallback",
                "resolved_hostname": host,
            })
        return out


class NetworkETW(Processing):
    """Parse network connection events and correlate with process info."""

    key = "network_etw"
    order = 99  # Run after suricata but before dnsgeeo (101)

    # ------------------------------------------------------------------ parse
    @staticmethod
    def _safe_extract(zf, member, dest_dir):
        """Extract `member` from `zf` into `dest_dir` only if the resolved
        target stays inside `dest_dir` (zip-slip guard). Returns the on-disk
        path on success, None if the entry would escape."""
        target = os.path.realpath(os.path.join(dest_dir, member))
        if not target.startswith(os.path.realpath(dest_dir) + os.sep):
            log.warning("Skipping evtx zip entry that would escape tmpdir: %s", member)
            return None
        zf.extract(member, dest_dir)
        return target

    @staticmethod
    def _read_evt_data(event_elem):
        """Parse <EventData><Data Name="X">value</Data>...</EventData> into a
        dict with XML entities properly decoded. Returns {} when no EventData
        present (some events don't carry one)."""
        out = {}
        ed = event_elem.find(EVT_NS + "EventData")
        if ed is None:
            return out
        for d in ed.findall(EVT_NS + "Data"):
            name = d.get("Name")
            if not name:
                continue
            # ElementTree returns text=None for self-closing/empty elements;
            # normalise to "" so callers can distinguish "missing" via .get()
            # default vs "present but empty" via "" — same as before, but now
            # entity-decoded (&amp; → &, &lt; → <, &#xNN; → unicode char).
            out[name] = (d.text or "").strip()
        return out

    def _parse_sysmon_evtx(self):
        """Extract EID 1 / EID 3 / EID 22 from sysmon EVTX snapshots.
        Returns (connections, pid_to_image, dns_queries)."""
        connections = []
        pid_to_image = {}
        dns_queries = []
        evtx_path = os.path.join(self.analysis_path, "evtx", "evtx.zip")
        if not HAVE_EVTX or not os.path.exists(evtx_path):
            return connections, pid_to_image, dns_queries

        tmpdir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(evtx_path) as z:
                sysmon_files = sorted([f for f in z.namelist() if "Sysmon" in f])
                for fname in sysmon_files:
                    path = self._safe_extract(z, fname, tmpdir)
                    if path is None:
                        continue
                    try:
                        with EvtxParser.Evtx(path) as ef:
                            for rec in ef.records():
                                try:
                                    root = ET.fromstring(rec.xml())
                                except ET.ParseError as parse_err:
                                    log.debug("Skipping malformed evtx record in %s: %s",
                                              fname, parse_err)
                                    continue
                                sys_elem = root.find(EVT_NS + "System")
                                if sys_elem is None:
                                    continue
                                eid_elem = sys_elem.find(EVT_NS + "EventID")
                                if eid_elem is None or eid_elem.text not in ("1", "3", "22"):
                                    continue
                                eid = eid_elem.text
                                fields = self._read_evt_data(root)

                                if eid == "1":
                                    pid = fields.get("ProcessId", "")
                                    image = fields.get("Image", "")
                                    if pid and image:
                                        pid_to_image[str(pid)] = os.path.basename(image)

                                elif eid == "22":
                                    pid = fields.get("ProcessId", "")
                                    qname = _clean_host(fields.get("QueryName", ""))
                                    image = fields.get("Image", "")
                                    if pid and qname:
                                        dns_queries.append((str(pid), qname, image))
                                    if pid and image:
                                        pid_to_image.setdefault(str(pid), os.path.basename(image))

                                else:  # "3"
                                    connections.append({
                                        "pid": fields.get("ProcessId", ""),
                                        "process_name": os.path.basename(fields.get("Image", "")),
                                        "process_path": fields.get("Image", ""),
                                        "protocol": fields.get("Protocol", "").upper(),
                                        "direction": "outbound" if fields.get("Initiated") == "true" else "inbound",
                                        "src_ip": fields.get("SourceIp", ""),
                                        "src_port": fields.get("SourcePort", ""),
                                        "dst_ip": fields.get("DestinationIp", ""),
                                        "dst_port": fields.get("DestinationPort", ""),
                                        "dst_hostname": fields.get("DestinationHostname", ""),
                                        "source": "sysmon",
                                    })
                    except Exception:
                        log.debug("Failed to parse sysmon EVTX %s", fname, exc_info=True)
        except Exception:
            log.warning("Failed to read EVTX zip", exc_info=True)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        return connections, pid_to_image, dns_queries

    def _parse_kernel_network_etw(self, pid_to_name):
        """Parse aux/network_etw.json from the Microsoft-Windows-Kernel-Network
        ETW provider (captured by the network_etw auxiliary at analysis time)."""
        connections = []
        etw_path = os.path.join(self.analysis_path, "aux", "network_etw.json")
        if not os.path.exists(etw_path):
            return connections

        try:
            with open(etw_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    pid = str(event.get("pid", ""))
                    connections.append({
                        "pid": pid,
                        "process_name": pid_to_name.get(pid, ""),
                        "process_path": "",
                        "protocol": event.get("protocol", "").upper(),
                        "direction": event.get("direction", ""),
                        "src_ip": event.get("src_ip", ""),
                        "src_port": str(event.get("src_port", "")),
                        "dst_ip": event.get("dst_ip", ""),
                        "dst_port": str(event.get("dst_port", "")),
                        "dst_hostname": "",
                        "source": "kernel_etw",
                    })
        except Exception:
            log.warning("Failed to parse network ETW data", exc_info=True)

        return connections

    def _parse_dns_etw(self):
        """Parse aux/dns_etw.json (DNS-Client ETW; originating-process DNS).
        Returns: [(pid_str, hostname_lower), ...]."""
        out = []
        path = os.path.join(self.analysis_path, "aux", "dns_etw.json")
        if not os.path.exists(path):
            return out
        try:
            with open(path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if e.get("QueryType") != "Query":
                        continue
                    pid = e.get("ProcessId")
                    qname = _clean_host(e.get("QueryName", ""))
                    if pid is None or not qname:
                        continue
                    out.append((str(pid), qname))
        except Exception:
            log.warning("Failed to parse dns_etw.json", exc_info=True)
        return out

    # --------------------------------------------------------------------- run
    def run(self):
        results = {
            "process_connections": [],
            "connections_by_pid": {},
            "connections_by_dst": {},
        }

        idx = AttributionIndex()

        # pid->image seeds ---------------------------------------------------
        behavior_processes = self.results.get("behavior", {}).get("processes", []) or []
        for proc in behavior_processes:
            idx.add_pid_name(proc.get("process_id"), proc.get("process_name", ""))

        sysmon_conns, sysmon_pid_to_image, sysmon_dns_queries = self._parse_sysmon_evtx()
        for pid, image in sysmon_pid_to_image.items():
            idx.add_pid_name(pid, image)

        # Direct connections -------------------------------------------------
        for c in sysmon_conns:
            idx.add_connection(
                pid=c["pid"], dst_ip=c["dst_ip"], dst_port=c["dst_port"],
                src_ip=c.get("src_ip", ""), src_port=c.get("src_port", ""),
                protocol=c["protocol"], process_name=c["process_name"],
                source="sysmon",
            )

        etw_conns = self._parse_kernel_network_etw(idx.pid_names())
        for c in etw_conns:
            idx.add_connection(
                pid=c["pid"], dst_ip=c["dst_ip"], dst_port=c["dst_port"],
                src_ip=c.get("src_ip", ""), src_port=c.get("src_port", ""),
                protocol=c["protocol"], process_name=c["process_name"],
                source="kernel_etw",
            )

        sigma = self.results.get("sigma", {}) or {}
        for det in sigma.get("detections", []) or []:
            for ev in det.get("matched_events", []) or []:
                if ev.get("EventID") == 3 and ev.get("ProcessID") is not None:
                    image = ev.get("Image", "")
                    idx.add_pid_name(ev.get("ProcessID"), image)
                    idx.add_connection(
                        pid=ev.get("ProcessID"),
                        dst_ip=ev.get("DestinationIp", ""),
                        dst_port=ev.get("DestinationPort"),
                        src_ip=ev.get("SourceIp", ""),
                        src_port=ev.get("SourcePort"),
                        protocol=ev.get("Protocol", ""),
                        process_name=os.path.basename(image) if image else "",
                        source="sigma",
                    )

        # DNS queries (pid -> hostname) --------------------------------------
        for pid, host in self._parse_dns_etw():
            idx.add_dns_query(pid, host, source="dns_etw")
        for pid, host, image in sysmon_dns_queries:
            idx.add_dns_query(pid, host, image, source="sysmon_eid22")
        for det in sigma.get("detections", []) or []:
            for ev in det.get("matched_events", []) or []:
                if ev.get("EventID") != 22:
                    continue
                pid = ev.get("ProcessID")
                if pid is None:
                    continue
                idx.add_dns_query(pid, ev.get("QueryName", ""),
                                  ev.get("Image", ""), source="sigma_eid22")

        # Resolutions (hostname -> IPs) --------------------------------------
        suricata = self.results.get("suricata", {}) or {}
        network = self.results.get("network", {}) or {}

        for rec in suricata.get("dns", []) or []:
            q = rec.get("rrname") or rec.get("query") or ""
            idx.add_resolution(q, rec.get("rdata") or rec.get("answer") or "")
            for a in rec.get("answers", []) or []:
                idx.add_resolution(q, a.get("rdata") or a.get("data") or "")
        for rec in network.get("dns", []) or []:
            q = rec.get("request") or ""
            for a in rec.get("answers", []) or []:
                if a.get("type") in ("A", "AAAA"):
                    idx.add_resolution(q, a.get("data", ""))
        for rec in network.get("hosts", []) or []:
            idx.add_resolution(rec.get("hostname", ""), rec.get("ip", ""))
        for det in sigma.get("detections", []) or []:
            for ev in det.get("matched_events", []) or []:
                if ev.get("EventID") != 22:
                    continue
                q = ev.get("QueryName", "")
                raw = ev.get("QueryResults", "") or ""
                for part in raw.split(";"):
                    part = part.strip()
                    if part and not part.startswith("type:"):
                        idx.add_resolution(q, part)

        idx.finalize()

        # Build the result structure (process_connections + by_pid + by_dst).
        # Dedupe key here is intentionally coarser than AttributionIndex's
        # (which uses src_port to keep distinct flows separate): this view
        # is for human consumption — multiple ephemeral connections from
        # the same process to the same dst_ip:dst_port should fold to one
        # row in process_connections / connections_by_dst. AttributionIndex
        # still has the per-flow detail for query-time matching.
        merged = []
        seen = set()
        for pool in (sysmon_conns, etw_conns):
            for c in pool:
                key = (c["pid"], c["dst_ip"], c["dst_port"])
                if c["pid"] and c["dst_ip"] and key not in seen:
                    seen.add(key)
                    merged.append(c)

        by_pid = {}
        by_dst = {}
        for c in merged:
            pid = c["pid"]
            dst = c["dst_ip"]
            if not dst or dst in ("127.0.0.1", "::1", "0.0.0.0", "::"):
                continue
            by_pid.setdefault(pid, {
                "pid": pid,
                "process_name": c["process_name"],
                "process_path": c.get("process_path", ""),
                "connections": [],
            })["connections"].append({
                "dst_ip": dst,
                "dst_port": c["dst_port"],
                "protocol": c["protocol"],
            })
            by_dst.setdefault(dst, []).append({
                "pid": pid,
                "process_name": c["process_name"],
                "dst_port": c["dst_port"],
                "protocol": c["protocol"],
                "source": c.get("source", ""),
            })

        results["process_connections"] = merged
        results["connections_by_pid"] = by_pid
        results["connections_by_dst"] = by_dst

        log.info(
            "network_etw: sources — %d sysmon conns, %d kernel-ETW conns, "
            "%d pid->image, %d sysmon DNS, %d DNS-ETW pairs, %d resolutions",
            len(sysmon_conns), len(etw_conns), len(sysmon_pid_to_image),
            len(sysmon_dns_queries), idx.stats_counters.get("dns_etw", 0),
            idx.stats_counters.get("resolutions", 0),
        )

        # Enrichment loops — all go through the single index ----------------
        enriched = {k: 0 for k in ("alerts", "tls", "http", "files",
                                    "tcp", "udp", "hosts", "dns", "sigma")}

        def apply(rec, hit):
            if not hit:
                return False
            rec["process_name"] = hit.get("process_name", "")
            rec["process_id"] = hit.get("pid", "")
            return True

        # suricata.alerts — bidirectional (ingress-direction rules dst=VM)
        for rec in suricata.get("alerts", []) or []:
            hit = idx.for_flow(rec.get("dstip", ""), rec.get("dstport"),
                               rec.get("srcip", ""), rec.get("srcport"))
            if apply(rec, hit):
                enriched["alerts"] += 1

        # suricata.tls + http — dst-based (with src fallback too, for safety)
        for kind in ("tls", "http"):
            for rec in suricata.get(kind, []) or []:
                hit = idx.for_flow(rec.get("dstip", ""), rec.get("dstport"),
                                   rec.get("srcip", ""), rec.get("srcport"))
                if apply(rec, hit):
                    enriched[kind] += 1
                    if kind == "http":
                        idx.set_http_owner(rec.get("hostname", ""),
                                           rec.get("uri", ""),
                                           hit["pid"], hit.get("process_name", ""))

        # suricata.files — via HTTP transaction (uri/host) or DNS hostname
        for rec in suricata.get("files", []) or []:
            host = rec.get("http_host", "")
            hit = idx.for_http(host, rec.get("http_uri", ""))
            if hit:
                pid, name = hit
                rec["process_name"] = name
                rec["process_id"] = pid
                enriched["files"] += 1

        # network.tcp / udp — CAPE's pcap-parsed connections (sport disambiguates)
        for proto in ("tcp", "udp"):
            for rec in network.get(proto, []) or []:
                hit = idx.for_ip(rec.get("dst", ""),
                                 dst_port=rec.get("dport"),
                                 src_port=rec.get("sport"))
                if apply(rec, hit):
                    enriched[proto] += 1

        # network.dns — via DNS-query hostname (never by UDP 53 flow owner)
        for rec in network.get("dns", []) or []:
            hit = idx.for_host(rec.get("request", ""))
            if hit:
                pid, name = hit
                rec["process_name"] = name
                rec["process_id"] = pid
                enriched["dns"] += 1

        # network.hosts — may have multiple owners; list all
        for rec in network.get("hosts", []) or []:
            owners = idx.all_processes_for(rec.get("ip", ""))
            if owners:
                rec["processes"] = owners
                enriched["hosts"] += 1

        # sigma.detections — hoist (pid, image, command_line, parent) from
        # matched_events so the UI doesn't have to dig
        for det in sigma.get("detections", []) or []:
            seen_procs = set()
            procs = []
            for ev in det.get("matched_events", []) or []:
                pid = ev.get("ProcessID")
                image = ev.get("Image", "")
                if pid is None and not image:
                    continue
                key = (pid, image)
                if key in seen_procs:
                    continue
                seen_procs.add(key)
                procs.append({
                    "pid": pid,
                    "process_name": os.path.basename(image) if image else "",
                    "process_path": image,
                    "command_line": ev.get("CommandLine", ""),
                    "parent_pid": ev.get("ParentProcessId"),
                    "parent_image": ev.get("ParentImage", ""),
                })
            if procs:
                det["processes"] = procs
                enriched["sigma"] += 1

        log.info(
            "network_etw: enriched — %d alerts, %d tls, %d http, %d files, "
            "%d tcp, %d udp, %d dns, %d hosts, %d sigma",
            enriched["alerts"], enriched["tls"], enriched["http"], enriched["files"],
            enriched["tcp"], enriched["udp"], enriched["dns"], enriched["hosts"],
            enriched["sigma"],
        )

        return results
