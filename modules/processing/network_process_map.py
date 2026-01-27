# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
from collections import defaultdict
from contextlib import suppress
from datetime import datetime
from urllib.parse import urlparse

from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)


DNS_APIS = {
    "getaddrinfo",
    "getaddrinfow",
    "getaddrinfoex",
    "getaddrinfoexw",
    "gethostbyname",
    "gethostbynamew",
    "dnsquery_a",
    "dnsquery_w",
    "dnsqueryex",
    "dnsquery",
}


HTTP_HINT_APIS = {
    "internetcrackurla",
    "internetcrackurlw",
    "httpsendrequesta",
    "httpsendrequestw",
    "internetsendrequesta",
    "internetsendrequestw",
    "internetconnecta",
    "internetconnectw",
    "winhttpopenrequest",
    "winhttpsendrequest",
    "winhttpconnect",
    "winhttpopen",
}


TLS_HINT_APIS = {
    "sslencryptpacket",
    "ssldecryptpacket",
    "initializesecuritycontexta",
    "initializesecuritycontextw",
    "initializesecuritycontextexa",
    "initializesecuritycontextexw",
    "acceptsecuritycontext",
}


def _norm_domain(d):
    if not d or not isinstance(d, str):
        return None
    d = d.strip().strip(".").lower()
    return d or None


def _parse_behavior_ts(ts_str):
    """
    Parse behavior timestamp like: '2026-01-22 23:46:58,199' -> epoch float
    Returns None if parsing fails.
    """
    if not ts_str or not isinstance(ts_str, str):
        return None
    with suppress(Exception):
        dt = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S,%f")
        return dt.timestamp()
    return None


def _extract_domain_from_call(call):
    for name in (
            "hostname", "host", "node", "nodename", "name", "domain",
            "szName", "pszName", "lpName", "query", "queryname", "dns_name",
            "QueryName", "lpstrName", "pName"
    ):
        v = _get_arg(call, name)
        if isinstance(v, str) and v.strip():
            return v

    for a in call.get("arguments", []) or []:
        v = a.get("value")
        if isinstance(v, str):
            s = v.strip()
            if "." in s and " " not in s and s.count(".") <= 10:
                return s

    return None


def _get_arg(call, name):
    for a in call.get("arguments", []) or []:
        if a.get("name") == name:
            return a.get("value")
    return None


def _get_arg_any(call, *names):
    """Return the first matching argument value for any of the provided names."""
    for n in names:
        v = _get_arg(call, n)
        if v is not None:
            return v
    return None


def _norm_ip(ip):
    if ip is None:
        return None
    if not isinstance(ip, str):
        ip = str(ip)
    ip = ip.strip()
    return ip or None


def _looks_like_http(buf):
    if not buf or not isinstance(buf, str):
        return False

    first = buf.splitlines()[0].strip() if buf else ""
    if not first:
        return False

    u = first.upper()
    if u.startswith("HTTP/1.") or u.startswith("HTTP/2"):
        return True

    methods = (
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE "
    )
    if any(u.startswith(m) for m in methods) and " HTTP/1." in u:
        return True

    if u.startswith("CONNECT ") and " HTTP/1." in u:
        return True

    return False


def _http_host_from_buf(buf):
    if not buf or not isinstance(buf, str):
        return None

    lines = buf.splitlines()
    if not lines:
        return None

    for line in lines[1:50]:
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip()

    with suppress(Exception):
        first = lines[0].strip()
        parts = first.split()
        if len(parts) >= 2:
            target = parts[1].strip()
            url = _extract_first_url(target)
            if url:
                host = _host_from_url(url)
                if host:
                    return host

    with suppress(Exception):
        first = lines[0].strip()
        parts = first.split()
        if len(parts) >= 2 and parts[0].upper() == "CONNECT":
            return parts[1].strip()

    return None


def _safe_int(x):
    with suppress(Exception):
        return int(x)
    return None


def _host_from_url(url):
    if not url or not isinstance(url, str):
        return None

    with suppress(Exception):
        u = urlparse(url)
        return u.hostname

    return None


def _extract_first_url(text):
    if not text or not isinstance(text, str):
        return None
    s = text.strip()
    for scheme in ("http://", "https://"):
        idx = s.lower().find(scheme)
        if idx != -1:
            return s[idx:].split()[0].strip('"\',')
    return None


def _norm_hostkey(host):
    if not host or not isinstance(host, str):
        return None
    h = host.strip().strip(".").lower()
    return h or None


def _add_http_host(http_host_map, host, pinfo, sock=None):
    """
    Store host keys in a stable way.
    Adds:
      - normalized host
      - if host is host:port and port parses, also normalized host-only
    """
    hk = _norm_hostkey(host)
    if not hk:
        return

    entry = dict(pinfo)
    if sock is not None:
        entry["socket"] = sock

    http_host_map[hk].append(entry)

    if ":" in hk:
        h_only, p = hk.rsplit(":", 1)
        if _safe_int(p) is not None and h_only:
            http_host_map[h_only].append(entry)


def _extract_tls_server_name(call):
    """
    Best-effort server name extraction for TLS/SChannel/SSPI.
    Common arg names seen in hooks vary; keep it conservative.
    """
    for name in (
            "sni", "SNI",
            "ServerName", "servername", "server_name",
            "TargetName", "targetname",
            "Host", "host", "hostname",
            "Url", "URL", "url",
    ):
        v = _get_arg(call, name)
        if isinstance(v, str) and v.strip():
            s = v.strip()
            u = _extract_first_url(s)
            if u:
                return _host_from_url(u) or s
            if "." in s and " " not in s and len(s) < 260:
                return s

    for a in call.get("arguments", []) or []:
        v = a.get("value")
        if isinstance(v, str):
            s = v.strip()
            if "." in s and " " not in s and len(s) < 260:
                u = _extract_first_url(s)
                if u:
                    return _host_from_url(u) or s
                return s

    return None


class NetworkProcessMap(Processing):
    """
    Augment existing results["network"] entries with process attribution fields.

    Adds (when available):
      - process_id
      - process_name

    No separate network_process_map output is produced.
    """

    order = 5

    def _load_behavior(self):
        with suppress(Exception):
            b = self.results.get("behavior")
            if b:
                return b

        return None

    def _load_network(self):
        with suppress(Exception):
            return self.results.get("network") or {}

        return {}

    def _build_endpoint_to_process_map(self, behavior):
        """
        Build:
          - endpoint_map[(ip, port)] -> [{process_id, process_name, socket?}, ...]
          - http_host_map[host] -> [{process_id, process_name, socket?}, ...]
        """
        endpoint_map = defaultdict(list)
        http_host_map = defaultdict(list)

        if not behavior:
            return endpoint_map, http_host_map

        for p in (behavior.get("processes") or []):
            pid = p.get("process_id")
            if pid is None:
                continue

            pinfo = {
                "process_id": pid,
                "process_name": p.get("process_name", ""),
            }

            for c in p.get("calls", []):
                if c.get("category") != "network":
                    continue

                api = (c.get("api") or "").lower()
                sock = _get_arg_any(c, "socket", "sock", "fd", "handle")
                ip = _norm_ip(_get_arg_any(c, "ip", "dst", "dstip", "ip_address", "address", "remote_ip", "server"))
                port = _get_arg_any(c, "port", "dport", "dstport", "remote_port", "server_port")
                buf = _get_arg_any(c, "Buffer", "buffer", "buf", "data")

                if api in ("connect", "wsaconnect", "connectex"):
                    p_int = _safe_int(port)
                    if ip and p_int is not None:
                        entry = dict(pinfo)
                        if sock is not None:
                            entry["socket"] = sock

                        endpoint_map[(ip, p_int)].append(entry)
                    continue

                if api in ("sendto", "wsasendto", "recvfrom", "wsarecvfrom"):
                    p_int = _safe_int(port)
                    if ip and p_int is not None:
                        entry = dict(pinfo)
                        if sock is not None:
                            entry["socket"] = sock

                        endpoint_map[(ip, p_int)].append(entry)

                if api in ("send", "wsasend", "sendto", "wsasendto") and _looks_like_http(buf):
                    host = _http_host_from_buf(buf)
                    if host:
                        _add_http_host(http_host_map, host, pinfo, sock=sock)

                if api in HTTP_HINT_APIS:
                    url = _get_arg_any(c, "url", "lpszUrl", "lpUrl", "uri", "pszUrl", "pUrl")
                    if isinstance(url, str) and url.strip():
                        u = _extract_first_url(url) or url.strip()
                        host = _host_from_url(u)
                        if host:
                            _add_http_host(http_host_map, host, pinfo, sock=sock)

                    if isinstance(buf, str):
                        u2 = _extract_first_url(buf)
                        if u2:
                            host2 = _host_from_url(u2)
                            if host2:
                                _add_http_host(http_host_map, host2, pinfo, sock=sock)

                if api in TLS_HINT_APIS:
                    sni = _extract_tls_server_name(c)
                    if sni:
                        _add_http_host(http_host_map, sni, pinfo, sock=sock)

                    if isinstance(buf, str) and _looks_like_http(buf):
                        host3 = _http_host_from_buf(buf)
                        if host3:
                            _add_http_host(http_host_map, host3, pinfo, sock=sock)

        return endpoint_map, http_host_map

    def _pick_best(self, candidates):
        if not candidates:
            return None

        for c in candidates:
            if c.get("process_name"):
                return c

        return candidates[0]

    def _build_dns_intents(self, behavior):
        """
        Build: domain -> list of {process info + ts_epoch}
        """
        intents = defaultdict(list)
        if not behavior:
            return intents

        for p in (behavior.get("processes") or []):
            pid = p.get("process_id")
            if pid is None:
                continue

            pinfo = {
                "process_id": pid,
                "process_name": p.get("process_name", ""),
            }

            for c in p.get("calls", []):
                if c.get("category") != "network":
                    continue

                api = (c.get("api") or "").lower()
                if api not in DNS_APIS:
                    continue

                domain = _norm_domain(_extract_domain_from_call(c))
                if not domain:
                    continue

                ts_epoch = _parse_behavior_ts(c.get("timestamp"))
                intents[domain].append(
                    {
                        "process": dict(pinfo),
                        "ts_epoch": ts_epoch,
                        "api": api,
                    }
                )

        for d in list(intents.keys()):
            intents[d].sort(key=lambda x: (x["ts_epoch"] is None, x["ts_epoch"] or 0.0))

        return intents

    def _match_dns_process(self, dns_entry, dns_intents, max_skew_seconds=10.0):
        """
        Match a network.dns entry to the closest behavior DNS intent by:
          - same domain
          - closest timestamp (if both sides have timestamps)

        Returns process dict or None.
        """
        req = _norm_domain(dns_entry.get("request"))
        if not req:
            return None

        candidates = dns_intents.get(req) or []
        if not candidates:
            return None

        net_ts = dns_entry.get("first_seen")
        if not isinstance(net_ts, (int, float)):
            return candidates[0].get("process")

        best = None
        best_delta = None

        for c in candidates:
            bts = c.get("ts_epoch")
            if not isinstance(bts, (int, float)):
                continue

            delta = abs(net_ts - bts)
            if best is None or delta < best_delta:
                best = c
                best_delta = delta

        if best is not None and best_delta is not None and best_delta <= max_skew_seconds:
            return best.get("process")

        return candidates[0].get("process")

    def _pcap_first_epoch(self, network):
        ts = []
        for k in ("dns", "http"):
            for e in (network.get(k) or []):
                v = e.get("first_seen")
                if isinstance(v, (int, float)):
                    ts.append(float(v))
        return min(ts) if ts else None

    def _build_dns_events_rel(self, network, dns_intents, max_skew_seconds=10.0):
        """
        Returns a list of dns events:
        [{"t_rel": float, "process": {...}|None, "request": "example.com"}]
        """
        out = []
        first_epoch = self._pcap_first_epoch(network)
        if first_epoch is None:
            return out

        for d in (network.get("dns") or []):
            first_seen = d.get("first_seen")
            if not isinstance(first_seen, (int, float)):
                continue
            t_rel = float(first_seen) - float(first_epoch)
            proc = self._match_dns_process(d, dns_intents, max_skew_seconds=max_skew_seconds)
            out.append({"t_rel": t_rel, "process": proc, "request": d.get("request")})

        out.sort(key=lambda x: x["t_rel"])
        return out

    def _nearest_dns_process_by_rel_time(self, dns_events_rel, t_rel, max_skew=5.0):
        if not dns_events_rel or not isinstance(t_rel, (int, float)):
            return None

        best = None
        best_delta = None
        for e in dns_events_rel:
            delta = abs(e["t_rel"] - float(t_rel))
            if best is None or delta < best_delta:
                best = e
                best_delta = delta

        if best is not None and best_delta is not None and best_delta <= max_skew:
            return best.get("process")
        return None

    def _set_proc_fields(self, obj, proc):
        """
        Add process_id/process_name onto an existing network entry.
        If proc is None, sets them to None (keeps template stable).
        """
        if proc:
            obj["process_id"] = proc.get("process_id")
            obj["process_name"] = proc.get("process_name")
        else:
            obj["process_id"] = None
            obj["process_name"] = None

    def run(self):
        behavior = self._load_behavior()
        network = self._load_network()

        endpoint_map, http_host_map = self._build_endpoint_to_process_map(behavior)

        for flow in (network.get("tcp") or []):
            proc = None
            if flow.get("dst") and flow.get("dport") is not None:
                proc = self._pick_best(endpoint_map.get((flow["dst"], int(flow["dport"])), []))

            self._set_proc_fields(flow, proc)

        dns_intents = self._build_dns_intents(behavior)
        dns_events_rel = self._build_dns_events_rel(network, dns_intents, max_skew_seconds=10.0)
        for d in (network.get("dns") or []):
            proc = self._match_dns_process(d, dns_intents, max_skew_seconds=10.0)
            self._set_proc_fields(d, proc)

        for flow in (network.get("udp") or []):
            proc = None
            dst = flow.get("dst")
            dport = flow.get("dport")
            sport = flow.get("sport")

            if dst and dport is not None:
                proc = self._pick_best(endpoint_map.get((dst, int(dport)), []))

            if not proc and (dport == 53 or sport == 53):
                t_rel = flow.get("time")
                proc = self._nearest_dns_process_by_rel_time(dns_events_rel, t_rel, max_skew=5.0)

            self._set_proc_fields(flow, proc)

        for key in ("http", "http_ex", "https_ex"):
            for h in (network.get(key) or []):
                proc = None

                host = h.get("host")
                if isinstance(host, str) and host:
                    proc = self._pick_best(http_host_map.get(host, []))

                    if not proc and ":" in host:
                        raw = host.rsplit(":", 1)[0].strip()
                        if raw:
                            proc = self._pick_best(http_host_map.get(raw, []))

                if not proc:
                    dst = h.get("dst")
                    dport = h.get("dport")
                    if dst and dport is not None:
                        proc = self._pick_best(endpoint_map.get((dst, int(dport)), []))

                self._set_proc_fields(h, proc)

        self.results.setdefault("network", {})
        self.results["network"] = network

        return {}
