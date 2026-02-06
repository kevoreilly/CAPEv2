# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
from contextlib import suppress
from urllib.parse import urlparse

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
    "internetopenurla",
    "internetopenurlw",
    "httpopenrequesta",
    "httpopenrequestw",
    "isvalidurl",
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
    try:
        return datetime.datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S,%f").timestamp()
    except ValueError:
        return None


def _get_call_args_dict(call):
    """Convert arguments list to a dictionary for O(1) access."""
    return {a["name"]: a["value"] for a in call.get("arguments", []) if "name" in a}


def _extract_domain_from_call(call, args_map):
    # Check named arguments first
    for name in (
        "hostname",
        "host",
        "node",
        "nodename",
        "name",
        "domain",
        "szName",
        "pszName",
        "lpName",
        "query",
        "queryname",
        "dns_name",
        "QueryName",
        "lpstrName",
        "pName",
    ):
        v = args_map.get(name)
        if isinstance(v, str) and v.strip():
            return v

    # Heuristic scan of all string arguments
    for v in args_map.values():
        if isinstance(v, str):
            s = v.strip()
            if "." in s and " " not in s and s.count(".") <= 10:
                return s

    return None


def _get_arg_any(args_map, *names):
    """Return the first matching argument value for any of the provided names."""
    for n in names:
        if n in args_map:
            return args_map[n]
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

    methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ")
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
            try:
                return line.split(":", 1)[1].strip()
            except IndexError:
                continue

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


def _add_http_host(http_host_map, host, pinfo, sock=None):
    """
    Store host keys in a stable way.
    Adds:
      - normalized host
      - if host is host:port and port parses, also normalized host-only
    """
    hk = _norm_domain(host)
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


def _extract_tls_server_name(call, args_map):
    """
    Best-effort server name extraction for TLS/SChannel/SSPI.
    """
    for name in (
        "sni",
        "SNI",
        "ServerName",
        "servername",
        "server_name",
        "TargetName",
        "targetname",
        "Host",
        "host",
        "hostname",
        "Url",
        "URL",
        "url",
    ):
        v = args_map.get(name)
        if isinstance(v, str) and v.strip():
            s = v.strip()
            u = _extract_first_url(s)
            if u:
                return _host_from_url(u) or s
            if "." in s and " " not in s and len(s) < 260:
                return s

    for v in args_map.values():
        if isinstance(v, str):
            s = v.strip()
            if "." in s and " " not in s and len(s) < 260:
                u = _extract_first_url(s)
                if u:
                    return _host_from_url(u) or s
                return s

    return None
