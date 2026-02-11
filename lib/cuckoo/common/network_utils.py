# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import re
from collections import defaultdict
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
    "dnsquery_utf8",
    "dnsqueryex",
    "dnsquery",
}


HTTP_HINT_APIS = {
    "internetcrackurla",
    "internetcrackurlw",
    "httpsendrequesta",
    "httpsendrequestw",
    "httpsendrequestexa",
    "httpsendrequestexw",
    "internetsendrequesta",
    "internetsendrequestw",
    "internetconnecta",
    "internetconnectw",
    "winhttpopenrequest",
    "winhttpsendrequest",
    "winhttpgetproxyforurl",
    "winhttpconnect",
    "winhttpopen",
    "internetopenurla",
    "internetopenurlw",
    "httpopenrequesta",
    "httpopenrequestw",
    "urldownloadtofilew",
    "urldownloadtocachefilew",
    "cryptretrieveobjectbyurlw",
    "urlcanonicalizew",
    "mkparsedisplayname",
    "mkparsedisplaynameex",
    "dsenumeratedomaintrustsw",
    "wnetuseconnectionw",
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


_HEX_HANDLE_RE = re.compile(r"^(?:0x)?([0-9a-fA-F]+)$")


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
    return {a["name"].lower(): a["value"] for a in call.get("arguments", []) if "name" in a}


def _extract_domain_from_call(call, args_map):
    # Check named arguments first
    for name in (
        "hostname",
        "host",
        "node",
        "nodename",
        "name",
        "domain",
        "szname",
        "pszname",
        "lpname",
        "query",
        "queryname",
        "dns_name",
        "lpstrname",
        "pname",
        "servername",
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
        if n.lower() in args_map:
            return args_map[n.lower()]
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
        if isinstance(x, str) and x.lower().startswith("0x"):
            return int(x, 16)
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
    def _is_valid_domain_chars(s):
        for c in s:
            if not (c.isalnum() or c in ".-_"):
                return False
        return True

    for name in (
        "sni",
        "servername",
        "server_name",
        "targetname",
        "host",
        "hostname",
        "url",
    ):
        v = args_map.get(name)
        if isinstance(v, str) and v.strip():
            s = v.strip()
            u = _extract_first_url(s)
            if u:
                return _host_from_url(u) or s
            if "." in s and " " not in s and len(s) < 260 and _is_valid_domain_chars(s):
                return s

    for v in args_map.values():
        if isinstance(v, str):
            s = v.strip()
            if "." in s and " " not in s and len(s) < 260:
                u = _extract_first_url(s)
                if u:
                    return _host_from_url(u) or s
                if _is_valid_domain_chars(s):
                    return s

    return None


def _parse_handle(v):
    """Normalize handles into '0x...' lowercase. Return None if invalid/zero."""
    if v is None:
        return None
    if isinstance(v, int):
        if v <= 0:
            return None
        return "0x%x" % v
    with suppress(Exception):
        s = str(v).strip()
        if not s:
            return None
        m = _HEX_HANDLE_RE.match(s)
        if not m:
            return None
        n = int(m.group(1), 16)
        if n <= 0:
            return None
        return "0x%x" % n
    return None


def _get_call_ret_handle(call):
    return _parse_handle(call.get("return") or call.get("retval") or call.get("ret"))


def _call_ok(call):
    """
    In your data, status is boolean.
    Keep tolerant for other shapes.
    """
    v = call.get("status")
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.lower() in ("success", "true", "1")
    return True


def _winhttp_get_proc_state(state, process):
    pid = process.get("process_id")
    pname = process.get("process_name", "") or ""
    procs = state.setdefault("processes", {})
    key = pid if pid is not None else (pname or "unknown")
    pstate = procs.get(key)
    if pstate is None:
        pstate = {
            "process_id": pid,
            "process_name": pname,
            "sessions": {},   # session_handle -> session dict
            "connects": {},   # connect_handle -> connect dict
            "requests": {},   # request_handle -> request dict
        }
        procs[key] = pstate
    return pstate


def winhttp_update_from_call(pstate, api_lc, args_map, ret_handle):
    """
    Update WinHTTP state from one call.
    args_map keys are lowercased by _get_call_args_dict().
    """
    # WinHttpOpen -> session handle
    if api_lc == "winhttpopen" and ret_handle:
        sess = pstate["sessions"].get(ret_handle)
        if sess is None:
            sess = {
                "handle": ret_handle,
                "user_agent": "",
                "access_type": "",
                "proxy_name": "",
                "proxy_bypass": "",
                "flags": "",
                "options": [],
                "connections": [],  # list of connect objects
            }
            pstate["sessions"][ret_handle] = sess

        ua = args_map.get("useragent")
        if ua and not sess["user_agent"]:
            sess["user_agent"] = str(ua)
        if args_map.get("accesstype") is not None:
            sess["access_type"] = str(args_map.get("accesstype"))
        if args_map.get("proxyname") is not None:
            sess["proxy_name"] = str(args_map.get("proxyname"))
        if args_map.get("proxybypass") is not None:
            sess["proxy_bypass"] = str(args_map.get("proxybypass"))
        if args_map.get("flags") is not None:
            sess["flags"] = str(args_map.get("flags"))
        return

    # WinHttpConnect -> connect handle (binds to session)
    if api_lc == "winhttpconnect" and ret_handle:
        sh = _parse_handle(args_map.get("sessionhandle"))
        server = args_map.get("servername")
        port = args_map.get("serverport")

        conn = pstate["connects"].get(ret_handle)
        if conn is None:
            conn = {
                "handle": ret_handle,
                "session_handle": sh,
                "server": str(server or ""),
                "port": None,
                "options": [],
                "requests": [],  # list of request objects
            }
            pstate["connects"][ret_handle] = conn

        if sh and not conn.get("session_handle"):
            conn["session_handle"] = sh
        if server and not conn.get("server"):
            conn["server"] = str(server)
        if conn.get("port") is None and port is not None:
            with suppress(Exception):
                conn["port"] = int(port)

        if sh:
            sess = pstate["sessions"].get(sh)
            if sess is not None:
                # ensure uniqueness by handle
                for c in sess["connections"]:
                    if isinstance(c, dict) and c.get("handle") == ret_handle:
                        return
                sess["connections"].append(conn)
        return

    # WinHttpOpenRequest -> request handle (binds to connect)
    if api_lc == "winhttpopenrequest" and ret_handle:
        ch = _parse_handle(args_map.get("internethandle"))
        req = pstate["requests"].get(ret_handle)
        if req is None:
            req = {
                "handle": ret_handle,
                "connect_handle": ch,
                "verb": str(args_map.get("verb") or ""),
                "object": str(args_map.get("objectname") or ""),
                "flags": str(args_map.get("flags") or ""),
                "version": str(args_map.get("version") or ""),
                "referrer": str(args_map.get("referrer") or ""),
                "options": [],
                "url": "",
            }
            pstate["requests"][ret_handle] = req
        else:
            if ch and not req.get("connect_handle"):
                req["connect_handle"] = ch

        if ch:
            conn = pstate["connects"].get(ch)
            if conn is not None:
                for r in conn["requests"]:
                    if isinstance(r, dict) and r.get("handle") == ret_handle:
                        break
                else:
                    conn["requests"].append(req)

                if conn.get("server") and req.get("object"):
                    scheme = "https" if conn.get("port") == 443 else "http"
                    req["url"] = "%s://%s%s" % (scheme, conn["server"], req["object"])
        return

    # WinHttpSetOption -> applies to session/connect/request by handle
    if api_lc == "winhttpsetoption":
        h = _parse_handle(args_map.get("internethandle"))
        if not h:
            return
        opt_entry = {"option": str(args_map.get("option") or ""), "buffer": str(args_map.get("buffer") or "")}
        if h in pstate["requests"]:
            pstate["requests"][h]["options"].append(opt_entry)
        elif h in pstate["connects"]:
            pstate["connects"][h]["options"].append(opt_entry)
        elif h in pstate["sessions"]:
            pstate["sessions"][h]["options"].append(opt_entry)
        return


def winhttp_finalize_sessions(state):
    """
    Returns per-process domain grouping with only:
      - url (scheme derived: https if port == 443 else http)
      - verb
      - user_agent
      - proxy info (access_type, proxy_name, proxy_bypass)
    """
    out = []
    procs = (state or {}).get("processes") or {}

    for _, p in procs.items():
        sessions = (p.get("sessions") or {})
        if not sessions:
            continue

        sessions_by_domain = {}
        sessions_by_domain_keys = defaultdict(set)

        for s in sessions.values():
            ua = s.get("user_agent") or ""
            access_type = s.get("access_type") or ""
            proxy_name = s.get("proxy_name") or ""
            proxy_bypass = s.get("proxy_bypass") or ""

            for c in s.get("connections") or []:
                if not isinstance(c, dict):
                    continue

                server = c.get("server") or ""
                dom = _norm_domain(server)
                if not dom:
                    continue

                port = c.get("port")
                scheme = "https" if port == 443 else "http"

                for r in c.get("requests") or []:
                    if not isinstance(r, dict):
                        continue

                    obj = r.get("object") or ""
                    if not isinstance(obj, str):
                        obj = str(obj)

                    obj = obj.strip()
                    if not obj:
                        continue

                    if not obj.startswith("/"):
                        obj = "/" + obj

                    verb = r.get("verb") or ""
                    if not isinstance(verb, str):
                        verb = str(verb)

                    verb = verb.strip().upper() or "GET"
                    request = f"{verb} {obj} \r\nUser-Agent: {ua}\r\nHost: {dom}\r\n"
                    entry = {
                        "uri": obj,
                        "dport": port,
                        "method": verb,
                        "protocol": scheme,
                        "user_agent": ua,
                        "request": request,
                        "access_type": access_type,
                        "proxy_name": proxy_name,
                        "proxy_bypass": proxy_bypass,
                    }

                    key = (obj, verb, ua, access_type, proxy_name, proxy_bypass)
                    if key not in sessions_by_domain_keys[dom]:
                        sessions_by_domain.setdefault(dom, []).append(entry)
                        sessions_by_domain_keys[dom].add(key)

        if sessions_by_domain:
            out.append({
                "process_id": p.get("process_id"),
                "process_name": p.get("process_name", ""),
                "sessions": sessions_by_domain,
            })

    return out
