# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import select
import socket
import threading
from typing import Callable

try:
    import requests

    HAVE_REQUESTS = True
    DOH_SESSION = requests.Session()
except Exception:
    HAVE_REQUESTS = False
    DOH_SESSION = None
    DOH_SESSION = None

try:
    import pycares

    HAVE_CARES = True
except Exception:
    HAVE_CARES = False

log = logging.getLogger(__name__)

# try:
#    import gevent, gevent.socket
#    HAVE_GEVENT = True
# except Exception:
HAVE_GEVENT = False

# these are used by all resolvers
DNS_TIMEOUT = 5
DNS_TIMEOUT_VALUE = ""


def set_timeout(value: int):
    global DNS_TIMEOUT
    DNS_TIMEOUT = value


def set_timeout_value(value: str):
    global DNS_TIMEOUT_VALUE
    DNS_TIMEOUT_VALUE = value


# standard gethostbyname in thread
# http://code.activestate.com/recipes/473878/
def with_timeout(func: Callable, args=(), kwargs={}):
    """This function will spawn a thread and run the given function
    using the args, kwargs and return the given default value if the
    timeout_duration is exceeded.
    """

    class ResultThread(threading.Thread):
        daemon = True

        def __init__(self):
            threading.Thread.__init__(self)
            self.result, self.error = None, None

        def run(self):
            try:
                self.result = func(*args, **kwargs)
            except Exception as e:
                self.error = e

    it = ResultThread()
    it.start()
    it.join(DNS_TIMEOUT)
    if it.is_alive():
        return DNS_TIMEOUT_VALUE
    else:
        if it.error:
            raise it.error
        return it.result


def resolve_thread(name: str) -> str:
    return with_timeout(gethostbyname, (name,))


def gethostbyname(name: str) -> str:
    try:
        ip = socket.gethostbyname(name)
    except socket.gaierror:
        ip = ""
    return ip


# C-ARES (http://c-ares.haxx.se/)
def resolve_cares(name: str) -> str:
    # create new c-ares channel
    careschan = pycares.Channel(timeout=DNS_TIMEOUT, tries=1)

    # if we don't get a response we return the default value
    result = Resultholder()
    result.value = DNS_TIMEOUT_VALUE

    def setresult_cb(res, error):
        # ignore error and just take first result ip (randomized anyway)
        if res and res.addresses:
            result.value = res.addresses[0]

    # resolve with cb
    careschan.gethostbyname(name, socket.AF_INET, setresult_cb)

    # now do the actual work
    readfds, writefds = careschan.getsock()
    canreadfds, _, _ = select.select(readfds, writefds, [], DNS_TIMEOUT)
    for rfd in canreadfds:
        careschan.process_fd(rfd, -1)

    # if the query did not succeed, setresult was not called and we just
    # return result destroy the channel first to not leak anything
    careschan.destroy()
    return result.value


# workaround until py3 nonlocal (for c-ares and gevent)
class Resultholder:
    pass


"""
# gevent based resolver with timeout
def resolve_gevent(name: str):
    result = resolve_gevent_real(name)
    # if it failed, do this a second time because of strange libevent behavior
    # basically sometimes the Timeout fires immediately instead of after
    # DNS_TIMEOUT
    if result == DNS_TIMEOUT_VALUE:
        result = resolve_gevent_real(name)
    return result


def resolve_gevent_real(name):
    result = DNS_TIMEOUT_VALUE
    with gevent.Timeout(DNS_TIMEOUT, False):
        try:
            result = gevent.socket.gethostbyname(name)
        except socket.gaierror:
            pass

    return result
"""


# DNS-over-HTTPS
# Supports Google (/resolve JSON API) and other application/dns-json
# compatible endpoints (for example, Cloudflare-style JSON APIs).
# Default: Google DNS. Configurable via set_doh_url().
DOH_URL = "https://dns.google/resolve"
USE_DOH = False

# Expected DNS response type numbers for rdtype validation
_RDTYPE_MAP = {"A": 1, "AAAA": 28, "PTR": 12, "CNAME": 5, "MX": 15, "TXT": 16, "NS": 2, "SOA": 6}


def set_doh(enabled: bool):
    global USE_DOH
    USE_DOH = enabled


def set_doh_url(url: str):
    global DOH_URL
    if url:
        if not url.startswith("https://"):
            log.warning("DoH URL %s does not use HTTPS — DNS queries will not be encrypted", url)
        DOH_URL = url.rstrip("/")


def resolve_doh(name: str, rdtype: str = "A") -> str:
    """Resolve a DNS name using DNS-over-HTTPS (JSON API).

    Compatible with Google (/resolve), Cloudflare (/dns-query), and other
    providers that support the application/dns-json content type.

    Uses a persistent requests.Session for connection pooling.
    """
    if not HAVE_REQUESTS or DOH_SESSION is None:
        if rdtype == "A":
            log.warning("requests library not available for DoH, falling back to system DNS")
            return resolve_thread(name)
        log.warning(
            "requests library not available for DoH, no system DNS fallback for %s queries",
            rdtype,
        )
        return DNS_TIMEOUT_VALUE
    try:
        expected_type = _RDTYPE_MAP.get(rdtype.upper())
        resp = DOH_SESSION.get(
            DOH_URL,
            params={"name": name, "type": rdtype},
            headers={"Accept": "application/dns-json"},
            timeout=DNS_TIMEOUT,
        )
        if resp.status_code != 200:
            log.debug("DoH request for %s returned HTTP %d", name, resp.status_code)
            return DNS_TIMEOUT_VALUE
        data = resp.json()
        for answer in data.get("Answer", []):
            answer_type = answer.get("type")
            # If we know the expected type, only return matching records
            if expected_type and answer_type == expected_type:
                result = answer["data"]
                if answer_type == 12:  # PTR — strip trailing dot
                    result = result.rstrip(".")
                return result
            # Fallback for unknown rdtype: return first A/AAAA/PTR
            if not expected_type and answer_type in (1, 12, 28):
                result = answer["data"]
                if answer_type == 12:
                    result = result.rstrip(".")
                return result
    except requests.RequestException as e:
        log.debug("DoH resolution failed for %s: %s", name, e)
    except (ValueError, KeyError) as e:
        log.debug("DoH response parse error for %s: %s", name, e)
    return DNS_TIMEOUT_VALUE


# choose resolver automatically
def resolve(name: str) -> str:
    if USE_DOH:
        return resolve_doh(name)
    if HAVE_CARES:
        return resolve_cares(name)
    # elif HAVE_GEVENT:
    #    return resolve_gevent(name)
    return resolve_thread(name)
