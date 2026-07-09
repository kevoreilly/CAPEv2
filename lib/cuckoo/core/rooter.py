# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import random
import threading
from contextlib import suppress

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.socket_utils import send_socket_command

cfg = Config()
router_cfg = Config("routing")
log = logging.getLogger(__name__)

vpns = {}
socks5s = {}
gateways = {}            # profile-id -> profile object (.name/.interface/.rt_table/.priority)
_gw_cursor = 0           # process-global round-robin cursor
_gw_lock = threading.Lock()


def _load_socks5_operational():
    socks5s = {}

    if not router_cfg.socks5.enabled:
        return socks5s

    try:
        from socks5man.exceptions import Socks5manDatabaseError
        from socks5man.manager import Manager
    except (ImportError, OSError):
        return socks5s
    except Exception as e:
        log.error(e)
        return socks5s

    try:
        for socks5 in Manager().list_socks5(operational=True):
            if not hasattr(socks5, "description"):
                continue

            name = socks5.description
            if not name:
                continue

            socks5s[name] = socks5.to_dict()

            # decode utf-8 socks5man database data
            for k, v in socks5s[name].items():
                if isinstance(v, (bytes, bytearray)):
                    with suppress(UnicodeDecodeError, AttributeError):
                        socks5s[name][k] = v.decode()
    except Socks5manDatabaseError as e:
        print(e, "you migth have an outdated database at $HOME/.socks5man")

    return socks5s


def rooter(command, *args, **kwargs):
    ret = send_socket_command(cfg.cuckoo.rooter, command, *args, **kwargs)
    if ret and ret.get("exception"):
        log.warning("Rooter returned error: %s", ret["exception"])
    return ret


def _gw_live(profile):
    """True if the profile's egress interface exists and is up. Delegates to the rooter
    nic_available check; overridable in tests."""
    resp = rooter("nic_available", str(profile.interface))
    return bool(resp and resp.get("output"))


def _select_gateway(route):
    """Resolve a task route to a LIVE gateway profile, or None (=> caller fails closed).
    route: an explicit profile id, or a default_policy token 'roundrobin'/'random'."""
    global _gw_cursor
    if not gateways:
        return None
    if route in gateways:
        p = gateways[route]
        return p if _gw_live(p) else None
    live = [gateways[k] for k in gateways if _gw_live(gateways[k])]
    if not live:
        return None
    if route == "random":
        return random.choice(live)
    if route != "roundrobin":
        # not a gateway id, not 'random', not 'roundrobin' => unknown selector, FAIL CLOSED
        # rather than silently treating it as roundrobin (gemini #15).
        return None
    # roundrobin: advance the process-global cursor under the lock
    with _gw_lock:
        p = live[_gw_cursor % len(live)]
        _gw_cursor += 1
    return p
