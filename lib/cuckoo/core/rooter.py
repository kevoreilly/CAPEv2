# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.socket_utils import send_socket_command

cfg = Config()
router_cfg = Config("routing")
log = logging.getLogger(__name__)

vpns = {}
socks5s = {}


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
    except Socks5manDatabaseError as e:
        print(e, "you migth have an outdated database at $HOME/.socks5man")

    return socks5s


def rooter(command, *args, **kwargs):
    ret = send_socket_command(cfg.cuckoo.rooter, command, *args, **kwargs)
    if ret and ret.get("exception"):
        log.warning("Rooter returned error: %s", ret["exception"])
    return ret
