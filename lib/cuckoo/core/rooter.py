# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import json
import logging
import socket
import tempfile
import threading
from pathlib import Path

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_exists

cfg = Config()
router_cfg = Config("routing")
log = logging.getLogger(__name__)
unixpath = tempfile.NamedTemporaryFile(mode="w+", delete=True)  # tempfile.mktemp()
lock = threading.Lock()

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
    if not path_exists(cfg.cuckoo.rooter):
        log.critical("Unable to passthrough root command (%s) as the rooter unix socket doesn't exist", command)
        return

    ret = None
    with lock:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

        unix_path = Path(unixpath.name)
        if unix_path.exists():
            unix_path.unlink()

        s.bind(unixpath.name)

        try:
            s.connect(cfg.cuckoo.rooter)
        except socket.error as e:
            log.critical("Unable to passthrough root command as we're unable to connect to the rooter unix socket: %s", e)
            return

        s.send(
            json.dumps(
                {
                    "command": command,
                    "args": args,
                    "kwargs": kwargs,
                }
            ).encode()
        )

        try:
            ret = json.loads(s.recv(0x10000))
        except socket.timeout:
            ret = {"exception": "rooter response timeout", "output": ""}

    if ret and ret["exception"]:
        log.warning("Rooter returned error: %s", ret["exception"])

    return ret
