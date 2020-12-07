# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import json
import logging
import os.path
import socket
import tempfile
import threading

from lib.cuckoo.common.config import Config

cfg = Config()
router_cfg = Config("routing")
log = logging.getLogger(__name__)
unixpath = tempfile.NamedTemporaryFile(mode="w+", delete=True)  # tempfile.mktemp()
lock = threading.Lock()

vpns = dict()
socks5s = dict()


def _load_socks5_operational():

    socks5s = dict()

    if not router_cfg.socks5.enabled:
        return socks5s

    try:
        from socks5man.manager import Manager
        from socks5man.exceptions import Socks5manDatabaseError
    except (ImportError, OSError) as e:
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
    if not os.path.exists(cfg.cuckoo.rooter):
        log.critical("Unable to passthrough root command (%s) as the rooter " "unix socket doesn't exist.", command)
        return

    lock.acquire()

    s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)

    if os.path.exists(unixpath.name):
        os.remove(unixpath.name)

    s.bind(unixpath.name)

    try:
        s.connect(cfg.cuckoo.rooter)
    except socket.error as e:
        log.critical("Unable to passthrough root command as we're unable to connect to the rooter unix socket: %s.", e)
        lock.release()
        return

    s.send(json.dumps({"command": command, "args": args, "kwargs": kwargs,}).encode("utf-8"))

    try:
        ret = json.loads(s.recv(0x10000))
    except socket.timeout:
        ret["exception"] = "rooter response timeout"

    lock.release()

    if ret["exception"]:
        log.warning("Rooter returned error: %s", ret["exception"])

    return ret
