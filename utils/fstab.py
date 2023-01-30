#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# This is auxiliar module for dist.py to add entries to /etc/fstab for new instances

import argparse
import errno
import grp
import json
import logging.handlers
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading

if sys.version_info[:2] < (3, 8):
    sys.exit("You are running an incompatible version of Python, please use >= 3.8")

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_mkdir, path_mount_point, path_read_file, path_write_file

dist_conf = Config("distributed")
log = logging.getLogger(__name__)
unixpath = tempfile.NamedTemporaryFile(mode="w+", delete=True)  # tempfile.mktemp()
lock = threading.Lock()

username = False
log = logging.getLogger("cape-fstab")
formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
ch = logging.StreamHandler()
ch.setFormatter(formatter)
log.addHandler(ch)
log.setLevel(logging.INFO)


def add_nfs_entry(hostname: str, worker_folder: str):
    worker_path = os.path.join(CUCKOO_ROOT, dist_conf.NFS.mount_folder, hostname)
    if not path_exists(worker_path):
        path_mkdir(worker_path, parent=True, mode=0o755)

    if path_mount_point(worker_path):
        return

    with lock:
        fstab = path_read_file("/etc/fstab", mode="text").split("\n")
        # new line strip
        if fstab[-1] == "":
            fstab = fstab[:-1]
        if any(hostname in entry for entry in fstab if not entry.startswith("#")):
            return

        # hostname:/opt/CAPEv2 /opt/CAPEv2/2 nfs, auto,users,nofail,noatime,nolock,intr,tcp,actimeo=1800, 0 0
        fstab.append(f"{hostname}:/opt/CAPEv2 {worker_path} nfs, auto,user,users,nofail,noatime,nolock,intr,tcp,actimeo=1800, 0 0")
        _ = path_write_file("/etc/fstab", "\n".join(fstab), mode="text")

        try:
            subprocess.check_output(["mount", worker_path])
        except Exception as e:
            print("add_nfs_entry error on mount: %s", str(e))


def remove_nfs_entry(hostname: str):

    worker_path = os.path.join(CUCKOO_ROOT, dist_conf.NFS.mount_folder, hostname)

    with lock:
        fstab = path_read_file("/etc/fstab", mode="text").split("\n")
        for entry in fstab:
            if entry.startswith(hostname) and " nfs, " in entry:
                fstab.remove(entry)
                _ = path_write_file("/etc/fstab", "\n".join(fstab), mode="text")
                break
        try:
            subprocess.check_output(["umount", worker_path])
        except Exception as e:
            print("remove_nfs_entry error on umount: %s", str(e))


handlers = {
    "add_entry": add_nfs_entry,
    "remove_entry": remove_nfs_entry,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("socket", nargs="?", default="/tmp/cape-fstab", help="Unix socket path for fstab worker")
    parser.add_argument("-g", "--group", default="cape", help="Unix socket group")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    settings = parser.parse_args()

    if settings.verbose:
        # Verbose logging is not only controlled by the level. Some INFO logs are also
        # conditional (like here).
        log.setLevel(logging.DEBUG)
        log.info("Verbose logging enabled")

    if os.getuid():
        sys.exit("This utility is supposed to be ran as root.")

    if path_exists(settings.socket):
        path_delete(settings.socket)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(settings.socket)

    # Provide the correct file ownership and permission so CAPE can use it
    # from an unprivileged process, based on Sean Whalen's routetor.
    try:
        gr = grp.getgrnam(settings.group)
    except KeyError:
        sys.exit(
            "The group (`%s`) does not exist. Please define the group / user "
            "through which Cuckoo will connect to the rooter, e.g., "
            "./utils/fstab.py -g myuser" % settings.group
        )

    # global username
    username = settings.group
    # 0 instead of os.getuid() can give Permission denied
    os.chown(settings.socket, os.getuid(), gr.gr_gid)
    os.chmod(settings.socket, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)

    # Simple object to allow a signal handler to stop the fstab loop

    class Run:
        def __init__(self):
            self.run = True

    do = Run()

    def handle_sigterm(sig, f):
        do.run = False
        server.shutdown(socket.SHUT_RDWR)
        server.close()

    signal.signal(signal.SIGTERM, handle_sigterm)

    while do.run:
        try:
            command, addr = server.recvfrom(4096)
        except socket.error as e:
            if not do.run:
                # When the signal handler shuts the server down, do.run is False and
                # server.recvfrom raises an exception. Ignore that exception and exit.
                break
            if e.errno == errno.EINTR:
                continue
            raise e

        try:
            obj = json.loads(command)
        except Exception:
            log.info("Received invalid request: %r", command)
            continue

        command = obj.get("command")
        args = obj.get("args", [])
        kwargs = obj.get("kwargs", {})

        if not isinstance(command, str) or command not in handlers:
            log.warning("Received incorrect command: %r", command)
            continue

        if not isinstance(args, (tuple, list)):
            log.warning("Invalid arguments type: %r", args)
            continue

        if not isinstance(kwargs, dict):
            log.warning("Invalid keyword arguments: %r", kwargs)
            continue

        for arg in args + list(kwargs.keys()) + list(kwargs.values()):
            if not isinstance(arg, str):
                log.warning("Invalid argument type detected: %r (%s)", arg, type(arg))
                break
        else:
            if settings.verbose:
                log.info(
                    "Processing command: %s %s %s", command, " ".join(args), " ".join("%s=%s" % (k, v) for k, v in kwargs.items())
                )

            error = None
            output = None
            try:
                output = handlers[command](*args, **kwargs)
            except Exception as e:
                log.exception("Error executing command: {}".format(command))
                error = str(e)
            server.sendto(
                json.dumps(
                    {
                        "output": output,
                        "exception": error,
                    }
                ).encode(),
                addr,
            )
