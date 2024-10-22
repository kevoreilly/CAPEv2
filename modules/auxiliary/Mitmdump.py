# Copyright (C) 2024 davidsb@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# This module runs mitmdump to get a HAR file
# mitmdump is behind mitmproxy project https://mitmproxy.org/

import logging
import os
import socket
import subprocess
from threading import Thread

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.rooter import rooter

mitmdump = Config("mitmdump")

log = logging.getLogger(__name__)


class Mitmdump(Auxiliary):
    """Module for generating HAR with Mitmdump."""

    def __init__(self):
        Auxiliary.__init__(self)
        Thread.__init__(self)
        log.info("Mitmdump module loaded")
        self.mitmdump_thread = None

    def start(self):
        """Start mitmdump in a separate thread."""

        self.mitmdump_thread = MitmdumpThread(self.task, self.machine)
        self.mitmdump_thread.start()
        return True

    def stop(self):
        """Stop mitmdump capture thread."""
        if self.mitmdump_thread:
            self.mitmdump_thread.stop()


class MitmdumpThread(Thread):
    """Thread responsible for control mitmdump service for each analysis."""

    def __init__(self, task, machine):
        Thread.__init__(self)
        self.task = task
        self.machine = machine
        self.do_run = True
        self.host_ip = mitmdump.cfg.get("host")
        self.host_iface = mitmdump.cfg.get("interface")
        self.mitmdump_bin = mitmdump.cfg.get("bin")
        self.proc = None
        self.host_port = self._get_unused_port()
        self.mitmdump_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "mitmdump")

    def stop(self):
        """Set stop mitmdump capture."""
        self.do_run = False

        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait()
            log.info("Stopping mitmdump")

        try:
            rooter("disable_mitmdump", self.host_iface, self.machine.ip, self.host_port)
        except subprocess.CalledProcessError as e:
            log.error("Failed to execute firewall rules: %s", e)

    def run(self):
        """Core function to the manage the module"""
        if "mitmdump" not in self.task.options:
            log.info("Exiting mitmdump. No parameter received.")
            return

        if self.do_run:
            if not self.host_port:
                log.exception("All ports in range are in use")
                return

            try:
                rooter("enable_mitmdump", self.host_iface, self.machine.ip, self.host_port)
            except subprocess.CalledProcessError as e:
                log.error("Failed to execute firewall rules: %s", e)

            try:
                mitmdump_args = []
                os.makedirs(self.mitmdump_path, exist_ok=True)
                file_path = os.path.join(self.mitmdump_path, "dump.har")
                mitmdump_args.extend(
                    [
                        self.mitmdump_bin,
                        "-q",
                        "--listen-host",
                        self.host_ip,
                        "-p",
                        str(self.host_port),
                        "--set",
                        "hardump=",
                        file_path,
                    ]
                )
                mitmdump_args[-2:] = [
                    "".join(mitmdump_args[-2:])
                ]  # concatenate the last two arguments, otherwise the HAR file will not be created.
                self.proc = subprocess.Popen(mitmdump_args, stdout=None, stderr=None, shell=False)
            except (OSError, ValueError):
                log.exception("Failed to mitmdump (host=%s, port=%s, dump_path=%s)", self.host_ip, self.host_port, file_path)
                return

            log.info(
                "Started mitmdump with PID %d (host=%s, port=%s, dump_path=%s)",
                self.proc.pid,
                self.host_ip,
                self.host_port,
                file_path,
            )

    def _get_unused_port(self) -> str | None:
        """Return the first unused TCP port from the set."""
        ports = set(range(8001, 8081))
        for port in ports:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex((self.host_ip, port)) != 0:
                    return str(port)
        return None
