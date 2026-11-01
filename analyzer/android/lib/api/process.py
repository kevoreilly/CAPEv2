# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import signal
import subprocess

log = logging.getLogger(__name__)


class Process:
    """Android process.

    Android runs a real Linux kernel, so /proc semantics are identical to
    analyzer/linux's Process implementation; this only drops the X11
    (XAUTHORITY/DISPLAY) environment assumptions that don't apply here.
    """

    first_process = True
    first_process_pid = None

    def __init__(self, pid=0):
        """@param pid: PID."""
        self.pid = pid

    def is_alive(self):
        if not os.path.exists(f"/proc/{self.pid}"):
            return False
        status = self.get_proc_status()
        if not status:
            return False
        if "zombie" in status.get("State", ""):
            return False
        return True

    def get_parent_pid(self):
        try:
            return int(self.get_proc_status().get("PPid"))
        except (TypeError, ValueError):
            return None

    def get_proc_status(self):
        try:
            with open(f"/proc/{self.pid}/status") as f:
                status = f.readlines()
            status_values = {}
            for line in status:
                if ":" in line:
                    key, value = line.split(":", 1)
                    status_values[key.strip()] = value.strip()
            return status_values
        except Exception:
            log.critical("Could not get process status for pid %s", self.pid)
        return {}

    def execute(self, cmd):
        self.proc = proc = subprocess.Popen(cmd)
        self.pid = proc.pid
        return True

    def terminate(self):
        """Kill the process. analyzer.py's shutdown path calls this on every
        still-alive PID it's tracking; upstream analyzer/linux's Process has
        no implementation for it (silently swallowed by a broad except),
        which leaves target app processes running across analyses.
        """
        try:
            os.kill(self.pid, signal.SIGKILL)
            return True
        except ProcessLookupError:
            return True
        except Exception:
            log.exception("Could not terminate pid %s", self.pid)
            return False

    def dump_memory(self, addr=None, length=None):
        pass
