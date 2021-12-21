# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import logging
import os
import subprocess

log = logging.getLogger(__name__)


class Process:
    """Linux process."""

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
        if "zombie" in status.get("State:", ""):
            return False
        return True

    def get_parent_pid(self):
        return self.get_proc_status().get("PPid")

    def get_proc_status(self):
        try:
            status = open(f"/proc/{self.pid}/status").readlines()
            status_values = dict((i[0], i[1]) for i in [j.strip().split(None, 1) for j in status])
            return status_values
        except Exception:
            log.critical("Could not get process status for pid %s", self.pid)
        return {}

    def execute(self, cmd):
        self.proc = proc = subprocess.Popen(cmd, env={"XAUTHORITY": "/root/.Xauthority", "DISPLAY": ":0"})
        self.pid = proc.pid
        return True

    def dump_memory(self, addr=None, length=None):
        pass
