# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import subprocess
from threading import Thread, Event

from lib.api.process import Process
from lib.common.exceptions import CuckooPackageError
from lib.common.constants import OPT_ARGUMENTS
from lib.common.parse_elf import is_elf_image
from lib.common.results import NetlogFile, append_buffer_to_host

log = logging.getLogger(__name__)

class Package:
    """Base abstract analysis package."""

    PATHS = []

    def __init__(self, options={}, config=None):
        """@param options: options dict."""
        self.options = options
        self.config = config
        self.pids = []
        # Добавляем переменные для поддержки strace
        self.nc = NetlogFile()
        self.thread = None
        self._read_ready_ev = Event()
        self.proc = None

    def set_pids(self, pids):
        """Update list of monitored PIDs in the package context.
        @param pids: list of pids.
        """
        self.pids = pids

    def start(self):
        """Run analysis package.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def check(self):
        """Check."""
        return True

    def thread_send_strace_buffer(self):
        """A thread that reads strace output and sends it to the host machine."""
        self._read_ready_ev.wait()
        if self.proc and self.proc.stderr:
            for line in self.proc.stderr:
                try:
                    append_buffer_to_host(line, self.nc)
                except ConnectionResetError:
                    log.info("Strace streaming connection has been closed")
                    return
                except Exception as e:
                    log.exception("Exception occurred during strace streaming: %s", e)

    def execute(self, cmd):
        """Start an executable for analysis with strace tracking."""
        self.nc.init("logs/strace.log", False)
        strace_args = self.options.get("strace_args", "").replace(";", ",")

        if self.options.get("nohuman"):
            final_cmd = f"sudo strace -o /dev/stderr -s 800 {strace_args} -ttf xterm -hold -e {cmd}"
        else:
            final_cmd = f"sudo strace -o /dev/stderr -s 800 {strace_args} -ttf {cmd}"

        log.info("Executing with strace: %s", final_cmd)

        self.thread = Thread(target=self.thread_send_strace_buffer, daemon=True)
        self.thread.start()

        self.proc = subprocess.Popen(
            final_cmd,
            env={"XAUTHORITY": "/root/.Xauthority", "DISPLAY": ":0"},
            stderr=subprocess.PIPE,
            shell=True
        )

        self._read_ready_ev.set()

        return self.proc.pid

    def package_files(self):
        """A list of files to upload to host."""
        return None

    def finish(self):
        """Finish run."""
        if self.options.get("procmemdump"):
            for pid in self.pids:
                p = Process(pid=pid)
                p.dump_memory()

        if hasattr(self, 'nc') and self.nc:
            self.nc.close()

        return True

    def enum_paths(self):
        """Enumerate available paths."""
        for path in self.get_paths():
            yield os.path.join(*path)

    def get_paths(self):
        """Get the default list of paths."""
        return self.PATHS

    def get_path(self, application):
        """Search for the application in all available paths."""
        for path in self.enum_paths():
            if application in path and os.path.isfile(path):
                return path

        raise CuckooPackageError(f"Unable to find any {application} executable")

    def get_path_app_in_path(self, application):
        """Search for the application in all available paths."""
        for path in self.enum_paths():
            if os.path.isfile(f"/{path}") and (not application or application.lower() in path.lower()):
                return f"/{path}"

        raise CuckooPackageError(f"Unable to find any {application} executable")

    def execute_interesting_file(self, root: str, file_name: str, file_path: str):
        """Based on file extension or file contents, run relevant analysis package"""
        if file_name.lower().endswith((".sh")):
            exec_string = f'{"/usr/bin/bash"} "{file_path}"'
            return self.execute(exec_string)
        elif file_name.lower().endswith(".pl"):
            exec_string = f'{"/usr/bin/perl"} "{file_path}"'
            return self.execute(exec_string)
        elif file_name.lower().endswith(".py"):
            exec_string = f'{"/usr/bin/python3"} "{file_path}"'
            return self.execute(exec_string)
        elif file_name.lower().endswith(".whl"):
            exec_string = f'{"/usr/bin/python3"} -m pip install "{file_path}"'
            return self.execute(exec_string)
        elif file_name.lower().endswith(".deb"):
            exec_string = f'{"/usr/bin/dpkg"} -i "{file_path}"'
            return self.execute(exec_string)
        elif file_name.lower().endswith(".jar"):
            exec_string = f'{"/usr/bin/java"} -jar "{file_path}"'
            return self.execute(exec_string)
        elif file_name.lower().endswith((".js")):
            exec_string = f'{"/usr/bin/node"} "{file_path}"'
            return self.execute(exec_string)
        elif file_name.lower().endswith(".ps1"):
            exec_string = f'{"/usr/bin/pwsh"} -NoProfile -File "{file_path}"'
            return self.execute(exec_string)
        elif is_elf_image(file_path):
            exec_string = f'{"/usr/bin/sh"} -c "{file_path} {self.options.get(OPT_ARGUMENTS, "")}"'
            return self.execute(exec_string)

    def get_pids(self):
        return []


class Auxiliary:
    priority = 0

    def __init__(self, options={}, analyzer=None):
        self.options = options
        self.analyzer = analyzer

    def get_pids(self):
        return []

    def init(self):
        pass

    def start(self):
        pass

    def stop(self):
        pass
