# Copyright (C) 2024 davidsb@virustotal.com
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# This module runs mitmdump to get a HAR file
# mitmdump is behind mitmproxy project https://mitmproxy.org/

# NOTE  /opt/mitmproxy/mitmdump_wrapper.sh
# is needed to write pidfile of mitmdump to exit.
"""
#!/bin/bash
echo $$ > mitmdump.pid
# exec full args
exec $@
"""

# NOTE  mitmdump is launched in net namespace,
# root access is needed to run in other namespace
# workaround for now is to allow sudo, which is security issue
# alternative could be to use rooter module
# in /etc/sudoers.d/ip_netns, add a line like
"""
cape ALL=NOPASSWD: /usr/sbin/ip netns exec * /usr/bin/sudo -u cape *
"""


import logging
import os
import signal
import socket
import subprocess
import threading
import time
from threading import Lock, Thread

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.rooter import rooter

mitmdump = Config("mitmdump")

log = logging.getLogger(__name__)


def read_pid_from_file(pid_file_path):
    """
    Reads a process ID (PID) from a given file.

    Args:
        pid_file_path (str): The path to the PID file.

    Returns:
        int or None: The PID if successfully read, or None if an error occurs.
    """
    try:
        with open(pid_file_path, "r") as f:
            pid_str = f.read().strip()
            pid = int(pid_str)
            return pid
    except FileNotFoundError:
        log.error("Error: PID file not found at: %s", pid_file_path)
        return None
    except ValueError:
        log.error("Error: Invalid PID format in: %s", pid_file_path)
        return None
    except Exception as e:
        log.error("An unexpected error occurred: %s", e)
        return None


def wait_for_pid_exit(pid, timeout=None, poll_interval=0.01, max_poll_interval=0.5):
    """
    Waits for a process with the given PID to exit.

    Args:
        pid (int): The process ID to wait for.
        timeout (int, optional): The maximum time to wait in seconds. Defaults to None (wait indefinitely).
        poll_interval (float, optional): Initial interval in seconds between checks. Doubles up to
            max_poll_interval. The previous flat one-second tick rounded every teardown up to the
            next whole second even though mitmdump normally exits in milliseconds.
        max_poll_interval (float, optional): Upper bound on the polling interval.

    Returns:
        bool: True if the process exited within the timeout, False otherwise.
    """
    deadline = None if timeout is None else time.monotonic() + timeout
    interval = poll_interval
    while True:
        try:
            os.kill(pid, 0)  # Send signal 0 to check if the process exists
        except OSError:
            return True  # Process does not exist (exited)
        if deadline is not None and time.monotonic() >= deadline:
            return False  # Timeout reached
        time.sleep(interval)
        interval = min(interval * 2, max_poll_interval)


def _is_mitmdump_enabled(task) -> bool:
    options = getattr(task, "options", None) or ""
    enabled = False
    for option in options.split(","):
        token = option.strip()
        if not token:
            continue
        if "=" in token:
            key, val = token.split("=", 1)
            if key.strip().lower() == "mitmdump":
                enabled = val.strip().lower() not in ("0", "no", "false", "")
        elif token.lower() == "mitmdump":
            enabled = True
    return enabled


class Mitmdump(Auxiliary):
    """Module for generating HAR with Mitmdump."""

    def __init__(self):
        Auxiliary.__init__(self)
        Thread.__init__(self)
        log.info("Mitmdump module loaded")
        self.mitmdump_thread = None

    def start(self):
        """Start mitmdump in a separate thread."""
        if not _is_mitmdump_enabled(self.task):
            log.debug("Exiting mitmdump. No parameter received.")
            return False

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
        self._enabled = _is_mitmdump_enabled(task)
        self._state_lock = Lock()
        self._firewall_enable_attempted = False
        self._process_started = False
        self.host_ip = mitmdump.cfg.get("host")
        self.host_iface = mitmdump.cfg.get("interface")
        self.mitmdump_bin = mitmdump.cfg.get("bin")
        self.proc = None
        self.host_port = self._get_unused_port() if self._enabled else None
        self.mitmdump_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "mitmdump")

    def _get_netns(self):
        options = getattr(self.task, "options", None) or ""
        for option in options.split(","):
            token = option.strip()
            if token.startswith("netns="):
                _key, value = token.split("=", 1)
                return value.strip()
        return ""

    def _disable_firewall(self, netns=None):
        with self._state_lock:
            if not self._firewall_enable_attempted:
                return
            self._firewall_enable_attempted = False

        if netns is None:
            netns = self._get_netns()
        try:
            resp = rooter("disable_mitmdump", self.host_iface, self.machine.ip, self.host_port, netns)
        except subprocess.CalledProcessError as e:
            log.error("Failed to execute firewall rules: %s", e)
            return
        if isinstance(resp, dict) and resp.get("exception"):
            log.error("Failed to execute firewall rules: %s", resp["exception"])

    def _stop_process(self):
        pidfile_path = os.path.join(self.mitmdump_path, "mitmdump.pid")
        pid = read_pid_from_file(pidfile_path)
        if pid:
            log.info("MitmdumpThread.stop pid %s", pid)
            # must directly kill subprocess since popen does sudo.
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except OSError as e:
                log.error("Failed to terminate mitmdump pid %s: %s", pid, e)
            else:
                if self.proc is not None and self.proc.pid == pid:
                    try:
                        self.proc.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        log.warning("Timed out waiting for mitmdump pid %s to exit", pid)
                else:
                    wait_for_pid_exit(pid, 15)
        elif self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()

        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                log.warning("Timed out waiting for mitmdump wrapper process %s", self.proc.pid)

    def stop(self):
        """Set stop mitmdump capture."""
        self.do_run = False

        if not self._enabled:
            return

        if self.is_alive() and threading.current_thread() is not self:
            self.join(timeout=65)

        log.info("MitmdumpThread.stop task.options %s", self.task.options)

        try:
            with self._state_lock:
                process_started = self._process_started
            if process_started:
                self._stop_process()
        finally:
            self._disable_firewall()
        log.info("MitmdumpThread.stop finished")

    def run(self):
        """Core function to the manage the module"""
        if not self._enabled:
            log.info("Exiting mitmdump. No parameter received.")
            return

        log.info("MitmdumpThread.run task.options %s", self.task.options)

        if not self.do_run:
            return

        if not self.host_port:
            log.error("All ports in range are in use")
            return

        netns = self._get_netns()

        with self._state_lock:
            if not self.do_run:
                return
            self._firewall_enable_attempted = True

        try:
            resp = rooter("enable_mitmdump", self.host_iface, self.machine.ip, self.host_port, netns)
        except subprocess.CalledProcessError as e:
            log.error("Failed to execute firewall rules: %s", e)
            return

        if isinstance(resp, dict) and resp.get("exception"):
            log.error("Failed to execute firewall rules: %s", resp["exception"])
            if resp.get("rooter_unavailable"):
                with self._state_lock:
                    self._firewall_enable_attempted = False
            else:
                self._disable_firewall(netns)
            return

        if not self.do_run:
            self._disable_firewall(netns)
            return

        file_path = os.path.join(self.mitmdump_path, "dump.har")
        try:
            mitmdump_args = []
            listen_host = self.host_ip
            if netns:
                log.info("has netns: %s", netns)
                listen_host = "0.0.0.0"  # listen in net namespace
                # sudo for ip netns exec, then sudo back to cape
                mitmdump_args.extend(["/usr/bin/sudo", "ip", "netns", "exec", netns, "/usr/bin/sudo", "-u", "cape"])

            os.makedirs(self.mitmdump_path, exist_ok=True)
            mitmdump_args.extend(
                [
                    "/opt/mitmproxy/mitmdump_wrapper.sh",
                    self.mitmdump_bin,
                    "-q",
                    "--listen-host",
                    listen_host,
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
            self.proc = subprocess.Popen(mitmdump_args, stdout=None, stderr=None, shell=False, cwd=self.mitmdump_path)
            with self._state_lock:
                self._process_started = True
        except (OSError, ValueError):
            log.exception("Failed to mitmdump (host=%s, port=%s, dump_path=%s)", self.host_ip, self.host_port, file_path)
            self._disable_firewall(netns)
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
