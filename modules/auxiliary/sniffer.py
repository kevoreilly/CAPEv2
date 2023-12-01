# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import functools
import getpass
import logging
import os
import signal
import subprocess
from stat import S_ISUID

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_GUEST_PORT, CUCKOO_ROOT
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.core.resultserver import ResultServer

log = logging.getLogger(__name__)

cfg = Config()
router_cfg = Config("routing")


class Sniffer(Auxiliary):
    sudo_path = "/usr/bin/sudo"

    def __init__(self):
        Auxiliary.__init__(self)
        self.proc = None

    def start(self):
        if not router_cfg.routing.enable_pcap and self.task.route in ("none", "None", "drop", "false"):
            return

        # Get updated machine info
        self.machine = self.db.view_machine_by_label(self.machine.label)

        # I got tired of Ubuntu's renaming
        tcpdump = self.options.get("tcpdump", "/usr/bin/tcpdump")
        if not os.path.exists(tcpdump):
            for path in ["/usr/bin/tcpdump", "/usr/sbin/tcpdump"]:
                if os.path.exists(path):
                    tcpdump = path
                    break

        bpf = self.options.get("bpf", "")
        remote = self.options.get("remote", False)
        custom = self.options.get("custom", "")
        remote_host = self.options.get("host", "")
        file_path = (
            f"/tmp/tcp.dump.{self.task.id}"
            if remote
            else os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "dump.pcap")
        )
        host = self.machine.ip
        # Selects per-machine interface if available.
        interface = self.machine.interface or self.options.get("interface")
        # Selects per-machine resultserver IP if available.
        resultserver_ip = str(self.machine.resultserver_ip or cfg.resultserver.ip)
        # Get resultserver port from its instance because it could change dynamically.
        ResultServer()
        resultserver_port = str(self.machine.resultserver_port or cfg.resultserver.port)

        sudo = False
        if not remote:
            if not path_exists(tcpdump):
                log.error('Tcpdump does not exist at path "%s", network capture aborted', tcpdump)
                return

            try:
                subprocess.check_call([self.sudo_path, "--list", "--non-interactive", tcpdump])
            except (FileNotFoundError, subprocess.CalledProcessError):
                # https://github.com/cuckoosandbox/cuckoo/pull/2842/files
                mode = os.stat(tcpdump).st_mode
                if mode & S_ISUID:
                    log.error(
                        "Tcpdump is not accessible for this user. Network capture aborted. "
                        "You probably need to grant sudo access to %s or add CAPE user to "
                        "pcap group",
                        tcpdump,
                    )
                    return
            else:
                sudo = True

        if not interface:
            log.error("Network interface not defined, network capture aborted")
            return

        pargs = []
        if sudo:
            pargs.extend([self.sudo_path, "--non-interactive", "--"])
        pargs.extend([tcpdump, "-U", "-q", "-s", "0", "-i", interface, "-n"])

        # Trying to save pcap with the same user which cape is running.
        try:
            user = getpass.getuser()
        except Exception:
            pass
        else:
            if not remote:
                pargs.extend(["-Z", user])

        pargs.extend(["-w", file_path])
        if remote:
            pargs.extend(["'", "host", host])
        else:
            pargs.extend(["host", host])
        # Do not capture XMLRPC agent traffic.
        pargs.extend(
            [
                "and",
                "not",
                "(",
                "dst",
                "host",
                host,
                "and",
                "dst",
                "port",
                str(CUCKOO_GUEST_PORT),
                ")",
                "and",
                "not",
                "(",
                "src",
                "host",
                host,
                "and",
                "src",
                "port",
                str(CUCKOO_GUEST_PORT),
                ")",
            ]
        )

        # Do not capture ResultServer traffic.
        pargs.extend(
            [
                "and",
                "not",
                "(",
                "dst",
                "host",
                resultserver_ip,
                "and",
                "dst",
                "port",
                resultserver_port,
                ")",
                "and",
                "not",
                "(",
                "src",
                "host",
                resultserver_ip,
                "and",
                "src",
                "port",
                resultserver_port,
                ")",
            ]
        )

        # TODO fix this, temp fix to not get all that noise
        # pargs.extend(["and", "not", "(", "dst", "host", resultserver_ip, "and", "src", "host", host, ")"])
        if custom:
            pargs.extend(["and", "(", *custom.split(" "), ")", "'"])

        if remote and bpf:
            pargs.extend(["and", "(", *bpf.split(" "), ")", "'"])
        elif bpf:
            pargs.extend(["and", "(", bpf, ")"])

        if remote and not remote_host:
            log.exception("Failed to start sniffer, remote enabled but no ssh string has been specified")
            return
        elif remote:
            with open(f"/tmp/{self.task.id}.sh", "w") as f:
                f.write(f"{' '.join(pargs)} & PID=$!")
                f.write("\n")
                f.write(f"echo $PID > /tmp/{self.task.id}.pid")
                f.write("\n")

            subprocess.check_output(
                ["scp", "-q", f"/tmp/{self.task.id}.sh", remote_host + f":/tmp/{self.task.id}.sh"],
            )
            subprocess.check_output(
                ["ssh", remote_host, "nohup", "/bin/bash", f"/tmp/{self.task.id}.sh", ">", "/tmp/log", "2>", "/tmp/err"],
            )

            self.pid = subprocess.check_output(
                ["ssh", remote_host, "cat", f"/tmp/{self.task.id}.pid"], stderr=subprocess.DEVNULL
            ).strip()
            log.info(
                "Started remote sniffer @ %s with (interface=%s, host=%s, dump path=%s, pid=%s)",
                remote_host,
                interface,
                host,
                file_path,
                self.pid,
            )
            subprocess.check_output(
                ["ssh", remote_host, "rm", "-f", f"/tmp/{self.task.id}.pid", f"/tmp/{self.task.id}.sh"],
            )

        else:
            try:
                self.proc = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            except (OSError, ValueError):
                log.exception("Failed to start sniffer (interface=%s, host=%s, dump path=%s)", interface, host, file_path)
                return

            log.info("Started sniffer with PID %d (interface=%s, host=%s, dump path=%s)", self.proc.pid, interface, host, file_path)

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """

        if not router_cfg.routing.enable_pcap and self.task.route in ("none", "None", "drop", "false"):
            return

        remote = self.options.get("remote", False)
        if remote:
            remote_host = self.options.get("host", "")
            remote_args = ["ssh", remote_host, "kill", "-2", self.pid]

            subprocess.check_output(remote_args)

            file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "dump.pcap")
            file_path2 = f"/tmp/tcp.dump.{self.task.id}"

            subprocess.check_output(["scp", "-q", f"{remote_host}:{file_path2}", file_path])
            subprocess.check_output(["ssh", remote_host, "rm", "-f", file_path2])
            return

        if self.proc and not self.proc.poll():
            if self.proc.args[0] == self.sudo_path and "-Z" in self.proc.args:
                # We must kill the child process that sudo spawned. We won't
                # have permission to kill the parent process because it's owned by root.
                try:
                    pid = int(subprocess.check_output(["ps", "--ppid", str(self.proc.pid), "-o", "pid="]).decode())
                except (subprocess.CalledProcessError, TypeError, ValueError):
                    log.exception("Failed to get child pid of sudo process to stop the sniffer.")
                    return
                term_func = functools.partial(os.kill, pid, signal.SIGTERM)
                kill_func = functools.partial(os.kill, pid, signal.SIGKILL)
            else:
                term_func = self.proc.terminate
                kill_func = self.proc.kill
                pid = self.proc.pid
            try:
                term_func()
                _, _ = self.proc.communicate()
            except Exception as e:
                log.exception("Unable to stop the sniffer (first try) with pid %d: %s", pid, e)
                try:
                    if not self.proc.poll():
                        log.debug("Killing sniffer")
                        kill_func()
                        _, _ = self.proc.communicate()
                except OSError as e:
                    log.debug("Error killing sniffer: %s, continuing", e)
                except Exception as e:
                    log.exception("Unable to stop the sniffer with pid %d: %s", pid, e)
