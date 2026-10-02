# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import functools
import getpass
import logging
import os
import shlex
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

physical_machinery = False
if cfg.cuckoo.machinery == "physical":
    physical_cfg = Config("physical")
    fog_Host = physical_cfg.fog.hostname
    physical_machinery = True


def build_tcpdump_args(
    tcpdump,
    interface,
    host,
    file_path,
    resultserver_ip,
    resultserver_port,
    user=None,
    custom="",
    bpf="",
    sudo_path=None,
    fog_host=None,
):
    """Build the tcpdump argv.

    The filter is returned as plain argv tokens. Quoting for the remote case is
    the caller's job (see shlex.join in Sniffer.start), because injecting bare
    "'" tokens here produced an unterminated quote when neither custom nor bpf
    was set, and a stray quote argument in the local case where nothing had
    opened one.
    """
    pargs = []
    if sudo_path:
        pargs.extend([sudo_path, "--non-interactive", "--"])
    pargs.extend([tcpdump, "-U", "-q", "-s", "0", "-i", interface, "-n"])

    if user:
        pargs.extend(["-Z", user])

    pargs.extend(["-w", file_path, "host", host])

    # Do not capture XMLRPC agent traffic.
    guest_port = str(CUCKOO_GUEST_PORT)
    pargs.extend(
        [
            "and", "not", "(", "dst", "host", host, "and", "dst", "port", guest_port, ")",
            "and", "not", "(", "src", "host", host, "and", "src", "port", guest_port, ")",
        ]
    )  # fmt: skip

    # Do not capture ResultServer traffic.
    pargs.extend(
        [
            "and", "not", "(", "dst", "host", resultserver_ip, "and", "dst", "port", resultserver_port, ")",
            "and", "not", "(", "src", "host", resultserver_ip, "and", "src", "port", resultserver_port, ")",
        ]
    )  # fmt: skip

    if fog_host:
        # Do not capture FOG Server traffic.
        pargs.extend(["and", "not", "(", "dst", "host", fog_host, ")"])

    # TODO fix this, temp fix to not get all that noise
    # pargs.extend(["and", "not", "(", "dst", "host", resultserver_ip, "and", "src", "host", host, ")"])

    for extra in (custom, bpf):
        if extra:
            pargs.extend(["and", "(", *extra.split(), ")"])

    return pargs


def build_remote_script(command, task_id):
    """Script fed to the remote shell on stdin.

    tcpdump is detached with nohup and its output redirected to files, so the
    ssh channel closes as soon as the pid has been echoed. The pid comes back on
    stdout rather than through a file, which removes the "ssh cat" and "ssh rm"
    round trips and leaves nothing behind in the remote /tmp.
    """
    return f"nohup {command} > /tmp/cape-sniffer-{task_id}.log 2> /tmp/cape-sniffer-{task_id}.err &\n" "echo $!\n"


# `sudo --list <tcpdump>` costs as much as the sudoers policy takes to evaluate.
# On a host with an LDAP/SSSD-backed sudoers it was measured at 333-348 ms, and
# it ran on every task start even though the answer only changes when sudoers
# or the tcpdump path does. Cached for the lifetime of the process; restart the
# scheduler after a sudoers change, as is already the case for the config files.
_SUDO_CACHE = {}


def sudo_allows_tcpdump(sudo_path, tcpdump):
    key = (sudo_path, tcpdump)
    cached = _SUDO_CACHE.get(key)
    if cached is None:
        try:
            subprocess.run(
                [sudo_path, "--list", "--non-interactive", tcpdump],
                check=True,
                capture_output=True,
                timeout=30,
            )
        except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            cached = False
        else:
            cached = True
        _SUDO_CACHE[key] = cached
    return cached


def ssh_opts(task_id):
    """Reuse a single TCP connection and one authentication for every ssh/scp
    call belonging to a task.

    start() and stop() together make up to seven ssh/scp invocations per task,
    each of which otherwise pays a full TCP handshake, key exchange and
    authentication. ControlPersist keeps the master around long enough to cover
    the gap between start() and stop().

    BatchMode stops ssh from blocking on a password prompt, which would
    otherwise hang until the subprocess timeout.
    """
    return [
        "-o",
        "BatchMode=yes",
        "-o",
        "ControlMaster=auto",
        "-o",
        f"ControlPath=/tmp/cape-sniffer-{task_id}-%C",
        "-o",
        "ControlPersist=600",
    ]


class Sniffer(Auxiliary):
    sudo_path = "/usr/bin/sudo"

    def __init__(self):
        Auxiliary.__init__(self)
        self.proc = None
        # Only set on the remote path, and only once the remote sniffer is up.
        # stop() has to cope with it never having been assigned.
        self.pid = None

    def start(self):
        if not router_cfg.routing.enable_pcap and self.task.route in ("none", "None", "drop", "false"):
            return

        # Get updated machine info
        self.machine = self.db.view_machine_by_label(self.machine.label)

        # I got tired of Ubuntu's renaming
        tcpdump = self.options.get("tcpdump", "/usr/bin/tcpdump")
        tcpdump_found = path_exists(tcpdump)
        if not tcpdump_found:
            for path in ("/usr/bin/tcpdump", "/usr/sbin/tcpdump"):
                if path_exists(path):
                    tcpdump = path
                    tcpdump_found = True
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
            if not tcpdump_found:
                log.error('Tcpdump does not exist at path "%s", network capture aborted', tcpdump)
                return

            sudo = sudo_allows_tcpdump(self.sudo_path, tcpdump)
            if not sudo:
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

        if not interface:
            log.error("Network interface not defined, network capture aborted")
            return

        # Trying to save pcap with the same user which cape is running.
        user = None
        if not remote:
            try:
                user = getpass.getuser()
            except Exception:
                pass

        pargs = build_tcpdump_args(
            tcpdump,
            interface,
            host,
            file_path,
            resultserver_ip,
            resultserver_port,
            user=user,
            custom=custom,
            bpf=bpf,
            sudo_path=self.sudo_path if sudo else None,
            fog_host=fog_Host if physical_machinery else None,
        )

        if remote and not remote_host:
            log.error("Failed to start sniffer, remote enabled but no ssh string has been specified")
            return
        elif remote:
            # shlex.join quotes every token, so parentheses and any shell
            # metacharacters coming from the custom/bpf options reach tcpdump
            # intact instead of being interpreted by the remote shell.
            script = build_remote_script(shlex.join(pargs), self.task.id)

            try:
                # The script is fed to the remote shell on stdin and echoes the
                # pid back on stdout, so starting the sniffer costs one ssh
                # connection instead of scp + ssh + ssh cat + ssh rm. Nothing is
                # left behind in /tmp on either host either.
                self.pid = (
                    subprocess.run(
                        ["ssh", *ssh_opts(self.task.id), remote_host, "/bin/bash", "-s"],
                        input=script.encode(),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=True,
                        timeout=30,
                    )
                    .stdout.decode()
                    .strip()
                )
                log.info(
                    "Started remote sniffer @ %s with (interface=%s, host=%s, dump path=%s, pid=%s)",
                    remote_host,
                    interface,
                    host,
                    file_path,
                    self.pid,
                )
            except subprocess.TimeoutExpired:
                log.error("Timeout connecting to remote host %s", remote_host)
            except subprocess.CalledProcessError as e:
                log.error("Error connecting to remote host %s: %s", remote_host, e.stderr.decode(errors="replace").strip())

        else:
            try:
                self.proc = subprocess.Popen(pargs, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
            except (OSError, ValueError):
                log.exception("Failed to start sniffer (interface=%s, host=%s, dump path=%s)", interface, host, file_path)
                return

            log.info(
                "Started sniffer with PID %d (interface=%s, host=%s, dump path=%s)",
                self.proc.pid,
                interface,
                host,
                file_path,
            )

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """

        if not router_cfg.routing.enable_pcap and self.task.route in ("none", "None", "drop", "false"):
            return

        remote = self.options.get("remote", False)
        if remote:
            if not self.pid:
                # start() never got as far as reading back the remote pid.
                log.warning("No remote sniffer pid recorded, nothing to stop")
                return

            remote_host = self.options.get("host", "")
            opts = ssh_opts(self.task.id)

            try:
                subprocess.check_output(["ssh", *opts, remote_host, "kill", "-2", self.pid], timeout=30)

                file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "dump.pcap")
                file_path2 = f"/tmp/tcp.dump.{self.task.id}"

                subprocess.check_output(["scp", "-q", *opts, f"{remote_host}:{file_path2}", file_path], timeout=300)
                subprocess.check_output(
                    [
                        "ssh",
                        *opts,
                        remote_host,
                        "rm",
                        "-f",
                        file_path2,
                        f"/tmp/cape-sniffer-{self.task.id}.log",
                        f"/tmp/cape-sniffer-{self.task.id}.err",
                    ],
                    timeout=30,
                )
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                log.error("Error stopping remote sniffer: %s", e)
            finally:
                # Close the multiplexing master instead of waiting out
                # ControlPersist; this talks to the local control socket only.
                subprocess.run(
                    ["ssh", *opts, "-O", "exit", remote_host],
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
            return

        if not self.proc:
            return

        # poll() is None while running and the exit code once it has exited, so
        # `not poll()` was True for a clean exit and False for a failed one.
        if self.proc.poll() is not None:
            # tcpdump is already gone - a bad filter expression, for instance,
            # makes it exit immediately. Report why instead of trying to kill it.
            _, stderr = self.proc.communicate()
            log.error(
                "Sniffer already exited with code %d before it was stopped: %s",
                self.proc.returncode,
                stderr.decode(errors="replace").strip() if stderr else "no output",
            )
            return

        if self.proc.args[0] == self.sudo_path and "-Z" in self.proc.args:
            # We must kill the child process that sudo spawned. We won't
            # have permission to kill the parent process because it's owned by root.
            try:
                output = subprocess.check_output(["ps", "--ppid", str(self.proc.pid), "-o", "pid="], timeout=30).decode().strip()
                pid = int(output.split()[0])
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, TypeError, ValueError, IndexError):
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
            _, _ = self.proc.communicate(timeout=5)
        except Exception as e:
            log.error("Unable to stop the sniffer (first try) with pid %d: %s", pid, e)
            try:
                if self.proc.poll() is None:
                    log.debug("Killing sniffer")
                    kill_func()
                    _, _ = self.proc.communicate(timeout=5)
            except OSError as e:
                log.debug("Error killing sniffer: %s, continuing", e)
            except Exception as e:
                log.exception("Unable to stop the sniffer with pid %d: %s", pid, e)
