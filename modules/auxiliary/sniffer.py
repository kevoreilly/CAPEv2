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

            try:
                subprocess.check_call(
                    [self.sudo_path, "--list", "--non-interactive", tcpdump],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
            except (FileNotFoundError, subprocess.CalledProcessError) as e:
                # https://github.com/cuckoosandbox/cuckoo/pull/2842/files
                sudo_err = (
                    e.stderr.decode(errors="replace").strip()
                    if isinstance(e, subprocess.CalledProcessError) and e.stderr
                    else str(e)
                )
                mode = os.stat(tcpdump).st_mode
                if mode & S_ISUID:
                    log.error(
                        "Tcpdump is not accessible for this user (%s). Network capture aborted. "
                        "You probably need to grant sudo access to %s or add CAPE user to "
                        "pcap group",
                        sudo_err,
                        tcpdump,
                    )
                    return
                log.warning(
                    "Sudo check for %s failed (%s); attempting to run tcpdump without sudo",
                    tcpdump,
                    sudo_err,
                )
            else:
                sudo = True

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
            command = shlex.join(pargs)
            with open(f"/tmp/{self.task.id}.sh", "w") as f:
                f.write(f"{command} & PID=$!")
                f.write("\n")
                f.write(f"echo $PID > /tmp/{self.task.id}.pid")
                f.write("\n")

            try:
                subprocess.check_output(
                    ["scp", "-q", f"/tmp/{self.task.id}.sh", remote_host + f":/tmp/{self.task.id}.sh"], timeout=30
                )
                subprocess.check_output(
                    [
                        "ssh",
                        remote_host,
                        "nohup",
                        "/bin/bash",
                        f"/tmp/{self.task.id}.sh",
                        ">",
                        "/tmp/log",
                        "2>",
                        "/tmp/err",
                    ],
                    timeout=30,
                )

                self.pid = (
                    subprocess.check_output(
                        ["ssh", remote_host, "cat", f"/tmp/{self.task.id}.pid"], stderr=subprocess.DEVNULL, timeout=30
                    )
                    .decode()
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
                subprocess.check_output(
                    ["ssh", remote_host, "rm", "-f", f"/tmp/{self.task.id}.pid", f"/tmp/{self.task.id}.sh"], timeout=30
                )
            except subprocess.TimeoutExpired:
                log.error("Timeout connecting to remote host %s", remote_host)
            except subprocess.CalledProcessError as e:
                log.error("Error connecting to remote host %s: %s", remote_host, e)

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

    def _reap_proc(self, timeout=2):
        if not self.proc:
            return "", ""
        try:
            out, err = self.proc.communicate(timeout=timeout)
            out_str = (out or b"").decode(errors="replace").strip() if isinstance(out, bytes) else str(out or "").strip()
            err_str = (err or b"").decode(errors="replace").strip() if isinstance(err, bytes) else str(err or "").strip()
            return out_str, err_str
        except Exception as e:
            return "", f"<communicate failed: {e}>"

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """

        if not router_cfg.routing.enable_pcap and self.task.route in ("none", "None", "drop", "false"):
            return

        remote = self.options.get("remote", False)
        if remote:
            if not self.pid:
                # start() never got as far as reading the remote pid file.
                log.warning("No remote sniffer pid recorded, nothing to stop")
                return

            remote_host = self.options.get("host", "")
            remote_args = ["ssh", remote_host, "kill", "-2", self.pid]

            try:
                subprocess.check_output(remote_args, timeout=30)

                file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "dump.pcap")
                file_path2 = f"/tmp/tcp.dump.{self.task.id}"

                subprocess.check_output(["scp", "-q", f"{remote_host}:{file_path2}", file_path], timeout=300)
                subprocess.check_output(["ssh", remote_host, "rm", "-f", file_path2], timeout=30)
            except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
                log.error("Error stopping remote sniffer: %s", e)
            return

        if not self.proc:
            return

        poll_rc = self.proc.poll()
        if poll_rc is not None:
            out, err = self._reap_proc(timeout=2)
            if poll_rc != 0:
                log.error(
                    "Sniffer process (pid %d) exited prematurely with code %d before stop() (args=%s, stdout=%r, stderr=%r)",
                    self.proc.pid,
                    poll_rc,
                    getattr(self.proc, "args", None),
                    out,
                    err,
                )
            else:
                log.warning(
                    "Sniffer process (pid %d) already exited with code 0 before stop() (args=%s, stdout=%r, stderr=%r)",
                    self.proc.pid,
                    getattr(self.proc, "args", None),
                    out,
                    err,
                )
            return

        if getattr(self.proc, "args", None) and self.proc.args[0] == self.sudo_path and "-Z" in self.proc.args:
            # We must kill the child process that sudo spawned. We won't
            # have permission to kill the parent process because it's owned by root.
            try:
                output = (
                    subprocess.check_output(
                        ["ps", "--ppid", str(self.proc.pid), "-o", "pid="],
                        stderr=subprocess.PIPE,
                        timeout=30,
                    )
                    .decode(errors="replace")
                    .strip()
                )
                pids = [int(p) for p in output.split() if p.isdigit()]
                if not pids:
                    poll_after = self.proc.poll()
                    out, err = self._reap_proc(timeout=2)
                    log.error(
                        "Failed to get child pid of sudo sniffer (pid %d, poll=%s, returncode=%s): "
                        "ps returned no pids (ps_output=%r, stdout=%r, stderr=%r, args=%s)",
                        self.proc.pid,
                        poll_after,
                        self.proc.returncode,
                        output,
                        out,
                        err,
                        self.proc.args,
                    )
                    return
                pid = pids[0]
            except subprocess.CalledProcessError as e:
                poll_after = self.proc.poll()
                out, err = self._reap_proc(timeout=2)
                ps_out = (e.output or b"").decode(errors="replace").strip()
                ps_err = (e.stderr or b"").decode(errors="replace").strip()
                log.error(
                    "Failed to get child pid of sudo sniffer (pid %d, poll=%s, returncode=%s): "
                    "ps exited with %d (ps_stdout=%r, ps_stderr=%r, stdout=%r, stderr=%r, args=%s)",
                    self.proc.pid,
                    poll_after,
                    self.proc.returncode,
                    e.returncode,
                    ps_out,
                    ps_err,
                    out,
                    err,
                    self.proc.args,
                )
                return
            except Exception as e:
                poll_after = self.proc.poll()
                out, err = self._reap_proc(timeout=2)
                log.error(
                    "Failed to get child pid of sudo sniffer (pid %d, poll=%s, returncode=%s): %s "
                    "(stdout=%r, stderr=%r, args=%s)",
                    self.proc.pid,
                    poll_after,
                    self.proc.returncode,
                    e,
                    out,
                    err,
                    self.proc.args,
                )
                return
            term_func = functools.partial(os.kill, pid, signal.SIGTERM)
            kill_func = functools.partial(os.kill, pid, signal.SIGKILL)
        else:
            term_func = self.proc.terminate
            kill_func = self.proc.kill
            pid = self.proc.pid

        try:
            term_func()
            self.proc.communicate(timeout=5)
        except ProcessLookupError as e:
            out, err = self._reap_proc(timeout=2)
            log.warning(
                "Sniffer process %d already terminated before signal: %s (returncode=%s, stdout=%r, stderr=%r)",
                pid,
                e,
                self.proc.returncode,
                out,
                err,
            )
        except Exception as e:
            log.error("Unable to stop the sniffer (first try) with pid %d: %s", pid, e)
            try:
                if self.proc.poll() is None:
                    log.debug("Killing sniffer")
                    kill_func()
                    self.proc.communicate(timeout=5)
            except (OSError, ProcessLookupError) as e:
                log.debug("Error killing sniffer: %s, continuing", e)
            except Exception as e:
                log.exception("Unable to stop the sniffer with pid %d: %s", pid, e)
