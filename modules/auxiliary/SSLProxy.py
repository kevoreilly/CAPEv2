import logging
import os
import shlex
import signal
import socket
import subprocess

from contextlib import closing
from threading import Thread

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.rooter import rooter

log = logging.getLogger(__name__)

sslproxy_cfg = Config("sslproxy")


class SSLProxy(Auxiliary):
    """Per-analysis SSLproxy TLS interception with STARTTLS support.

    Uses a single SSLproxy autossl listener per analysis. All VM TCP traffic is
    NAT REDIRECT'd to it. SSLproxy detects TLS ClientHello on any port and
    STARTTLS upgrades, intercepts them with MITM, and passes non-TLS through.

    Enabled per-task via the ``sslproxy=1`` task option.
    """

    def __init__(self):
        Auxiliary.__init__(self)
        Thread.__init__(self)
        self.sslproxy_thread = None

    def start(self):
        self.sslproxy_thread = SSLProxyThread(self.task, self.machine)
        self.sslproxy_thread.start()
        return True

    def stop(self):
        if self.sslproxy_thread:
            self.sslproxy_thread.stop()


class SSLProxyThread(Thread):
    """Thread controlling per-analysis SSLproxy instance."""

    # Fwmark range for per-analysis upstream VPN routing.
    # Each analysis gets fwmark_base + (task_id % fwmark_range).
    FWMARK_BASE = 100
    FWMARK_RANGE = 900

    def __init__(self, task, machine):
        Thread.__init__(self)
        self.task = task
        self.machine = machine
        self.storage_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                        str(self.task.id), "sslproxy")
        self.proc = None
        self.log_file = None
        self.do_run = True
        self._rooter_enabled = False

        # Config
        self.sslproxy_bin = sslproxy_cfg.cfg.get("bin")
        self.ca_cert = sslproxy_cfg.cfg.get("ca_cert")
        self.ca_key = sslproxy_cfg.cfg.get("ca_key")
        self.interface = sslproxy_cfg.cfg.get("interface")

        # Per-analysis fwmark for upstream VPN routing
        fwmark_base = int(sslproxy_cfg.cfg.get("fwmark_base", self.FWMARK_BASE))
        fwmark_range = int(sslproxy_cfg.cfg.get("fwmark_range", self.FWMARK_RANGE))
        self.fwmark = str(fwmark_base + (self.task.id % fwmark_range))

        # Single autossl port handles everything
        self.proxy_port = self._get_unused_port()
        self.resultserver_port = str(getattr(self.machine, 'resultserver_port', 2042))

        # Determine routing table for upstream VPN routing
        routing_conf = Config("routing")
        self.route = self.task.route or routing_conf.routing.route
        self.rt_table = ""
        if self.route and self.route not in ("none", "None", "drop", "false", "inetsim", "tor"):
            if hasattr(routing_conf, self.route):
                entry = routing_conf.get(self.route)
                self.rt_table = str(getattr(entry, 'rt_table', ''))
            elif self.route.startswith("tun"):
                self.rt_table = self.route
            elif self.route == "internet":
                self.rt_table = str(routing_conf.routing.rt_table) if routing_conf.routing.rt_table else ""

    def _get_unused_port(self):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(("", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return str(s.getsockname()[1])

    def _is_sslproxy_requested(self):
        """Check if sslproxy=1 is set in task options."""
        for opt in (self.task.options or "").split(","):
            opt = opt.strip()
            if "=" in opt:
                key, val = opt.split("=", 1)
                if key.strip() == "sslproxy":
                    return val.strip() not in ("0", "no", "false", "")
        return False

    def run(self):
        log.info("SSLProxy thread running for task %s", self.task.id)
        if not self._is_sslproxy_requested():
            log.info("SSLProxy not requested for task %s, skipping", self.task.id)
            return

        if not self.do_run:
            return

        if not self.proxy_port:
            log.error("SSLProxy failed to allocate port")
            return

        # Set up NAT REDIRECT + per-analysis upstream VPN routing
        try:
            rooter("sslproxy_enable", self.interface, self.machine.ip,
                   self.proxy_port, self.resultserver_port, self.rt_table,
                   self.fwmark)
            self._rooter_enabled = True
        except Exception as e:
            log.exception("Failed to enable SSLproxy iptables rules: %s", e)
            return

        try:
            self._start_sslproxy()
        except Exception as e:
            log.error("Failed to start SSLproxy for task %s: %s", self.task.id, e)
            self._disable_rooter()

    def _start_sslproxy(self):
        """Build command and launch SSLproxy process."""
        os.makedirs(self.storage_dir, exist_ok=True)

        conn_log = os.path.join(self.storage_dir, "connections.log")
        master_keys = os.path.join(self.storage_dir, "master_keys.log")
        pcap_file = os.path.join(self.storage_dir, "sslproxy.pcap")

        # Build command as a list to avoid shell injection
        sslproxy_cmd = [
            self.sslproxy_bin, "-D",
            "-k", self.ca_key, "-c", self.ca_cert,
            "-l", conn_log, "-X", pcap_file, "-M", master_keys,
            "-u", "root", "-o", "VerifyPeer=no", "-P",
            "autossl", "0.0.0.0", self.proxy_port, "up:80",
        ]

        # Launch in per-VM cgroup so iptables cgroup match can route upstream through VPN.
        cgroup_procs = f"/sys/fs/cgroup/sslproxy/{self.machine.ip}/cgroup.procs"
        shell_cmd = "echo $$ > {} 2>/dev/null; exec {}".format(
            shlex.quote(cgroup_procs),
            " ".join(shlex.quote(arg) for arg in sslproxy_cmd),
        )
        popen_args = ["sudo", "bash", "-c", shell_cmd]

        self.log_file = open(os.path.join(self.storage_dir, "sslproxy.log"), "w")
        self.log_file.write(" ".join(sslproxy_cmd) + "\n")
        self.log_file.flush()

        try:
            self.proc = subprocess.Popen(popen_args, stdout=self.log_file,
                                         stderr=self.log_file, shell=False,
                                         start_new_session=True)
        except (OSError, subprocess.SubprocessError):
            self.log_file.close()
            self.log_file = None
            raise

        log.info("Started SSLproxy PID %d for task %s (autossl port=%s, VM=%s, fwmark=%s)",
                 self.proc.pid, self.task.id, self.proxy_port, self.machine.ip, self.fwmark)

    def _disable_rooter(self):
        """Remove per-VM iptables rules."""
        if not self._rooter_enabled:
            return
        try:
            rooter("sslproxy_disable", self.interface, self.machine.ip,
                   self.proxy_port, self.resultserver_port, self.rt_table,
                   self.fwmark)
            self._rooter_enabled = False
        except Exception as e:
            log.error("Failed to disable SSLproxy iptables rules: %s", e)

    def stop(self):
        self.do_run = False

        try:
            if self.proc and self.proc.poll() is None:
                log.info("Stopping SSLproxy for task %s", self.task.id)
                try:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                    self.proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    log.warning("SSLproxy did not exit gracefully, killing")
                    try:
                        os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                        self.proc.wait(timeout=5)
                    except OSError:
                        pass
                except OSError:
                    pass  # Process already exited
        except Exception as e:
            log.error("Failed to stop SSLproxy: %s", e)
        finally:
            self.proc = None
            if self.log_file:
                self.log_file.close()
                self.log_file = None
            self._disable_rooter()
