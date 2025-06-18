import logging
import os
import socket
import subprocess
import re

from contextlib import closing
from threading import Thread

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.rooter import rooter

log = logging.getLogger(__name__)

polarproxy = Config("polarproxy")
routing = Config("routing")

class PolarProxy(Auxiliary):
    """Module for generating PCAP with PolarProxy."""

    def __init__(self):
        Auxiliary.__init__(self)
        Thread.__init__(self)
        log.info("PolarProxy module loaded")
        self.polarproxy_thread = None

    def start(self):
        """Start PolarProxy in a separate thread."""

        self.polarproxy_thread = PolarProxyThread(self.task, self.machine)
        self.polarproxy_thread.start()
        return True

    def stop(self):
        """Stop PolarProxy capture thread."""
        if self.polarproxy_thread:
            self.polarproxy_thread.stop()


class PolarProxyThread(Thread):
    """Thread responsible for control PolarProxy service for each analysis."""

    def __init__(self, task, machine):
        Thread.__init__(self)
        self.task = task
        self.machine = machine
        self.proc = None
        self.do_run = True
        self.host_ip = polarproxy.cfg.get("host")
        self.host_iface = polarproxy.cfg.get("interface")
        self.polar_path = polarproxy.cfg.get("bin")
        self.cert = polarproxy.cfg.get("cert")
        self.password = polarproxy.cfg.get("password")
        self.ruleset = polarproxy.cfg.get("ruleset")
        self.tlsport = 443
        self.listen_port = self._get_unused_port()
        self.pcap_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "polarproxy")

    def _get_unused_port(self) -> str | None:
        """Return the first unused TCP port from the set."""
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                s.bind(('', 0))
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                return s.getsockname()[1]
        return None

    def run(self):

        if "polarproxy" not in self.task.options:
            log.info("Exiting polarproxy. No parameter received.")
            return

        if self.do_run:
            if not self.listen_port:
                log.exception("PolarProxy failed to find an available bind port. Bailing...")
                return

            if "tlsport" in self.task.options:
                match = re.search(r"tlsport=(\d+)", self.task.options)
                if not match:
                    log.warning("Failed to parse 'tlsport' out of options (%s). Defaulting to %d.", self.task.options, self.tlsport)
                else:
                    self.tlsport = match.groups()[0]

            try:
                rooter("polarproxy_enable", self.host_iface, self.machine.ip, str(self.tlsport), str(self.listen_port))
            except subprocess.CalledProcessError as e:
                log.exception("Failed to execute firewall rules: %s. Bailing...", e)
                return

            log.info("Starting PolarProxy process")

            os.makedirs(self.pcap_dir, exist_ok=True)
            file_path = os.path.join(self.pcap_dir, "tls.pcap")

            polarproxy_args = [
                self.polar_path,
                "-v",
                "-w",
                file_path,
                "--writeall",
                "--autoflush",
                "1",
                "--cacert",
                f"load:{self.cert}:{self.password}",
                "--leafcert",
                "sign",
            ]

            if self.ruleset:
                polarproxy_args += ["--ruleset", self.ruleset]

            # LISTEN-IP             IPv4 or IPv6 address to bind proxy to.
            # LISTEN-PORT           TCP port to bind proxy to.
            # DECRYPTED-PORT        TCP server port to use for decrypted traffic in PCAP.
            # EXTERNAL-PORT         TCP port for proxy to connect to. Default value is same as LISTEN-PORT.

            if self.task.route == "inetsim":
                # For some dark magic iptables reason I cannot get around, it does not appear feasible
                # to redirect packets from client destined for port 443 to a local service listening on
                # port XYZ _AND_ have iptables DNAT that same packet to inetsim. After PREROUTING to
                # localhost:XYZ, iptables briefly "loses track" of the packet, so when it comes back
                # out of PolarProxy and hits the OUTPUT table, the source IP is localhost and iptables
                # cannot distinguish if the packet came from the host or has been proxied. This means
                # the packet also cannot be masqueraded because it has not been forwarded, it has been
                # proxied. Redirecting all 443 from localhost to inetsim would be very unpleasant for
                # the hosts HTTPS stack. So, PolarProxy is made a termination proxy and forwards the
                # decrypted HTTP to inetsim.
                polarproxy_args += [
                    "-p",
                    f"{self.host_ip},{self.listen_port},{self.tlsport},80",
                    "--terminate",
                    "--nosni",
                    "nosni.inetsim.org",
                    "--connect",
                    routing.inetsim.server,
                ]
            else:
                # FTODO: Figure out other route configurations?
                polarproxy_args += ["-p", f"{self.host_ip},{self.listen_port},80,{self.tlsport}"]

            try:
                self.proc = subprocess.Popen(polarproxy_args, stdout=None, stderr=None, shell=False)
            except:
                log.exception("Failed to PolarProxy (host=%s, port=%s, dump_path=%s)", self.host_ip, self.listen_port, file_path)
                return

            log.info(
                "Started PolarProxy with PID %d (host=%s, port=%s, dump_path=%s)",
                self.proc.pid,
                self.host_ip,
                self.listen_port,
                file_path,
            )

    def stop(self):
        """Set stop PolarProxy capture."""
        self.do_run = False

        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait()
            log.info("Stopping PolarProxy")

        try:
            rooter("polarproxy_disable", self.host_iface, self.machine.ip, str(self.tlsport), str(self.listen_port))
        except subprocess.CalledProcessError as e:
            log.error("Failed to execute firewall rules: %s", e)
