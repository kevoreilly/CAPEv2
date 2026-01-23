import json
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
        self.storage_dir = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id), "polarproxy")
        self.machine = machine
        self.proc = None
        self.log_file = None
        self.pcap = None
        self.do_run = True
        self.host_ip = polarproxy.cfg.get("host")
        self.host_iface = polarproxy.cfg.get("interface")
        self.polar_path = polarproxy.cfg.get("bin")
        self.cert = polarproxy.cfg.get("cert")
        self.password = polarproxy.cfg.get("password")
        self.bypass_domains = polarproxy.cfg.get("bypass_list")
        self.block_domains = polarproxy.cfg.get("block_list")
        self.ruleset = os.path.join(self.storage_dir, "ruleset.json")
        self.tlsport = 443
        self.listen_port = self._get_unused_port()

    def _get_unused_port(self) -> int | None:
        """Return the first unused TCP port from the set."""
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(("", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]
        return None

    def generate_ruleset(self):
        """Generate PolarProxy TLS firewall ruleset JSON file."""
        ruleset_json = {
            "name": "PolarProxy ruleset for CAPEv2.",
            "version": "1.0",
            "description": "A curated ruleset generated on the fly to block/bypass specific domain patterns AND handle termination proxying to InetSim.",
            "rules": [],
        }
        if self.task.route == "inetsim":
            # It does not appear feasible to redirect packets from client destined for port 443 to
            # a local service listening on port XYZ _AND_ have iptables DNAT that same packet to
            # inetsim. After PREROUTING to localhost:XYZ, iptables briefly "loses track" of the
            # packet, so when it comes back out of PolarProxy and hits the OUTPUT table, the
            # source IP is localhost and iptables cannot distinguish if the packet came from the
            # host or has been proxied. This means the packet also cannot be masqueraded because
            # it has not been forwarded, it has been proxied. Redirecting all 443 from localhost
            # to inetsim would be very unpleasant for the hosts HTTPS stack. So, PolarProxy is
            # made a termination proxy and forwards the decrypted HTTP to inetsim.
            #
            # Using this ruleset approach instead of `--terminate --connect` is safer because the
            # default action type "inspect" will clash with these flags and try to decrypt already
            # decrypted traffic.
            ruleset_json["default"] = {
                "action": {"type": "terminate", "target": f"{routing.inetsim.server}:80"},
                "description": "Terminate TLS and forward to InetSim server.",
            }
        else:
            ruleset_json["default"] = {
                "action": {"type": "inspect"},
                "description": "Inspect any traffic that is not bypassed or blocked.",
            }

        # If bypass domains are specified in polarproxy.conf, add a block rule for each domain within.
        if self.block_domains:
            with open(self.block_domains, "r") as fh:
                domain_regexes = [line.strip() for line in fh.readlines() if line.strip()]
            for domain_regex in domain_regexes:
                ruleset_json["rules"].append(
                    {"active": True, "match": {"type": "domain_regex", "expression": domain_regex}, "action": {"type": "block"}}
                )

        # If bypass domains are specified in polarproxy.conf, add a bypass rule for each domain within.
        if self.bypass_domains:
            with open(self.bypass_domains, "r") as fh:
                domain_regexes = [line.strip() for line in fh.readlines() if line.strip()]
            for domain_regex in domain_regexes:
                ruleset_json["rules"].append(
                    {"active": True, "match": {"type": "domain_regex", "expression": domain_regex}, "action": {"type": "bypass"}}
                )

        with open(self.ruleset, "w") as fh:
            json.dump(ruleset_json, fh, indent=2)

    def run(self):
        if "polarproxy=" not in self.task.options:
            log.info("Exiting polarproxy. No parameter received.")
            return

        if self.do_run:
            if not self.listen_port:
                log.exception("PolarProxy failed to find an available bind port. Bailing...")
                return

            # See if user specified a different TLS port to intercept on.
            if "tlsport" in self.task.options:
                match = re.search(r"tlsport=(\d+)", self.task.options)
                if not match:
                    log.warning("Failed to parse 'tlsport' out of options (%s). Defaulting to %d.", self.task.options, self.tlsport)
                else:
                    self.tlsport = int(match.groups()[0])

            try:
                rooter("polarproxy_enable", self.host_iface, self.machine.ip, str(self.tlsport), str(self.listen_port))
            except subprocess.CalledProcessError as e:
                log.exception("Failed to execute firewall rules: %s. Bailing...", e)
                return

            log.info("Starting PolarProxy process")

            # Create directory to store pcap and logs.
            os.makedirs(self.storage_dir, exist_ok=True)

            # Create ruleset file to bypass/block domains AND terminate proxy to InetSim if applicable
            self.generate_ruleset()

            # Specify where to dump decrypted traffic PCAP
            self.pcap = os.path.join(self.storage_dir, "tls.pcap")

            # Craft polarproxy command.
            polarproxy_args = [
                self.polar_path,
                # Provide debugging output incase TLS MITMing fails for some reason.
                "-d",
                # PCAP to write to.
                "-w",
                self.pcap,
                # Write data to PCAP once a second so it's always there when the proc gets killed.
                "--autoflush",
                "1",
                # Specify CA cert that client VM will be expecting.
                "--cacert",
                f"load:{self.cert}:{self.password}",
                # Always sign generated certs with PP's root CA, even when original server cert isn't trusted.
                "--leafcert",
                "sign",
                "--ruleset",
                self.ruleset,
                # Allow clients to not provide an SNI
                "--nosni",
                "nosni.example.org",
                # LISTEN-IP             IPv4 or IPv6 address to bind proxy to.
                # LISTEN-PORT           TCP port to bind proxy to.
                # DECRYPTED-PORT        TCP server port to use for decrypted traffic in PCAP.
                # EXTERNAL-PORT         TCP port for proxy to connect to. Default value is same as LISTEN-PORT.
                "-p",
                f"{self.host_ip},{self.listen_port},80,{self.tlsport}",
            ]

            # Open up log file handle
            self.log_file = open(os.path.join(self.storage_dir, "polarproxy.log"), "w")

            # Log PolarProxy command for safe keeping
            self.log_file.write(f"{' '.join(polarproxy_args)}\n")
            self.log_file.flush()

            try:
                self.proc = subprocess.Popen(polarproxy_args, stdout=self.log_file, stderr=self.log_file, shell=False)
            except (OSError, subprocess.SubprocessError) as e:
                log.info(
                    "Failed to start PolarProxy (host=%s, port=%s, dump_path=%s, log=%s). Error(%s)",
                    self.host_ip,
                    self.listen_port,
                    self.pcap,
                    self.log_file,
                    str(e)
                )
                self.log_file.close()
                self.log_file = None
                return

            log.info(
                "Started PolarProxy with PID %d (host=%s, port=%s, dump_path=%s, log=%s)",
                self.proc.pid,
                self.host_ip,
                self.listen_port,
                self.pcap,
                self.log_file,
            )

    def stop(self):
        """Set stop PolarProxy capture."""
        self.do_run = False

        if self.log_file:
            self.log_file.close()
            self.log_file = None

        try:
            if self.proc and self.proc.poll() is None:
                log.info("Stopping PolarProxy")
                self.proc.terminate()
                self.proc.wait()

        except subprocess.SubprocessError as e:
            log.error("Failed to shutdown PolarProxy module: %s", e)
        finally:
            self.proc = None
            log.info("Cleaning up PolarProxy iptables rules")
            rooter("polarproxy_disable", self.host_iface, self.machine.ip, str(self.tlsport), str(self.listen_port))
