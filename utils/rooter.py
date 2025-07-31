#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import argparse
import errno
import grp
import ipaddress
import json
import logging.handlers
import os
import signal
import socket
import stat
import subprocess
import sys

if sys.version_info[:2] < (3, 10):
    sys.exit("You are running an incompatible version of Python, please use >= 3.10")

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CUCKOO_ROOT)

from lib.cuckoo.common.path_utils import path_delete, path_exists

username = False
log = logging.getLogger("cuckoo-rooter")
formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
ch = logging.StreamHandler()
ch.setFormatter(formatter)
log.addHandler(ch)
log.setLevel(logging.INFO)

class s:
    iptables = None
    iptables_save = None
    iptables_restore = None
    ip = None


def run(*args):
    """Wrapper to Popen."""
    log.debug("Running command: %s", " ".join(args))
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    stdout, stderr = p.communicate()
    return stdout, stderr


def get_tun_peer_address(interface_name):
    """Gets the peer address of a tun interface.

    Args:
        interface_name: The name of the tun interface (e.g., "tun0").
        Format similar to:
        inet 172.30.1.5 peer 172.30.1.6/32 scope global

    Returns:
        The peer IP address as a string, or None if an error occurs.  Returns None if the interface does not exist, or does not have a peer.
    """
    try:
        result = subprocess.run(["ip", "addr", "show", interface_name], capture_output=True, text=True, check=True)
        output = result.stdout

        for line in output.splitlines():
            if "peer" in line:
                parts = line.split()
                if len(parts) > 1:  # Check if there's a second element to avoid IndexError
                    peer_with_cidr = parts[3]
                    try:
                        # Handle CIDR notation using ipaddress library
                        peer_ip = ipaddress.ip_interface(peer_with_cidr).ip.exploded
                        return peer_ip
                    except ValueError:  # Handle invalid CIDR notations
                        try:
                            peer_ip = peer_with_cidr.split("/")[0]  # Try just splitting by /
                            return peer_ip
                        except IndexError:
                            return None  # Invalid format - give up.
                else:
                    return None  # No peer address found on the line.
        return None  # "peer" not found in the output

    except subprocess.CalledProcessError as e:
        if e.returncode == 1:  # Interface not found
            return None
        else:
            print(f"Error executing ip command: {e}")
            return None
    except FileNotFoundError:
        print("ip command not found. Is iproute2 installed?")
        return None


def enable_ip_forwarding(sysctl="/usr/sbin/sysctl"):
    log.debug("Enabling IPv4 forwarding")
    run(sysctl, "-w" "net.ipv4.ip_forward=1")


def check_tuntap(vm_name, main_iface):
    """Create tuntap device for qemu vms"""
    try:
        run(s.ip, "tuntap", "add", "dev", f"tap_{vm_name}", "mode", "tap", "user", username)
        run(s.ip, "link", "set", "tap_{vm_name}", "master", main_iface)
        run(s.ip, "link", "set", "dev", "tap_{vm_name}", "up")
        run(s.ip, "link", "set", "dev", main_iface, "up")
        return True
    except subprocess.CalledProcessError:
        return False


def run_iptables(*args, **kwargs):
    if kwargs and kwargs.get('netns'):
        netns = kwargs.get('netns')
        iptables_args = ["/usr/sbin/ip", "netns", "exec", netns, s.iptables]
    else:
        iptables_args = [s.iptables]

    iptables_args.extend(list(args))
    iptables_args.extend(["-m", "comment", "--comment", "CAPE-rooter"])
    return run(*iptables_args)


def cleanup_rooter():
    """Filter out all CAPE rooter entries from iptables-save and
    restore the resulting ruleset."""
    stdout = False
    try:
        stdout, _ = run(s.iptables_save)
    except OSError as e:
        log.error("Failed to clean CAPE rooter rules. Is iptables-save available? %s", e)
        return

    if not stdout:
        return

    cleaned = [line for line in stdout.split("\n") if line and "CAPE-rooter" not in line]

    p = subprocess.Popen([s.iptables_restore], stdin=subprocess.PIPE, universal_newlines=True)
    p.communicate(input="\n".join(cleaned))

    run_iptables("-F", "CAPE_ACCEPTED_SEGMENTS")
    run_iptables("-F", "CAPE_REJECTED_SEGMENTS")
    run_iptables("-N", "CAPE_ACCEPTED_SEGMENTS")
    run_iptables("-N", "CAPE_REJECTED_SEGMENTS")
    run_iptables("-I", "FORWARD", "-j", "CAPE_REJECTED_SEGMENTS")
    run_iptables("-I", "FORWARD", "-j", "CAPE_ACCEPTED_SEGMENTS")


def nic_available(interface):
    """Check if specified network interface is available."""
    try:
        subprocess.check_call(
            [settings.ip, "link", "show", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def rt_available(rt_table):
    """Check if specified routing table is defined."""
    try:
        subprocess.check_call(
            [settings.ip, "route", "list", "table", rt_table],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def init_vrf(rt_table, dirty_line_dev):
    run(s.ip, "link", "add", "dirty-line", "type", "vrf", "table", rt_table)
    run(s.ip, "link", "set", "dev", "dirty-line", "up")
    run(s.ip, "rule", "add", "l3mdev", "proto", "kernel", "prio", "1000")
    run(s.ip, "rule", "add", "l3mdev", "proto", "kernel", "unreachable", "prio", "1001")
    run(s.ip, "rule", "add", "lookup", "local", "proto", "kernel", "prio", "32765")
    run(s.ip, "rule", "delete", "lookup", "local", "prio", "0")
    run(s.ip, "link", "set", "dev", dirty_line_dev, "master", "dirty-line")


def cleanup_vrf(dirty_line_dev):
    run(s.ip, "rule", "add", "lookup", "local", "proto", "kernel", "prio", "0")
    run(s.ip, "rule", "delete", "lookup", "local", "prio", "32765")
    run(s.ip, "rule", "delete", "l3mdev", "prio", "1000")
    run(s.ip, "rule", "delete", "l3mdev", "unreachable", "prio", "1001")
    run(s.ip, "link", "set", "dev", dirty_line_dev, "nomaster")
    run(s.ip, "link", "set", "dev", "dirty-line", "down")
    run(s.ip, "link", "del", "dirty-line")


def add_dev_to_vrf(dev):
    run(s.ip, "link", "set", "dev", dev, "master", "dirty-line")


def delete_dev_from_vrf(dev):
    run(s.ip, "link", "set", "dev", dev, "nomaster")


def vpn_status(name):
    """Gets current VPN status."""
    ret = {}
    for line in run(settings.systemctl, "status", f"openvpn@{name}.service")[0].split("\n"):
        if "running" in line:
            ret[name] = "running"
            break

    return ret


def forward_drop():
    """Disable any and all forwarding unless explicitly said so."""
    run_iptables("-P", "FORWARD", "DROP")


def state_enable():
    """Enable stateful connection tracking."""
    run_iptables("-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
    run_iptables("-I", "CAPE_ACCEPTED_SEGMENTS", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")


def state_disable():
    """Disable stateful connection tracking."""
    while True:
        _, err = run_iptables("-D", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        if err:
            break
        _, err = run_iptables("-D", "CAPE_ACCEPTED_SEGMENTS", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        if err:
            break


def enable_nat(interface):
    """Enable NAT on this interface."""
    run_iptables("-t", "nat", "-A", "POSTROUTING", "-o", interface, "-j", "MASQUERADE")


def disable_nat(interface):
    """Disable NAT on this interface."""
    run_iptables("-t", "nat", "-D", "POSTROUTING", "-o", interface, "-j", "MASQUERADE")


def enable_mitmdump(interface, client, port, netns):
    """Enable mitmdump on this interface."""

    log.info("enable_mitmdump client: %s port: %s netns: %s", client, port, netns)

    if netns:
        # assume all traffic in network namespace can be captured
        run_iptables(
            "-t",
            "nat",
            "-I",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "REDIRECT",
            "--to-port",
            port,
            netns=netns,
        )
        run_iptables(
            "-t",
            "nat",
            "-I",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            "80",
            "-j",
            "REDIRECT",
            "--to-port",
            port,
            netns=netns,
        )
    else:
        run_iptables(
            "-t",
            "nat",
            "-I",
            "PREROUTING",
            "-i",
            interface,
            "-s",
            client,
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "REDIRECT",
            "--to-port",
            port,
        )
        run_iptables(
            "-t",
            "nat",
            "-I",
            "PREROUTING",
            "-i",
            interface,
            "-s",
            client,
            "-p",
            "tcp",
            "--dport",
            "80",
            "-j",
            "REDIRECT",
            "--to-port",
            port
        )


def disable_mitmdump(interface, client, port, netns):
    """Disable mitmdump on this interface."""

    if netns:
        run_iptables(
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "REDIRECT",
            "--to-port",
            port,
            netns=netns,
        )
        run_iptables(
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-p",
            "tcp",
            "--dport",
            "80",
            "-j",
            "REDIRECT",
            "--to-port",
            port,
            netns=netns,
        )
    else:
        run_iptables(
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-i",
            interface,
            "-s",
            client,
            "-p",
            "tcp",
            "--dport",
            "443",
            "-j",
            "REDIRECT",
            "--to-port",
            port,
        )
        run_iptables(
            "-t",
            "nat",
            "-D",
            "PREROUTING",
            "-i",
            interface,
            "-s",
            client,
            "-p",
            "tcp",
            "--dport",
            "80",
            "-j",
            "REDIRECT",
            "--to-port",
            port,
        )

def polarproxy_enable(interface, client, tls_port, proxy_port):
    log.info("Enabling polarproxy route.")
    run_iptables(
        "-t",
        "nat",
        "-I",
        "PREROUTING",
        "1",
        "-i",
        interface,
        "--source",
        client,
        "-p",
        "tcp",
        "--dport",
        tls_port,
        "-j",
        "REDIRECT",
        "--to",
        proxy_port
    )
    run_iptables(
        "-A",
        "INPUT",
        "-i",
        interface,
        "-p",
        "tcp",
        "--dport",
        proxy_port,
        "-m",
        "state",
        "--state",
        "NEW",
        "-j",
        "ACCEPT"
    )

def polarproxy_disable(interface, client, tls_port, proxy_port):
    log.info("Disabling polarproxy route.")
    run_iptables(
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "-i",
        interface,
        "--source",
        client,
        "-p",
        "tcp",
        "--dport",
        tls_port,
        "-j",
        "REDIRECT",
        "--to",
        proxy_port
    )
    run_iptables(
        "-D",
        "INPUT",
        "-i",
        interface,
        "-p",
        "tcp",
        "--dport",
        proxy_port,
        "-m",
        "state",
        "--state",
        "NEW",
        "-j",
        "ACCEPT"
    )

def init_rttable(rt_table, interface):
    """Initialise routing table for this interface using routes
    from main table."""
    if rt_table in ("local", "main", "default"):
        return

    stdout, _ = run(settings.ip, "route", "list", "dev", interface)
    for line in stdout.split("\n"):
        args = ["route", "add"] + [x for x in line.split(" ") if x]
        args += ["dev", interface, "table", rt_table]
        run(settings.ip, *args)


def flush_rttable(rt_table):
    """Flushes specified routing table entries."""
    if rt_table in ("local", "main", "default"):
        return

    run(settings.ip, "route", "flush", "table", rt_table)


def forward_enable(src, dst, ipaddr, accept_segments=None, proto=None, ports=None):
    """Enable forwarding a specific IP address from one interface into another."""
    # Delete libvirt's default FORWARD REJECT rules. e.g.:
    # -A FORWARD -o virbr0 -j REJECT --reject-with icmp-port-unreachable
    # -A FORWARD -i virbr0 -j REJECT --reject-with icmp-port-unreachable
    run_iptables("-D", "FORWARD", "-i", src, "-j", "REJECT")
    run_iptables("-D", "FORWARD", "-o", src, "-j", "REJECT")
    if ports and (not proto or proto not in ["tcp", "udp"]):
        log.debug("Invalid protocol of transport layer")
        return False
    if ports:
        if "-" in ports:
            # We need a single hyphen to indicate that it is a range
            if ports.count("-") != 1:
                log.debug("Invalid ports range entry: %s", ports)
                return False
            else:
                start_port, end_port = ports.split("-")
                if not start_port.isdigit() or not end_port.isdigit() or start_port > end_port:
                    log.debug("Invalid port range entry: %s", ports)
                    return False
                else:
                    # Good to go! iptables takes port ranges as start:end
                    ports = ports.replace("-", ":")
        # Handle a single port
        else:
            if not ports.isdigit():
                log.debug("Invalid port entry: %s", ports)
                return False

    args = ["-I", "CAPE_ACCEPTED_SEGMENTS", "-i", src, "-o", dst, "--source", ipaddr]
    if accept_segments:
        args += ["--destination", accept_segments]
    if ports:
        args += ["-p", proto, "-m", "multiport", "--dport", ports]
    args += ["-j", "ACCEPT"]
    run_iptables(*args)


def forward_disable(src, dst, ipaddr, accept_segments=None, proto=None, ports=None):
    """Disable forwarding of a specific IP address from one interface into
    another."""
    if ports and (not proto or proto not in ["tcp", "udp"]):
        log.debug("Invalid protocol of transport layer")
        return False
    if ports:
        if "-" in ports:
            # We need a single hyphen to indicate that it is a range
            if ports.count("-") != 1:
                log.debug("Invalid ports range entry: %s", ports)
                return False
            else:
                start_port, end_port = ports.split("-")
                if not start_port.isdigit() or not end_port.isdigit() or start_port > end_port:
                    log.debug("Invalid port range entry: %s", ports)
                    return False
                else:
                    # Good to go! iptables takes port ranges as start:end
                    ports = ports.replace("-", ":")
        # Handle a single port
        else:
            if not ports.isdigit():
                log.debug("Invalid port entry: %s", ports)
                return False

    args = ["-D", "CAPE_ACCEPTED_SEGMENTS", "-i", src, "-o", dst, "--source", ipaddr]
    if accept_segments:
        args += ["--destination", accept_segments]
    if ports:
        args += ["-p", proto, "-m", "multiport", "--dport", ports]
    args += ["-j", "ACCEPT"]
    run_iptables(*args)


def forward_reject_enable(src, dst, ipaddr, reject_segments):
    """Enable forwarding a specific IP address from one interface into another
    but reject some targets network segments."""
    run_iptables(
        "-I", "CAPE_REJECTED_SEGMENTS", "-i", src, "-o", dst, "--source", ipaddr, "--destination", reject_segments, "-j", "REJECT"
    )


def forward_reject_disable(src, dst, ipaddr, reject_segments):
    """Disable forwarding a specific IP address from one interface into another
    but reject some targets network segments."""
    run_iptables(
        "-D", "CAPE_REJECTED_SEGMENTS", "-i", src, "-o", dst, "--source", ipaddr, "--destination", reject_segments, "-j", "REJECT"
    )


def hostports_reject_enable(src, ipaddr, reject_hostports):
    """Enable drop a specific IP address from one interface to host ports."""
    run_iptables(
        "-A", "INPUT", "-i", src, "--source", ipaddr, "-p", "tcp", "-m", "multiport", "--dport", reject_hostports, "-j", "REJECT"
    )
    run_iptables(
        "-A", "INPUT", "-i", src, "--source", ipaddr, "-p", "udp", "-m", "multiport", "--dport", reject_hostports, "-j", "REJECT"
    )


def hostports_reject_disable(src, ipaddr, reject_hostports):
    """Disable drop a specific IP address from one interface to host ports."""
    run_iptables(
        "-D", "INPUT", "-i", src, "--source", ipaddr, "-p", "tcp", "-m", "multiport", "--dport", reject_hostports, "-j", "REJECT"
    )
    run_iptables(
        "-D", "INPUT", "-i", src, "--source", ipaddr, "-p", "udp", "-m", "multiport", "--dport", reject_hostports, "-j", "REJECT"
    )


def srcroute_enable(rt_table, ipaddr):
    """Enable routing policy for specified source IP address."""
    run(settings.ip, "rule", "add", "from", ipaddr, "table", rt_table)
    run(settings.ip, "route", "flush", "cache")


def srcroute_disable(rt_table, ipaddr):
    """Disable routing policy for specified source IP address."""
    run(settings.ip, "rule", "del", "from", ipaddr, "table", rt_table)
    run(settings.ip, "route", "flush", "cache")


def dns_forward(action, vm_ip, dns_ip, dns_port="53"):
    """Route DNS requests from the VM to a custom DNS on a separate network."""
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "-p",
        "tcp",
        "--dport",
        "53",
        "--source",
        vm_ip,
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (dns_ip, dns_port),
    )

    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "-p",
        "udp",
        "--dport",
        "53",
        "--source",
        vm_ip,
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (dns_ip, dns_port),
    )


def inetsim_redirect_port(action, srcip, dstip, ports):
    """Note that the parameters (probably) mean the opposite of what they
    imply; this method adds or removes an iptables rule for redirect traffic
    from (srcip, srcport) to (dstip, dstport).
    E.g., if 192.168.56.101:80 -> 192.168.56.1:8080, then it redirects
    outgoing traffic from 192.168.56.101 to port 80 to 192.168.56.1:8080.
    """
    for entry in ports.split():
        if entry.count(":") != 1:
            log.debug("Invalid inetsim ports entry: %s", entry)
            continue
        srcport, dstport = entry.split(":")
        if not dstport.isdigit():
            log.debug("Invalid inetsim dstport entry: %s", dstport)
            continue

        # Handle srcport ranges
        if "-" in srcport:
            # We need a single hyphen to indicate that it is a range
            if srcport.count("-") != 1:
                log.debug("Invalid inetsim srcport range entry: %s", srcport)
                continue
            else:
                start_srcport, end_srcport = srcport.split("-")
                if not start_srcport.isdigit() or not end_srcport.isdigit():
                    log.debug("Invalid inetsim srcport range entry: %s", srcport)
                    continue
                else:
                    # Good to go! iptables takes port ranges as start:end
                    srcport = srcport.replace("-", ":")

        # Handle a single srcport
        else:
            if not srcport.isdigit():
                log.debug("Invalid inetsim srcport entry: %s", srcport)
                continue
        run_iptables(
            "-t",
            "nat",
            action,
            "PREROUTING",
            "--source",
            srcip,
            "-p",
            "tcp",
            "--syn",
            "--dport",
            srcport,
            "-j",
            "DNAT",
            "--to-destination",
            "%s:%s" % (dstip, dstport),
        )


def inetsim_service_port_trap(action, srcip, dstip, protocol):
    # Note that the multiport limit for ports specified is 15,
    # so we will split this up into two rules
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        srcip,
        "-p",
        protocol,
        "-m",
        "multiport",
        "--dports",
        # The following ports are used for default services on Ubuntu
        "7,9,13,17,19,21,22,25,37,69,79,80,110,113",
        "-j",
        "DNAT",
        "--to-destination",
        dstip,
    )
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        srcip,
        "-p",
        protocol,
        "-m",
        "multiport",
        "--dports",
        # The following ports are used for default services on Ubuntu
        "123,443,465,514,990,995,6667",
        "-j",
        "DNAT",
        "--to-destination",
        dstip,
    )


def inetsim_trap(action, ipaddr, inetsim_ip, resultserver_port):
    # There are four options for protocol in iptables: tcp, udp, icmp and all
    # Since we want tcp, udp and icmp to be configured differently, we cannot use all
    # tcp
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        ipaddr,
        "-p",
        "tcp",
        "-m",
        "tcp",
        "--syn",
        "!",
        "--dport",
        resultserver_port,
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (inetsim_ip, "1"),
    )
    # udp
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        ipaddr,
        "-p",
        "udp",
        "!",
        "--dport",
        resultserver_port,
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (inetsim_ip, "1"),
    )
    # icmp
    run_iptables(
        "-t",
        "nat",
        action,
        "PREROUTING",
        "--source",
        ipaddr,
        "-p",
        "icmp",
        "--icmp-type",
        "any",
        "-j",
        "DNAT",
        "--to-destination",
        "%s:%s" % (inetsim_ip, "1"),
    )


def inetsim_enable(ipaddr, inetsim_ip, dns_port, resultserver_port, ports):
    """Enable hijacking of all traffic and send it to InetSIM."""
    log.info("Enabling inetsim route.")
    inetsim_redirect_port("-A", ipaddr, inetsim_ip, ports)
    inetsim_service_port_trap("-A", ipaddr, inetsim_ip, "tcp")
    inetsim_service_port_trap("-A", ipaddr, inetsim_ip, "udp")
    dns_forward("-A", ipaddr, inetsim_ip, dns_port)
    inetsim_trap("-A", ipaddr, inetsim_ip, resultserver_port)
    # INetSim does not have an SSH service, so SSH traffic can get through to the host. We want to block this.
    run_iptables("-A", "INPUT", "--source", ipaddr, "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "DROP")
    run_iptables("-A", "OUTPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-A", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
    run_iptables("-A", "OUTPUT", "--source", ipaddr, "-j", "DROP")


def inetsim_disable(ipaddr, inetsim_ip, dns_port, resultserver_port, ports):
    """Disable hijacking of all traffic and send it to InetSIM."""
    log.info("Disabling inetsim route.")
    inetsim_redirect_port("-D", ipaddr, inetsim_ip, ports)
    inetsim_service_port_trap("-D", ipaddr, inetsim_ip, "tcp")
    inetsim_service_port_trap("-D", ipaddr, inetsim_ip, "udp")
    dns_forward("-D", ipaddr, inetsim_ip, dns_port)
    inetsim_trap("-D", ipaddr, inetsim_ip, resultserver_port)
    run_iptables("-D", "INPUT", "--source", ipaddr, "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "DROP")
    run_iptables("-D", "OUTPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-D", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
    run_iptables("-D", "OUTPUT", "--source", ipaddr, "-j", "DROP")


def interface_route_tun_enable(ipaddr: str, out_interface: str, task_id: str):
    """Enable routing and NAT via tun output_interface."""
    log.info("Enabling interface routing via: %s for task: %s", out_interface, task_id)

    # mark packets from analysis VM
    run_iptables("-t", "mangle", "-I", "PREROUTING", "--source", ipaddr, "-j", "MARK", "--set-mark", task_id)

    run_iptables("-t", "nat", "-I", "POSTROUTING", "--source", ipaddr, "-o", out_interface, "-j", "MASQUERADE")
    # ACCEPT forward
    run_iptables("-t", "filter", "-I", "FORWARD", "--source", ipaddr, "-o", out_interface, "-j", "ACCEPT")

    # in routing table add route table task_id
    run(s.ip, "rule", "add", "fwmark", task_id, "lookup", task_id)

    peer_ip = get_tun_peer_address(out_interface)
    if peer_ip:
        log.info("interface_route_enable %s has peer: %s ", out_interface, peer_ip)
        run(s.ip, "route", "add", "default", "via", peer_ip, "table", task_id)
    else:
        log.error("interface_route_enable missing peer IP ")


def interface_route_tun_disable(ipaddr: str, out_interface: str, task_id: str):
    """Disable routing and NAT via tun output_interface."""
    log.info("Disable interface routing via: %s for task: %s", out_interface, task_id)

    # mark packets from analysis VM
    run_iptables("-t", "mangle", "-D", "PREROUTING", "--source", ipaddr, "-j", "MARK", "--set-mark", task_id)

    run_iptables("-t", "nat", "-D", "POSTROUTING", "--source", ipaddr, "-o", out_interface, "-j", "MASQUERADE")
    # ACCEPT forward
    run_iptables("-t", "filter", "-D", "FORWARD", "--source", ipaddr, "-o", out_interface, "-j", "ACCEPT")

    # in routing table add route table task_id
    run(s.ip, "rule", "del", "fwmark", task_id, "lookup", task_id)

    peer_ip = get_tun_peer_address(out_interface)
    if peer_ip:
        log.info("interface_route_disable %s has peer %s", out_interface, peer_ip)
        run(s.ip, "route", "del", "default", "via", peer_ip, "table", task_id)
    else:
        log.error("interface_route_disable missing peer IP ")


def socks5_enable(ipaddr, resultserver_port, dns_port, proxy_port):
    """Enable hijacking of all traffic and send it to socks5."""
    log.info("Enabling socks route.")
    run_iptables(
        "-t",
        "nat",
        "-I",
        "PREROUTING",
        "--source",
        ipaddr,
        "-p",
        "tcp",
        "--syn",
        "!",
        "--dport",
        resultserver_port,
        "-j",
        "REDIRECT",
        "--to-ports",
        proxy_port,
    )
    run_iptables("-I", "OUTPUT", "1", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-I", "OUTPUT", "2", "-m", "state", "--state", "INVALID", "-j", "DROP")
    run_iptables(
        "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port
    )
    run_iptables(
        "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port
    )
    run_iptables("-A", "OUTPUT", "--source", ipaddr, "-j", "DROP")


def socks5_disable(ipaddr, resultserver_port, dns_port, proxy_port):
    """Enable hijacking of all traffic and send it to socks5."""
    log.info("Disabling socks route.")
    run_iptables(
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "--source",
        ipaddr,
        "-p",
        "tcp",
        "--syn",
        "!",
        "--dport",
        resultserver_port,
        "-j",
        "REDIRECT",
        "--to-ports",
        proxy_port,
    )
    run_iptables("-D", "OUTPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-D", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
    run_iptables(
        "-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port
    )
    run_iptables(
        "-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port
    )
    run_iptables("-D", "OUTPUT", "--source", ipaddr, "-j", "DROP")


def drop_enable(ipaddr, resultserver_port):
    run_iptables(
        "-t", "nat", "-I", "PREROUTING", "--source", ipaddr, "-p", "tcp", "--syn", "--dport", resultserver_port, "-j", "ACCEPT"
    )
    run_iptables("-A", "INPUT", "--destination", ipaddr, "-p", "tcp", "--dport", "8000", "-j", "ACCEPT")
    run_iptables("-A", "INPUT", "--destination", ipaddr, "-p", "tcp", "--sport", resultserver_port, "-j", "ACCEPT")
    run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-p", "tcp", "--dport", "8000", "-j", "ACCEPT")
    run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-p", "tcp", "--sport", resultserver_port, "-j", "ACCEPT")
    # run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-j", "LOG")
    run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-j", "DROP")


def drop_disable(ipaddr, resultserver_port):
    run_iptables(
        "-t", "nat", "-D", "PREROUTING", "--source", ipaddr, "-p", "tcp", "--syn", "--dport", resultserver_port, "-j", "ACCEPT"
    )
    run_iptables("-D", "INPUT", "--destination", ipaddr, "-p", "tcp", "--dport", "8000", "-j", "ACCEPT")
    run_iptables("-D", "INPUT", "--destination", ipaddr, "-p", "tcp", "--sport", resultserver_port, "-j", "ACCEPT")
    run_iptables("-D", "OUTPUT", "--destination", ipaddr, "-p", "tcp", "--dport", "8000", "-j", "ACCEPT")
    run_iptables("-D", "OUTPUT", "--destination", ipaddr, "-p", "tcp", "--sport", resultserver_port, "-j", "ACCEPT")
    # run_iptables("-D", "OUTPUT", "--destination", ipaddr, "-j", "LOG")
    run_iptables("-D", "OUTPUT", "--destination", ipaddr, "-j", "DROP")


handlers = {
    "nic_available": nic_available,
    "rt_available": rt_available,
    "vpn_status": vpn_status,
    "forward_drop": forward_drop,
    "state_enable": state_enable,
    "state_disable": state_disable,
    "enable_nat": enable_nat,
    "disable_nat": disable_nat,
    "init_rttable": init_rttable,
    "flush_rttable": flush_rttable,
    "forward_enable": forward_enable,
    "forward_disable": forward_disable,
    "forward_reject_enable": forward_reject_enable,
    "forward_reject_disable": forward_reject_disable,
    "hostports_reject_enable": hostports_reject_enable,
    "hostports_reject_disable": hostports_reject_disable,
    "srcroute_enable": srcroute_enable,
    "srcroute_disable": srcroute_disable,
    "inetsim_enable": inetsim_enable,
    "inetsim_disable": inetsim_disable,
    "interface_route_tun_enable": interface_route_tun_enable,
    "interface_route_tun_disable": interface_route_tun_disable,
    "socks5_enable": socks5_enable,
    "socks5_disable": socks5_disable,
    "drop_enable": drop_enable,
    "drop_disable": drop_disable,
    "cleanup_rooter": cleanup_rooter,
    "init_vrf": init_vrf,
    "cleanup_vrf": cleanup_vrf,
    "add_dev_to_vrf": add_dev_to_vrf,
    "delete_dev_from_vrf": delete_dev_from_vrf,
    "enable_mitmdump": enable_mitmdump,
    "disable_mitmdump": disable_mitmdump,
    "polarproxy_enable": polarproxy_enable,
    "polarproxy_disable": polarproxy_disable,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("socket", nargs="?", default="/tmp/cuckoo-rooter", help="Unix socket path")
    parser.add_argument("-g", "--group", default="cape", help="Unix socket group")
    parser.add_argument("--systemctl", default="/bin/systemctl", help="Systemctl wrapper script for invoking OpenVPN")
    parser.add_argument("--sysctl", default="/usr/sbin/sysctl", help="Path to sysctl")
    parser.add_argument("--iptables", default="/sbin/iptables", help="Path to iptables")
    parser.add_argument("--iptables-save", default="/sbin/iptables-save", help="Path to iptables-save")
    parser.add_argument("--iptables-restore", default="/sbin/iptables-restore", help="Path to iptables-restore")
    parser.add_argument("--ip", default="/sbin/ip", help="Path to ip")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    settings = parser.parse_args()

    if settings.verbose:
        # Verbose logging is not only controlled by the level. Some INFO logs are also
        # conditional (like here).
        log.setLevel(logging.DEBUG)
        log.info("Verbose logging enabled")

    if not settings.systemctl or not path_exists(settings.systemctl):
        sys.exit(
            "The systemctl binary is not available, please configure it!\n"
            "Note that on CentOS you should provide --systemctl /bin/systemctl, "
            "rather than using the Ubuntu/Debian default /bin/systemctl."
        )

    if not settings.iptables or not path_exists(settings.iptables):
        sys.exit("The `iptables` binary is not available, eh?!")

    if not settings.sysctl or not path_exists(settings.sysctl):
        sys.exit("The `sysctrl` binary is not available, eh?!")

    if os.getuid():
        sys.exit("This utility is supposed to be ran as root.")

    enable_ip_forwarding(settings.sysctl)

    if path_exists(settings.socket):
        path_delete(settings.socket)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    server.bind(settings.socket)

    # Provide the correct file ownership and permission so Cuckoo can use it
    # from an unprivileged process, based on Sean Whalen's routetor.
    try:
        gr = grp.getgrnam(settings.group)
    except KeyError:
        sys.exit(
            "The group (`%s`) does not exist. Please define the group / user "
            "through which Cuckoo will connect to the rooter, e.g., "
            "./utils/rooter.py -g myuser" % settings.group
        )

    # global username
    username = settings.group
    os.chown(settings.socket, 0, gr.gr_gid)
    os.chmod(settings.socket, stat.S_IRUSR | stat.S_IWUSR | stat.S_IWGRP)

    # Initialize global variables.
    s.iptables = settings.iptables
    s.iptables_save = settings.iptables_save
    s.iptables_restore = settings.iptables_restore
    s.ip = settings.ip

    # Simple object to allow a signal handler to stop the rooter loop

    class Run:
        def __init__(self):
            self.run = True

    do = Run()

    def handle_sigterm(sig, f):
        do.run = False
        server.shutdown(socket.SHUT_RDWR)
        server.close()
        cleanup_rooter()

    signal.signal(signal.SIGTERM, handle_sigterm)

    while do.run:
        try:
            command, addr = server.recvfrom(4096)
        except socket.error as e:
            if not do.run:
                # When the signal handler shuts the server down, do.run is False and
                # server.recvfrom raises an exception. Ignore that exception and exit.
                break
            if e.errno == errno.EINTR:
                continue
            raise e

        try:
            obj = json.loads(command)
        except Exception:
            log.info("Received invalid request: %r", command)
            continue

        command = obj.get("command")
        args = obj.get("args", [])
        kwargs = obj.get("kwargs", {})

        if not isinstance(command, str) or command not in handlers:
            log.warning("Received incorrect command: %r", command)
            continue

        if not isinstance(args, (tuple, list)):
            log.warning("Invalid arguments type: %r", args)
            continue

        if not isinstance(kwargs, dict):
            log.warning("Invalid keyword arguments: %r", kwargs)
            continue

        for arg in args + list(kwargs.keys()) + list(kwargs.values()):
            if not isinstance(arg, str):
                log.warning("Invalid argument type detected: %r (%s)", arg, type(arg))
                break
        else:
            if settings.verbose:
                log.info(
                    "Processing command: %s %s %s", command, " ".join(args), " ".join("%s=%s" % (k, v) for k, v in kwargs.items())
                )

            error = None
            output = None
            try:
                output = handlers[command](*args, **kwargs)
            except Exception as e:
                log.exception("Error executing command: %s", command)
                error = str(e)
            server.sendto(json.dumps({"output": output, "exception": error}).encode(), addr)
