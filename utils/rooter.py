#!/usr/bin/env python
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import sys
import signal
import argparse
import grp
import json
import logging.handlers
import os.path
import socket
import stat
import subprocess
import sys
import errno


if sys.version_info[:2] < (3, 6):
    sys.exit("You are running an incompatible version of Python, please use >= 3.6")

username = False
log = logging.getLogger("cuckoo-rooter")
formatter = logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s")
ch = logging.StreamHandler()
ch.setFormatter(formatter)
log.addHandler(ch)
log.setLevel(logging.INFO)


class s(object):
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

def check_tuntap(vm_name, main_iface):
    """Create tuntap device for qemu vms"""
    try:
        run([s.ip, "tuntap", "add", "dev", f"tap_{vm_name}", "mode", "tap", "user", username])
        run([s.ip, "link", "set", "tap_{vm_name}", "master", main_iface])
        run([s.ip, "link", "set", "dev", "tap_{vm_name}", "up"])
        run([s.ip, "link", "set", "dev", main_iface, "up"])
        return True
    except subprocess.CalledProcessError:
        return False


def run_iptables(*args):
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

    cleaned = []
    for l in stdout.split("\n"):
        if l and "CAPE-rooter" not in l:
            cleaned.append(l)

    p = subprocess.Popen([s.iptables_restore], stdin=subprocess.PIPE, universal_newlines=True)
    p.communicate(input="\n".join(cleaned))


def nic_available(interface):
    """Check if specified network interface is available."""
    try:
        subprocess.check_call([settings.ip, "link", "show", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        return True
    except subprocess.CalledProcessError:
        return False


def rt_available(rt_table):
    """Check if specified routing table is defined."""
    try:
        subprocess.check_call(
            [settings.ip, "route", "list", "table", rt_table], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True
        )
        return True
    except subprocess.CalledProcessError:
        return False


def vpn_status(name):
    """Gets current VPN status."""
    ret = {}
    for line in run(settings.systemctl, "status", "openvpn@{}.service".format(name))[0].split("\n"):
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


def state_disable():
    """Disable stateful connection tracking."""
    while True:
        _, err = run_iptables("-D", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT")
        if err:
            break


def enable_nat(interface):
    """Enable NAT on this interface."""
    run_iptables("-t", "nat", "-A", "POSTROUTING", "-o", interface, "-j", "MASQUERADE")


def disable_nat(interface):
    """Disable NAT on this interface."""
    run_iptables("-t", "nat", "-D", "POSTROUTING", "-o", interface, "-j", "MASQUERADE")


def init_rttable(rt_table, interface):
    """Initialise routing table for this interface using routes
    from main table."""
    if rt_table in ["local", "main", "default"]:
        return

    stdout, _ = run(settings.ip, "route", "list", "dev", interface)
    for line in stdout.split("\n"):
        args = ["route", "add"] + [x for x in line.split(" ") if x]
        args += ["dev", interface, "table", rt_table]
        run(settings.ip, *args)


def flush_rttable(rt_table):
    """Flushes specified routing table entries."""
    if rt_table in ["local", "main", "default"]:
        return

    run(settings.ip, "route", "flush", "table", rt_table)


def forward_enable(src, dst, ipaddr):
    """Enable forwarding a specific IP address from one interface into
    another."""
    # Delete libvirt's default FORWARD REJECT rules. e.g.:
    # -A FORWARD -o virbr0 -j REJECT --reject-with icmp-port-unreachable
    # -A FORWARD -i virbr0 -j REJECT --reject-with icmp-port-unreachable
    run_iptables("-D", "FORWARD", "-i", src, "-j", "REJECT")
    run_iptables("-D", "FORWARD", "-o", src, "-j", "REJECT")
    run_iptables("-I", "FORWARD", "-i", src, "-o", dst, "--source", ipaddr, "-j", "ACCEPT")
    run_iptables("-I", "FORWARD", "-i", dst, "-o", src, "--destination", ipaddr, "-j", "ACCEPT")


def forward_disable(src, dst, ipaddr):
    """Disable forwarding of a specific IP address from one interface into
    another."""
    run_iptables("-D", "FORWARD", "-i", src, "-o", dst, "--source", ipaddr, "-j", "ACCEPT")
    run_iptables("-D", "FORWARD", "-i", dst, "-o", src, "--destination", ipaddr, "-j", "ACCEPT")


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
        if not srcport.isdigit() or not dstport.isdigit():
            log.debug("Invalid inetsim ports entry: %s", entry)
            continue
        run(
            settings.iptables,
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


def inetsim_enable(ipaddr, inetsim_ip, dns_port, resultserver_port, ports):
    """Enable hijacking of all traffic and send it to InetSIM."""
    log.info("Enabling inetsim route.")
    inetsim_redirect_port("-A", ipaddr, inetsim_ip, ports)
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
        "DNAT",
        "--to-destination",
        "{}".format(inetsim_ip),
    )
    run_iptables("-A", "OUTPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-A", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
    dns_forward("-A", ipaddr, inetsim_ip, dns_port)
    run_iptables("-A", "OUTPUT", "--source", ipaddr, "-j", "DROP")


def inetsim_disable(ipaddr, inetsim_ip, dns_port, resultserver_port, ports):
    """Disable hijacking of all traffic and send it to InetSIM."""
    log.info("Disabling inetsim route.")
    inetsim_redirect_port("-D", ipaddr, inetsim_ip, ports)
    run_iptables(
        "-D",
        "PREROUTING",
        "-t",
        "nat",
        "--source",
        ipaddr,
        "-p",
        "tcp",
        "--syn",
        "!",
        "--dport",
        resultserver_port,
        "-j",
        "DNAT",
        "--to-destination",
        "{}".format(inetsim_ip),
    )
    run_iptables("-D", "OUTPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-D", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
    dns_forward("-D", ipaddr, inetsim_ip, dns_port)
    run_iptables("-D", "OUTPUT", "--source", ipaddr, "-j", "DROP")


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
    run_iptables("-I", "1", "OUTPUT", "-m", "conntrack", "--ctstate", "INVALID", "-j", "DROP")
    run_iptables("-I", "2", "OUTPUT", "-m", "state", "--state", "INVALID", "-j", "DROP")
    run_iptables("-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port)
    run_iptables("-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port)
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
    run_iptables("-t", "nat", "-D", "PREROUTING", "-p", "tcp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port)
    run_iptables("-t", "nat", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "--source", ipaddr, "-j", "REDIRECT", "--to-ports", dns_port)
    run_iptables("-D", "OUTPUT", "--source", ipaddr, "-j", "DROP")


def drop_enable(ipaddr, resultserver_port):
    run_iptables("-t", "nat", "-I", "PREROUTING", "--source", ipaddr, "-p", "tcp", "--syn", "--dport", resultserver_port, "-j", "ACCEPT")
    run_iptables("-A", "INPUT", "--destination", ipaddr, "-p", "tcp", "--dport", "8000", "-j", "ACCEPT")
    run_iptables("-A", "INPUT", "--destination", ipaddr, "-p", "tcp", "--sport", resultserver_port, "-j", "ACCEPT")
    run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-p", "tcp", "--dport", "8000", "-j", "ACCEPT")
    run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-p", "tcp", "--sport", resultserver_port, "-j", "ACCEPT")
    # run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-j", "LOG")
    run_iptables("-A", "OUTPUT", "--destination", ipaddr, "-j", "DROP")


def drop_disable(ipaddr, resultserver_port):
    run_iptables("-t", "nat", "-D", "PREROUTING", "--source", ipaddr, "-p", "tcp", "--syn", "--dport", resultserver_port, "-j", "ACCEPT")
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
    "srcroute_enable": srcroute_enable,
    "srcroute_disable": srcroute_disable,
    "inetsim_enable": inetsim_enable,
    "inetsim_disable": inetsim_disable,
    "socks5_enable": socks5_enable,
    "socks5_disable": socks5_disable,
    "drop_enable": drop_enable,
    "drop_disable": drop_disable,
    "cleanup_rooter": cleanup_rooter,
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("socket", nargs="?", default="/tmp/cuckoo-rooter", help="Unix socket path")
    parser.add_argument("-g", "--group", default="cuckoo", help="Unix socket group")
    parser.add_argument("--systemctl", default="/bin/systemctl", help="Systemctl wrapper script for invoking OpenVPN")
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
        log.info('Verbose logging enabled')

    if not settings.systemctl or not os.path.exists(settings.systemctl):
        sys.exit(
            "The systemctl binary is not available, please configure it!\n"
            "Note that on CentOS you should provide --systemctl /bin/systemctl, "
            "rather than using the Ubuntu/Debian default /bin/systemctl."
        )

    if not settings.iptables or not os.path.exists(settings.iptables):
        sys.exit("The `iptables` binary is not available, eh?!")

    if os.getuid():
        sys.exit("This utility is supposed to be ran as root.")

    if os.path.exists(settings.socket):
        os.remove(settings.socket)

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

    class Run(object):
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
        except:
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
                log.info("Processing command: %s %s %s", command, " ".join(args), " ".join("%s=%s" % (k, v) for k, v in kwargs.items()))

            error = None
            output = None
            try:
                output = handlers[command](*args, **kwargs)
            except Exception as e:
                log.exception("Error executing command: {}".format(command))
                error = str(e)
            server.sendto(json.dumps({"output": output, "exception": error,}).encode("utf-8"), addr)
