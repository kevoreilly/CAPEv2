import argparse
import logging
import os
import sys

CAPE_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.append(CAPE_ROOT)

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooNetworkError
from lib.cuckoo.core.rooter import _load_socks5_operational, rooter

cfg = Config()
routing = Config("routing")
log = logging.getLogger()
socks5s = _load_socks5_operational()
machinery_conf = Config(cfg.cuckoo.machinery)
vpns = routing.vpn.get("vpns", "")

# os.listdir('/sys/class/net/')
HAVE_NETWORKIFACES = False
try:
    import psutil

    network_interfaces = list(psutil.net_if_addrs().keys())
    HAVE_NETWORKIFACES = True
except ImportError:
    print("Missing dependency: poetry run pip install psutil")


def check_privileges():
    if not os.environ.get("SUDO_UID") and os.geteuid() != 0:
        raise PermissionError("You need to run this script with sudo or as root.")


def _rooter_response_check(rooter_response):
    if rooter_response and rooter_response["exception"] is not None:
        raise CuckooCriticalError(f"Error execution rooter command: {rooter_response['exception']}")


def route_enable(route, interface, rt_table, machine, reject_segments, reject_hostports):
    if route == "inetsim":
        rooter_response = rooter(
            "inetsim_enable",
            machine.ip,
            str(routing.inetsim.server),
            str(routing.inetsim.dnsport),
            str(cfg.resultserver.port),
            str(routing.inetsim.ports),
        )
    elif route == "tor":
        rooter_response = rooter(
            "socks5_enable",
            machine.ip,
            str(cfg.resultserver.port),
            str(routing.tor.dnsport),
            str(routing.tor.proxyport),
        )
    elif route in socks5s:
        rooter_response = rooter(
            "socks5_enable",
            machine.ip,
            str(cfg.resultserver.port),
            str(socks5s[route]["dnsport"]),
            str(socks5s[route]["port"]),
        )
    elif route in ("none", "None", "drop"):
        rooter_response = rooter("drop_enable", machine.ip, str(cfg.resultserver.port))
        _rooter_response_check(rooter_response)

    # check if the interface is up
    if HAVE_NETWORKIFACES and routing.routing.verify_interface and interface and interface not in network_interfaces:
        raise CuckooNetworkError(f"Network interface {interface} not found")
    if interface:
        # import code;code.interact(local=dict(locals(), **globals()))
        rooter_response = rooter(
            "forward_enable", machine.interface or machinery_conf.get(cfg.cuckoo.machinery).get("interface"), interface, machine.ip
        )
        _rooter_response_check(rooter_response)

    if reject_segments:
        rooter_response = rooter("forward_reject_enable", machine.interface, interface, machine.ip, reject_segments)
        _rooter_response_check(rooter_response)

    if reject_hostports:
        rooter_response = rooter("hostports_reject_enable", machine.interface, machine.ip, reject_hostports)
        _rooter_response_check(rooter_response)

    log.info("Enabled route '%s'. Bear in mind that routes none and drop won't generate PCAP file", route)

    if rt_table:
        rooter_response = rooter("srcroute_enable", rt_table, machine.ip)
        _rooter_response_check(rooter_response)


def route_disable(route, interface, rt_table, machine, reject_segments, reject_hostports):
    if interface:
        rooter_response = rooter(
            "forward_disable", machine.interface or machinery_conf.get(cfg.cuckoo.machinery).get("interface"), interface, machine.ip
        )
        _rooter_response_check(rooter_response)
        if reject_segments:
            rooter_response = rooter("forward_reject_disable", machine.interface, interface, machine.ip, reject_segments)
            _rooter_response_check(rooter_response)
        if reject_hostports:
            rooter_response = rooter("hostports_reject_disable", machine.interface, machine.ip, reject_hostports)
            _rooter_response_check(rooter_response)
        log.info("Disabled route '%s'", route)

    if rt_table:
        rooter_response = rooter("srcroute_disable", rt_table, machine.ip)
        _rooter_response_check(rooter_response)

    if route == "inetsim":
        rooter_response = rooter(
            "inetsim_disable",
            machine.ip,
            routing.inetsim.server,
            str(routing.inetsim.dnsport),
            str(cfg.resultserver.port),
            str(routing.inetsim.ports),
        )
    elif route == "tor":
        rooter_response = rooter(
            "socks5_disable",
            machine.ip,
            str(cfg.resultserver.port),
            str(routing.tor.dnsport),
            str(routing.tor.proxyport),
        )
    elif route in socks5s:
        rooter_response = rooter(
            "socks5_disable",
            machine.ip,
            str(cfg.resultserver.port),
            str(socks5s[route]["dnsport"]),
            str(socks5s[route]["port"]),
        )
    elif route in ("none", "None", "drop"):
        rooter_response = rooter("drop_disable", machine.ip, str(cfg.resultserver.port))
        _rooter_response_check(rooter_response)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Standalone script to debug VM problems that allows to enable routing on VM")
    parser.add_argument("-r", "--route", default="tor", help="Route to enable")
    parser.add_argument("-e", "--enable", default=False, action="store_true", help="Route enable")
    parser.add_argument("-d", "--disable", default=False, action="store_true", help="Route disable")
    parser.add_argument("--show-vm-names", action="store_true", default=False, help="Show names of all vms to use")
    parser.add_argument(
        "--vm-name",
        default="",
        help="VM name to load VM config from conf/<machinery>.conf, name that you have between []. Ex: [cape_vm1]. Specify only cape_vm1",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()
    check_privileges()
    route = args.route
    rt_table = None
    reject_segments = None
    reject_hostports = None
    if route in ("none", "None", "drop", "false"):
        interface = None
        rt_table = None
    elif route == "inetsim":
        interface = routing.inetsim.interface
    elif route == "tor":
        interface = routing.tor.interface
    elif route == "internet" and routing.routing.internet != "none":
        interface = routing.routing.internet
        rt_table = routing.routing.rt_table
        if routing.routing.reject_segments != "none":
            reject_segments = routing.routing.reject_segments
        if routing.routing.reject_hostports != "none":
            reject_hostports = str(routing.routing.reject_hostports)
    elif route in vpns:
        vpn = routing.get(route)
        interface = vpn.interface
        rt_table = vpn.rt_table
    elif route in socks5s:
        interface = ""
    else:
        log.warning("Unknown network routing destination specified, ignoring routing for this analysis: %s", route)
        interface = None
        rt_table = None

        # Check if the network interface is still available. If a VPN dies for
        # some reason, its tunX interface will no longer be available.
        if interface and not rooter("nic_available", interface):
            log.error(
                "The network interface '%s' configured for this analysis is "
                "not available at the moment, switching to route=none mode",
                interface,
            )
            route = "none"
            interface = None
            rt_table = None

    if args.enable:
        print(route, interface, rt_table, machinery_conf.get(args.vm_name), reject_segments, reject_hostports)
        route_enable(route, interface, rt_table, machinery_conf.get(args.vm_name), reject_segments, reject_hostports)
    elif args.disable:
        route_disable(route, interface, rt_table, machinery_conf.get(args.vm_name), reject_segments, reject_hostports)
    elif args.show_vm_names:
        sys.exit(machinery_conf.get(cfg.cuckoo.machinery).get("machines").split(","))
    else:
        parser.print_help()
