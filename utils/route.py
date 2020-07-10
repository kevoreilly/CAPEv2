#!/usr/bin/python

"""
    Aux script for VPN setup
"""

import os
import subprocess

IP_ROUTE_TABLES = "/etc/iproute2/rt_tables"

if __name__ == "__main__":
    config_name = os.environ.get("config")
    local_ip = os.environ.get("ifconfig_local")
    vpn_gateway = os.environ.get("route_vpn_gateway")
    common_name = os.environ.get("common_name")
    dev = os.environ.get("dev")
    ip_table = common_name
    print("ip rule add from {} table {}".format(local_ip, ip_table))
    print("ip route add default via {} dev {} table {}".format(vpn_gateway, dev, ip_table))
    subprocess.call(["ip", "rule", "add", "from", local_ip, "table", ip_table])
    subprocess.call(["ip", "route", "add", "default", "via", vpn_gateway, "dev", dev, "table", ip_table])
