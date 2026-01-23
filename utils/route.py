#!/usr/bin/python

"""
Aux script for VPN setup

Get a look on utils/vpn2cape.py
Example:
    /etc/iproute2/rt_tables
        5 host1
        6 host2
        7 host3

    conf/routing.conf
        [vpn5]
        name = X.ovpn
        description = X
        interface = tunX
        rt_table = host1
"""

import os
import subprocess

IP_ROUTE_TABLES = "/etc/iproute2/rt_tables"

if __name__ == "__main__":
    # This doesn't work out of the box for most of the providers.
    # To make it works for your provider you need first to uncomment `print(os.environ)` to get all variables
    # Adjust variables name or even code if needed to match your entries in rt_table
    # print(os.environ)
    config_name = os.environ.get("config")
    local_ip = os.environ.get("ifconfig_local")
    vpn_gateway = os.environ.get("route_vpn_gateway")
    dev = os.environ.get("dev")
    # You might need to edit next line to set ip_table name properly. It can be under different variable.
    # if you don't have host1 in os.enviroment under any variable, search another variable that you can use and edit rt_tables and routing.conf
    ip_table = dev[3:]
    print(f"ip rule add from {local_ip} table {ip_table}")
    print(f"ip route add default via {vpn_gateway} dev {dev} table {ip_table}")
    subprocess.call(["ip", "rule", "add", "from", local_ip, "table", ip_table])
    subprocess.call(["ip", "route", "add", "default", "via", vpn_gateway, "dev", dev, "table", ip_table])
