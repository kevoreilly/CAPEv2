#!/usr/bin/python

import os
import subprocess

if __name__ == "__main__":
    config_name = os.environ.get("config")
    local_ip = os.environ.get("ifconfig_local")
    vpn_gateway = os.environ.get("route_vpn_gateway")
    dev = os.environ.get("dev")
    ip_table = dev[3:]
    print("ip rule del from {} table {}".format(local_ip, ip_table))
    print("ip route del default via {} dev {} table {}".format(vpn_gateway, dev, ip_table))
    subprocess.call(["ip", "rule", "del", "from", local_ip, "table", ip_table])
