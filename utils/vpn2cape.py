import argparse
import os
import re

#
#   VPN integrator for CAPE
#   Quick and Dirty script by doomedraven to prepare configs for vpn integration


def main(folder, port):
    idx_start = 1000
    rt_table = {}
    templates = []
    paths = []
    vpns = []
    template = """
[vpn_{id}]
name = {vpn_path}
description = {description}
interface = tun{id}
rt_table = {rt}
"""

    files = os.listdir(folder)
    for index, file in enumerate(files):
        if file.endswith(".ovpn"):
            path = os.path.join(folder, file)
            with open(path, "rt") as f:
                tmp = f.read()
            write = 0

            # rt_table
            rt = ""
            rt = re.findall(fr"remote\s(.*)\s{port}", tmp)
            if rt:
                # start from id idx_start
                rt_table.setdefault(str(index + idx_start), rt[0])
                rt = rt[0]

            # add read login data from conf file
            if tmp.find("auth-user-pass /etc/openvpn/login.creds") == -1:
                if tmp.find("auth-user-pass /etc/openvpn/login.conf") == -1 and tmp.find("auth-user-pass") != -1:
                    tmp = tmp.replace("auth-user-pass", "")

                tmp += "\nauth-user-pass /etc/openvpn/login.creds"
                tmp += "\nscript-security 2"
                tmp += "\nroute-noexec"
                tmp += "\nroute-up /opt/CAPEv2/utils/route.py"
                tmp += "\nping 10"
                tmp += "\nping-restart 60"
                tmp += "\npull-filter ignore auth-token"
                tmp += "\npull-filter ignore ifconfig-ipv6"
                tmp += "\npull-filter ignore route-ipv6"
                write = 1

            # check device
            dev = re.findall("dev tun0", tmp)
            if dev:
                tmp = tmp.replace("dev tun0", f"dev tun{index + idx_start}")
                # print(file, f"dev tun{index+idx_start}")
                write = 1

            # template for CAPE's routing.conf
            print(
                template.format(
                    vpn_path=path,
                    description=file.split(".ovpn", 1)[0],
                    id=index + idx_start,
                    rt=rt,
                )
            )
            vpns.append(f"vpn_{index + idx_start}")

            file = file.replace(" ", r"\ ")
            paths.append(f"sudo openvpn --config {file} &")

            if write:
                # updating config
                with open(path, "wt") as tmp2:
                    tmp2.write(tmp)

    if vpns:
        print("\n\n\n[+] VPNs for CAPE's routing.conf")
        print(", ".join(vpns))

    if templates:
        print("\n\n\n[+] Templates for CAPE's routing.conf")
        for template in templates:
            print(template)

    if rt_table:
        print("\n\n\n[+] rt_table for /etc/iproute2/rt_tables")
        for route in sorted(rt_table, key=int):
            print(f"{route} {rt_table[route]}")

    if paths:
        print("\n\n\n[+] Paths to execute all in one")
        for path in paths:
            print(path)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-f", "--folder", action="store", help="Path to folder with ovpn configs")
    p.add_argument("-p", "--port", action="store", help="Port used by vpn server")
    args = p.parse_args()
    folder = args.folder
    port = args.port
    main(folder, port)
