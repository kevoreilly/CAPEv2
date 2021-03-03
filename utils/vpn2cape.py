import os
import re
import sys
import argparse

#
#   VPN intergrator for CAPE
#   Quick and Dirty script by doomedraven to preparate configs for vpn integration

def main():
    rt_table = dict()
    templates = list()
    paths = list()
    vpns = list()
    template = """
[vpn_{id}]
# rename this to something different, you will use thil field to see in webgui or set in routing.conf
name = {vpn_path}
description = {description}
interface = tun{id}
rt_table = {rt}
"""

    files = os.listdir(sys.argv[1])
    for index, file in enumerate(files):
        if file.endswith(".ovpn"):
            path = os.path.join(sys.argv[1], file)
            tmp = open(path, "rt").read()
            write = 0

            # rt_table
            rt = ""
            rt = re.findall("remote\s(.*)\s1194", tmp)
            if rt:
                # start from id 5
                rt_table.setdefault(str(index + 5), rt[0])
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
                write = 1

            # check device
            dev = re.findall("dev tun\\b", tmp)
            if dev:
                tmp = tmp.replace("dev tun", "dev tun{0}".format(index + 1))
                # print(file, 'dev tun{0}'.format(index+1))
                write = 1

            # tempalte for CAPE's routing.conf
            print(template.format(vpn_name=file.split("/")[-1], vpn_path=path, description=file.split(".ovpn")[0], id=index + 1, rt=rt))
            vpns.append("vpn_{0}".format(index + 1))

            file = file.replace(" ", "\ ")
            paths.append("sudo openvpn --config {0} --script-security 2 --route-noexec --route-up utils/route.py &".format(file))
            if write:
                # updatign config
                tmp2 = open(path, "wt")
                tmp2.write(tmp)
                tmp2.close()

    if vpns:
        print("\n\n\n[+] VPNs for CAPE's routing.conf")
        print(", ".join(vpns))

    if templates:
        print("\n\n\n[+] Tempaltes for CAPE's routing.conf")
        for template in templates:
            print(template)

    if rt_table:
        print("\n\n\n[+] rt_table for /etc/iproute2/rt_tables")
        for route in sorted(rt_table, key=int):
            print("{0} {1}".format(route, rt_table[route]))

    if paths:
        print("\n\n\n[+] Paths to execute all in one")
        for path in paths:
            print(path)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("-f", "--folder", action="store", help="Path to folder with ovpn configs")
    main()
