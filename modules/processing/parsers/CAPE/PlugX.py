# PlugX config parser for CAPE
#
# Based on PlugX RAT detection and analysis for Volatility 2.0, version 1.2
#
# Author: Fabien Perigaud <fabien.perigaud@cassidian.com>
#
# Modified for CAPE by Kevin O'Reilly <kevin.oreilly@contextis.co.uk>
#
# This plugin is based on poisonivy.py by Andreas Schuster.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

import socket
from collections import OrderedDict, defaultdict
from socket import inet_ntoa
from struct import calcsize, unpack_from

persistence = defaultdict(lambda: "Unknown", {0: "Service + Run Key", 1: "Service", 2: "Run key", 3: "None"})
regs = defaultdict(
    lambda: "Unknown",
    {
        0x80000000: "HKEY_CLASSES_ROOT",
        0x80000001: "HKEY_CURRENT_USER",
        0x80000002: "HKEY_LOCAL_MACHINE",
        0x80000003: "HKEY_USERS",
        0x80000005: "HKEY_CURRENT_CONFIG",
    },
)


def get_str_utf16le(buff):
    tstrend = buff.find(b"\x00\x00")
    tstr = buff[: tstrend + (tstrend & 1)]
    return tstr.decode()


def get_proto(proto):
    ret = []
    if proto & 0x1:
        ret.append("TCP")
    if proto & 0x2:
        ret.append("HTTP")
    if proto & 0x4:
        ret.append("UDP")
    if proto & 0x8:
        ret.append("ICMP")
    if proto & 0x10:
        ret.append("DNS")
    if proto > 0x1F:
        ret.append("OTHER_UNKNOWN")
    return " / ".join(ret)


def get_proto2(proto):
    protos = ("???", "???", "????", "TCP", "HTTP", "DNS", "UDP", "ICMP", "RAW", "???", "???")
    try:
        ret = protos[proto] + f"({proto})"
    except Exception:
        ret = f"UNKNOWN ({proto})"
    return ret


def get_timer_string(timer: tuple) -> str:
    timer_str = ""
    if timer[0] != 0:
        timer_str += f"{timer[0]} days, "
    if timer[1] != 0:
        timer_str += f"{timer[1]} hours, "
    if timer[2] != 0:
        timer_str += f"{timer[2]} mins, "
    timer_str += f"{timer[3]} secs"
    return timer_str


def extract_config(cfg_blob):
    cfg_sz = len(cfg_blob)
    config_output = OrderedDict()
    if cfg_sz not in (0xBE4, 0x150C, 0x1510, 0x170C, 0x1B18, 0x1D18, 0x2540, 0x254C, 0x2D58, 0x36A4, 0x4EA4):
        return None
    if cfg_sz == 0x1510:
        cfg_blob = cfg_blob[12:]
    elif cfg_sz in (0x36A4, 0x4EA4):
        cfg_blob = cfg_blob
    else:
        cfg_blob = cfg_blob[8:]
    # Flags
    if cfg_sz == 0xBE4:
        desc = "<L"
    elif cfg_sz in (0x36A4, 0x4EA4):
        desc = "<10L"
    else:
        desc = "<11L"
    flags = unpack_from(desc, cfg_blob)
    cfg_blob = cfg_blob[calcsize(desc) :]
    config_output.update({"Flags": ([str(k != 0) for k in flags])})
    # 2 timers
    timer = unpack_from("4B", cfg_blob)
    cfg_blob = cfg_blob[4:]
    timer_str = get_timer_string(timer)
    config_output.update({"Timer 1": timer_str})
    timer = unpack_from("4B", cfg_blob)
    cfg_blob = cfg_blob[4:]
    timer_str = get_timer_string(timer)
    config_output.update({"Timer 2": timer_str})
    # Timetable
    timetable = cfg_blob[:0x2A0]
    cfg_blob = cfg_blob[0x2A0:]
    space = any(char != "\x01" for char in timetable)
    if space:
        config_output.update({"TimeTable": "Custom"})
    # Custom DNS
    dns1, dns2, dns3, dns4 = unpack_from("<4L", cfg_blob)
    custom_dns = cfg_blob[:0x10]
    cfg_blob = cfg_blob[0x10:]
    if dns1 not in (0, 0xFFFFFFFF):
        config_output.update({"Custom DNS 1": inet_ntoa(custom_dns[:4])})
    if dns2 not in (0, 0xFFFFFFFF):
        config_output.update({"Custom DNS 2": inet_ntoa(custom_dns[4:8])})
    if dns3 not in (0, 0xFFFFFFFF):
        config_output.update({"Custom DNS 3": inet_ntoa(custom_dns[8:12])})
    if dns4 not in (0, 0xFFFFFFFF):
        config_output.update({"Custom DNS 4": inet_ntoa(custom_dns[12:16])})
    # CC
    num_cc = 4 if cfg_sz not in (0x36A4, 0x4EA4) else 16
    get_proto_func = get_proto if cfg_sz not in (0x36A4, 0x4EA4) else get_proto2
    cc_list = []
    for _ in range(num_cc):
        proto, cc_port, cc_address = unpack_from("<2H64s", cfg_blob)
        cfg_blob = cfg_blob[0x44:]
        proto = get_proto_func(proto)
        cc_address = cc_address.split(b"\x00", 1)[0].decode()
        if cc_address != "":
            cc_list.append(f"{cc_address}:{cc_port} (proto)")
    if cc_list:
        config_output.update({"C&C Address": cc_list})
    # Additional URLs
    num_url = 4 if cfg_sz not in (0x36A4, 0x4EA4) else 16
    url_list = []
    for _ in range(num_url):
        url = cfg_blob[:0x80].split(b"\x00", 1)[0].decode()
        cfg_blob = cfg_blob[0x80:]
        if len(url) > 0 and str(url) != "HTTP://":
            url_list.append(str(url))
    if url_list:
        config_output.update({"URL": url_list})
    # Proxies
    proxy_list = []
    proxy_creds = []
    for _ in range(4):
        ptype, port, proxy, user, passwd = unpack_from("<2H64s64s64s", cfg_blob)
        cfg_blob = cfg_blob[calcsize("<2H64s64s64s") :]
        if proxy[0] != "\x00":
            proxy_list.append("{}:{}".format(proxy.split(b"\x00", 1)[0].decode(), port))
            if user[0] != b"\x00":
                proxy_creds.append(f"{user.decode()} / {passwd.decode()}\0")
    if proxy_list:
        config_output.update({"Proxy": proxy_list})
    if proxy_creds:
        config_output.update({"Proxy credentials": proxy_creds})
    str_sz = 0x80 if cfg_sz == 0xBE4 else 0x200
    # Persistence
    if cfg_sz in (0x1B18, 0x1D18, 0x2540, 0x254C, 0x2D58, 0x36A4, 0x4EA4):
        persistence_type = unpack_from("<L", cfg_blob)[0]
        cfg_blob = cfg_blob[4:]
        config_output.update({"Persistence Type": persistence[persistence_type]})
    install_dir = get_str_utf16le(cfg_blob[:str_sz])
    cfg_blob = cfg_blob[str_sz:]
    config_output.update({"Install Dir": install_dir})
    # Service
    service_name = get_str_utf16le(cfg_blob[:str_sz])
    cfg_blob = cfg_blob[str_sz:]
    config_output.update({"Service Name": service_name})
    service_disp = get_str_utf16le(cfg_blob[:str_sz])
    cfg_blob = cfg_blob[str_sz:]
    config_output.update({"Service Disp": service_disp})
    service_desc = get_str_utf16le(cfg_blob[:str_sz])
    cfg_blob = cfg_blob[str_sz:]
    config_output.update({"Service Desc": service_desc})
    # Run key
    if cfg_sz in (0x1B18, 0x1D18, 0x2540, 0x254C, 0x2D58, 0x36A4, 0x4EA4):
        reg_hive = unpack_from("<L", cfg_blob)[0]
        cfg_blob = cfg_blob[4:]
        reg_key = get_str_utf16le(cfg_blob[:str_sz])
        cfg_blob = cfg_blob[str_sz:]
        reg_value = get_str_utf16le(cfg_blob[:str_sz])
        cfg_blob = cfg_blob[str_sz:]
        config_output.update({"Registry hive": regs[reg_hive]})
        config_output.update({"Registry key": reg_key})
        config_output.update({"Registry value": reg_value})
    # Net injection
    if cfg_sz in (0x1B18, 0x1D18, 0x2540, 0x254C, 0x2D58, 0x36A4, 0x4EA4):
        inject = unpack_from("<L", cfg_blob)[0]
        cfg_blob = cfg_blob[4:]
        config_output.update({"Net injection": (f"{inject == 1}\0")})
        i = 4 if cfg_sz in (0x2540, 0x254C, 0x2D58, 0x36A4, 0x4EA4) else 1
        for _ in range(i):
            inject_in = get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            if inject_in != "":
                config_output.update({"Net injection process": inject_in})
    # Elevation injection
    if cfg_sz in (0x2D58, 0x36A4, 0x4EA4):
        inject = unpack_from("<L", cfg_blob)[0]
        cfg_blob = cfg_blob[4:]
        config_output.update({"Elevation injection": (f"{inject == 1}\0")})
        for _ in range(4):
            inject_in = get_str_utf16le(cfg_blob[:str_sz])
            cfg_blob = cfg_blob[str_sz:]
            if inject_in != "":
                config_output.update({"Elevation injection process": inject_in})
    # Memo / Pass / Mutex
    if cfg_sz in (0xBE4, 0x150C, 0x1510, 0x170C, 0x1B18, 0x1D18, 0x2540, 0x254C, 0x2D58, 0x36A4, 0x4EA4):
        online_pass = get_str_utf16le(cfg_blob[:str_sz])
        cfg_blob = cfg_blob[str_sz:]
        config_output.update({"Online Pass": online_pass})
        memo = get_str_utf16le(cfg_blob[:str_sz])
        cfg_blob = cfg_blob[str_sz:]
        config_output.update({"Memo": memo})
    if cfg_sz in (0x1D18, 0x2540, 0x254C, 0x2D58, 0x36A4, 0x4EA4):
        mutex = get_str_utf16le(cfg_blob[:str_sz])
        cfg_blob = cfg_blob[str_sz:]
        config_output.update({"Mutex": mutex})
    if cfg_sz == 0x170C:
        app = get_str_utf16le(cfg_blob[:str_sz])
        cfg_blob = cfg_blob[str_sz:]
        config_output.update({"Application Name": app})
    # Screenshots
    if cfg_sz in (0x2540, 0x254C, 0x2D58, 0x36A4, 0x4EA4):
        screenshots, freq, zoom, color, qual, days = unpack_from("<6L", cfg_blob)
        cfg_blob = cfg_blob[calcsize("<6L") :]
        config_output.update({"Screenshots": (f"{screenshots != 0}\0")})
        config_output.update(
            {"Screenshots params": (f"{freq} sec / Zoom {zoom} / {color} bits / Quality {qual} / Keep {days} days\0")}
        )
        screen_path = get_str_utf16le(cfg_blob[:str_sz])
        cfg_blob = cfg_blob[str_sz:]
        config_output.update({"Screenshots path": screen_path})
    # Lateral
    if cfg_sz in (0x2540, 0x254C, 0x2D58, 0x36A4, 0x4EA4):
        udp_enabled, udp_port, tcp_enabled, tcp_port = unpack_from("<4L", cfg_blob)
        if tcp_enabled == 1:
            config_output.update({"Lateral movement TCP port": (f"{tcp_port}\0")})
        if udp_enabled == 1:
            config_output.update({"Lateral movement UDP port": (f"{udp_port}\0")})
        cfg_blob = cfg_blob[calcsize("<4L") :]
    if cfg_sz in (0x254C, 0x2D58, 0x36A4, 0x4EA4):
        icmp_enabled, icmp_port = unpack_from("<2L", cfg_blob)
        if icmp_enabled == 1:
            config_output.update({"Lateral movement ICMP port (?)": (f"{icmp_port}\0")})
        cfg_blob = cfg_blob[calcsize("<2L") :]
    if cfg_sz in (0x36A4, 0x4EA4):
        protoff_enabled, protoff_port = unpack_from("<2L", cfg_blob)
        if protoff_enabled == 1:
            config_output.update({"Lateral movement Protocol 0xff port (?)": (f"{protoff_port}\0")})
        cfg_blob = cfg_blob[calcsize("<2L") :]
    if cfg_sz in (0x36A4, 0x4EA4):
        p2p_scan = unpack_from("<L", cfg_blob)
        if p2p_scan != 0:
            config_output.update({"P2P Scan LAN range": ("True\0")})
        cfg_blob = cfg_blob[calcsize("<L") :]
        p2p_start = cfg_blob[: 4 * calcsize("<L")]
        cfg_blob = cfg_blob[4 * calcsize("<L") :]
        p2p_stop = cfg_blob[: 4 * calcsize("<L")]
        cfg_blob = cfg_blob[4 * calcsize("<L") :]
        for i in range(4):
            if p2p_start[i * calcsize("<L") : i * calcsize("<L") + calcsize("<L")] != "\0\0\0\0":
                config_output.update(
                    {
                        "P2P Scan range %d start": (
                            i,
                            socket.inet_ntoa(p2p_start[i * calcsize("<L") : i * calcsize("<L") + calcsize("<L")]),
                        )
                    }
                )
                config_output.update(
                    {
                        "P2P Scan range %d stop": (
                            i,
                            socket.inet_ntoa(p2p_stop[i * calcsize("<L") : i * calcsize("<L") + calcsize("<L")]),
                        )
                    }
                )
    if cfg_sz in (0x36A4, 0x4EA4):
        mac_addr = cfg_blob[:6]
        if mac_addr != "\0\0\0\0\0\0":
            config_output.update({"Mac Address black list": (f"{k:02x}" for k in mac_addr)})
        cfg_blob = cfg_blob[6:]
    if cfg_sz == 0x4EA4:
        process_list = []
        for _ in range(8):
            process_name = get_str_utf16le(cfg_blob[:0x100])
            cfg_blob = cfg_blob[0x100:]
            if process_name != "":
                process_list.append(process_name)
        if process_list:
            config_output.update({"Process black list": process_list})
        file_list = []
        for _ in range(8):
            file_name = get_str_utf16le(cfg_blob[:0x100])
            cfg_blob = cfg_blob[0x100:]
            if process_name != "":
                file_list.append(file_name)
        if file_list:
            config_output.update({"File black list": file_list})
        reg_list = []
        for _ in range(8):
            reg_name = get_str_utf16le(cfg_blob[:0x100])
            cfg_blob = cfg_blob[0x100:]
            if process_name != "":
                reg_list.append(reg_name)
        if reg_list:
            config_output.update({"Registry black list": reg_list})
    return config_output
