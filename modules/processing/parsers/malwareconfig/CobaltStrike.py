from __future__ import absolute_import
from __future__ import print_function
import yara
import re
from struct import unpack, unpack_from
from socket import inet_ntoa

rule_source = '''
rule CobaltStrike {
  meta:
    author = "JPCERTCC"
    description = "Cobalt Strike Payload"
    ref = "https://raw.githubusercontent.com/JPCERTCC/aa-tools/master/cobaltstrikescan.py"
    cape_type = "Cobalt Strike Payload"

  strings:
    $cfg_pattern = { 69 68 69 68 69 }
    $BeaconType = { 00 01 00 01 00 02 }
    $Port = { 00 02 00 01 00 02 } 
    $Polling_ms = { 00 03 00 02 00 04 } 
    $Unknown1 = { 00 04 00 02 00 04 } 
    $Jitter = { 00 05 00 01 00 02 } 
    $Maxdns = { 00 06 00 01 00 02 } 
    $Unknown2 = { 00 07 00 03 01 00 } 
    $C2Server = { 00 08 00 03 01 00 } 
    $UserAgent = { 00 09 00 03 00 80 } 
    $HTTP_Method2_Path = { 00 0a 00 03 00 40 } 
    $Unknown3 = { 00 0b 00 03 01 00 } 
    $Header1 = { 00 0c 00 03 01 00 } 
    $Header2 = { 00 0d 00 03 01 00 } 
    $Injection_Process = { 00 0e 00 03 00 40 } 
    $PipeName = { 00 0f 00 03 00 80 } 
    $Year = { 00 10 00 01 00 02 } 
    $Month = { 00 11 00 01 00 02 } 
    $Day = { 00 12 00 01 00 02 } 
    $DNS_idle = { 00 13 00 02 00 04 } 
    $DNS_sleep_ms = { 00 14 00 02 00 04 } 
    $Method1 = { 00 1a 00 03 00 10 } 
    $Method2 = { 00 1b 00 03 00 10 } 
    $Unknown4 = { 00 1c 00 02 00 04 } 
    $Spawnto_x86 = { 00 1d 00 03 00 40 } 
    $Spawnto_x64 = { 00 1e 00 03 00 40 } 
    $Unknown5 = { 00 1f 00 01 00 02 } 
    $Proxy_HostName = { 00 20 00 03 00 80 } 
    $Proxy_UserName = { 00 21 00 03 00 40 } 
    $Proxy_Password = { 00 22 00 03 00 40 } 
    $Proxy_AccessType = { 00 23 00 01 00 02 } 
    $create_remote_thread = { 00 24 00 01 00 02 } 

  condition:
    any of them
}

'''

CFG_SIZE = 0x1000

CONF_INFO = [
    ['BeaconType', 0x2],
    ['Port', 0x2],
    ['Polling_ms', 0x4],
    ['Unknown1', 0x4],
    ['Jitter', 0x2],
    ['Maxdns', 0x2],
    ['Unknown2', 0x100],
    ['C2Server', 0x100],
    ['UserAgent', 0x80],
    ['HTTP_Method2_Path:', 0x40],
    ['Unknown3', 0x100],
    ['Header1', 0x100],
    ['Header2', 0x100],
    ['Injection_Process:', 0x40],
    ['PipeName', 0x80],
    ['Year', 0x2],
    ['Month', 0x2],
    ['Day', 0x2],
    ['DNS_idle', 0x4],
    ['DNS_sleep_ms', 0x2],
    ['Method1', 0x10],
    ['Method2', 0x10],
    ['Unknown4', 0x4],
    ['Spawnto_x86', 0x40],
    ['Spawnto_x64', 0x40],
    ['Unknown5', 0x2],
    ['Proxy_HostName', 0x80],
    ['Proxy_UserName', 0x40],
    ['Proxy_Password', 0x40],
    ['Proxy_AccessType', 0x2],
    ['create_remote_thread', 0x2]
]

BEACONTYPE = {0x0: "0 (HTTP)", 0x1: "1 (Hybrid HTTP and DNS)", 0x8: "8 (HTTPS)"}
ACCESSTYPE = {0x1: "1 (use direct connection)", 0x2: "2 (use IE settings)", 0x4: "4 (use proxy server)"}


def decode_config(cfg_blob):
    return "".join(chr(ord(cfg_offset) ^ 0x69) for cfg_offset in cfg_blob)


def parse_config(cfg_blob, offsets):
    config_dict = {}

    for name, size in CONF_INFO:
        rname = '${}'.format(name)
        if rname not in offsets:
            config_dict[name] = ''
            continue
        if not offsets[rname]:
            config_dict[name] = ''
            continue
        else:
            cfg_offset = offsets[rname]
        config_data = cfg_blob[cfg_offset + 6:cfg_offset + 6 + size]
        if name == 'Port':
            config_dict[name] = unpack_from('>H', cfg_blob, 0xE)[0]
            continue
        if name.startswith('Unknown'):
            config_dict[name] = repr(config_data)
            continue
        if size == 2:
            if name == 'BeaconType':
                config_dict[name] = BEACONTYPE[unpack('>H', config_data)[0]]
            elif name == 'AccessType':
                config_dict[name] = ACCESSTYPE[unpack('>H', config_data)[0]]
            elif name == 'create_remote_thread':
                if unpack('>H', config_data)[0] != 0:
                    config_dict[name] = "Enable"
                else:
                    config_dict[name] = "Disable"
            else:
                config_dict[name] = unpack('>H', config_data)[0]
        elif size == 4:
            if name == 'DNS_idle':
                config_dict[name] = inet_ntoa(config_data)
            else:
                config_dict[name] = unpack('>I', config_data)[0]
        else:
            if name.startswith('Header'):
                offset = 3
                flag = 0
                txtblock = ""
                while 1:
                    if offset > 255:
                        break
                    else:
                        if config_data[offset] != '\x00':
                            if config_data[offset + 1] != '\x00':
                                if flag:
                                    txtblock = ""
                                txtblock += "{}".format(config_data[(offset + 1):].split('\x00')[0])
                                offset = config_data[offset:].find('\x00\x00\x00') + offset - 1
                                flag += 1
                            else:
                                offset += 4
                                continue
                        else:
                            offset += 4
                            continue
                config_dict[name] = txtblock
            else:
                config_dict[name] = re.sub(r'[^\x1F-\x7f]',r'', config_data)

    return config_dict


def yara_scan(raw_data, rule_name=None):
    addresses = {}
    try:
        yara_rules = yara.compile(source=rule_source)
        matches = yara_rules.match(data=raw_data)
        for match in matches:
            if match.rule == 'CobaltStrike':
                for item in match.strings:
                    if rule_name:
                        if item[1] == rule_name:
                            addresses[item[1]] = item[0]
                            return addresses
                    else:
                        addresses[item[1]] = item[0]
    except Exception as e:
        print(e)

    return addresses


def config(data):
    offsets = yara_scan(data, rule_name='$cfg_pattern')

    if not offsets:
        return

    cfg_offset = offsets['$cfg_pattern']
    cfg_data = data[cfg_offset:cfg_offset + CFG_SIZE]
    cfg_buf = decode_config(cfg_data)
    offsets = yara_scan(cfg_buf)
    cfg_dict = parse_config(cfg_buf, offsets)

    return cfg_dict
