# coding=UTF-8

from __future__ import absolute_import
from __future__ import print_function
import pefile
import yara
from struct import unpack_from
from sys import argv
from binascii import hexlify
from hashlib import md5
from Crypto.Cipher import ARC4

rule_source = '''
rule BackOffPOS {
  meta:
    author = "enzok"
    description = "BackOffPOS Payload"
    cape_type = "BackOffPOS Payload"

    strings:
        $header = "Content-Type: application/x-www-form-urlencoded"
    condition:
        all of them
}

'''


def RC4(key, data):
    cipher = ARC4.new(key)
    return cipher.decrypt(data)


def yara_scan(raw_data, rule_name=None):
    addresses = []
    try:
        yara_rules = yara.compile(source=rule_source)
        matches = yara_rules.match(data=raw_data)
        for match in matches:
            if match.rule == 'BackOffPOS':
                for item in match.strings:
                    if rule_name:
                        if item[1] == rule_name:
                            addresses.append(item)
                    else:
                        addresses.append(item)
    except Exception as e:
        print(e)

    return addresses


def extract_config(data):
    config_data = dict()
    urls = []
    pe = pefile.PE(data=data)
    type(pe)
    for section in pe.sections:
        if ".data" in section.Name:
            data = section.get_data()
            cfg_start = yara_scan(data, rule_name='$header')
            if cfg_start:
                start_offset = cfg_start[0][0] + len(cfg_start[0][2]) + 1
                rc4_seed = bytes(bytearray(unpack_from('>8B', data, offset=start_offset)))
                config_data['RC4Seed'] = hexlify(rc4_seed)
                key = md5(rc4_seed).digest()[:5]
                config_data['EncryptionKey'] = hexlify(key)
                enc_data = bytes(bytearray(unpack_from('>8192B', data, offset=start_offset+8)))
                dec_data = RC4(key, enc_data)
                config_data['Build'] = dec_data[:16].strip('\x00')
                for url in dec_data[16:].split("|"):
                    urls.append(url.strip('\x00'))
                config_data['URLs'] = urls
                config_data['Version'] = unpack_from('>5s', data, offset=start_offset+16+8192)[0]
                print("")
            else:
                return None

    return config_data


def config(task_info, data):
    return extract_config(data)


if __name__ == "__main__":
    filename = argv[1]
    with open(filename, "r") as infile:
        t = config(0, infile.read())
    print(t)