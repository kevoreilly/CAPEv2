#!/usr/bin/env python
"""
ShadowTech Config Extractor
"""

import re
import string

import createIOC
import database

new_line = "#-@NewLine@-#"
split_string = "ESILlzCwXBSrQ1Vb72t6bIXtKRzHJkolNNL94gD8hIi9FwLiiVlrznTz68mkaaJQQSxJfdLyE4jCnl5QJJWuPD4NeO4WFYURvmkth8"
enc_key = "pSILlzCwXBSrQ1Vb72t6bIXtKRzAHJklNNL94gD8hIi9FwLiiVlr"  # Actual key is "KeY11PWD24"


# Helper Functions Go Here


def string_print(line):
    return [x for x in line if x in string.printable]


def get_config(data):
    config_list = []
    config_string = data.split(split_string)
    for x in range(1, len(config_string)):
        try:
            output = ""
            hex_pairs = [config_string[x][i : i + 2] for i in range(0, len(config_string[x]), 2)]
            for i in range(len(config_string[x]) // 2):
                data_slice = int(hex_pairs[i], 16)  # get next hex value
                key_slice = ord(enc_key[i + 1])  # get next Char For Key
                output += chr(data_slice ^ key_slice)  # xor Hex and Key Char
            print(output)
        except Exception:
            output = "DecodeError"
        config_list.append(output)
    return config_list


# returns pretty config
def parse_config(config_list):
    return {
        "Domain": config_list[0],
        "Port": config_list[1],
        "CampaignID": config_list[2],
        "Password": config_list[3],
        "InstallFlag": config_list[4],
        "RegistryKey": config_list[5],
        "Melt": config_list[6],
        "Persistance": config_list[7],
        "Mutex": config_list[8],
        "ShowMsgBox": config_list[9],
        # "Flag5": config_list[10] # MsgBox Icon,
        # "Flag6": config_list[11] # MsgBox Buttons,
        "MsgBoxTitle": config_list[12],
        "MsgBoxText": config_list[13],
    }


"""
def decrypt_XOR(enckey, data):
    # ToDo fix it yourself, XOR not defined
    cipher = XOR.new(enckey)  # set the cipher
    return cipher.decrypt(data)  # decrpyt the data
"""


def snortRule(md5, config_dict):
    rules = []
    domain = config_dict["Domain"]
    ipPattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    ipTest = ipPattern.search(domain)
    if len(domain) > 1:
        if ipTest:
            rules.append(
                f"""alert tcp any any -> {domain}"""
                f""" any (msg: "ShadowTech Beacon Domain: {domain}"""
                """"; classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
        else:
            rules.append(
                f"""alert udp any any -> any 53 (msg: "ShadowTech Beacon Domain: {domain}"""
                f""""; content:"|0e|{domain}"""
                """|00|"; nocase; classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
            rules.append(
                f"""alert tcp any any -> any 53 (msg: "ShadowTech Beacon Domain: {domain}"""
                f""""; content:"|0e|{domain}"""
                """|00|"; nocase; classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
    database.insertSnort(md5, rules)


# IOC Creator Two elements Domain or install
def generateIOC(md5, config_dict):
    items = [
        [
            ("is", "PortItem", "PortItem/remotePort", "string", config_dict["Port"]),
            ("contains", "Network", "Network/DNS", "string", config_dict["Domain"]),
        ]
    ]
    IOC = createIOC.main(items, "ShadowTech", md5)
    database.insertIOC(md5, IOC)


def run(md5, data):
    raw_config = get_config(data)

    # lets Process this and format the config
    config_dict = parse_config(raw_config)
    if len(config_dict["Domain"]) > 0:
        snortRule(md5, config_dict)
        generateIOC(md5, config_dict)
        database.insertDomain(md5, [config_dict["Domain"]])
    return config_dict
