#!/usr/bin/env python
"""
ShadowTech Config Extractor
"""

from __future__ import absolute_import
from __future__ import print_function
import database
import createIOC
import re
import string
from operator import xor

new_line = "#-@NewLine@-#"
split_string = "ESILlzCwXBSrQ1Vb72t6bIXtKRzHJkolNNL94gD8hIi9FwLiiVlrznTz68mkaaJQQSxJfdLyE4jCnl5QJJWuPD4NeO4WFYURvmkth8"  #
enc_key = "pSILlzCwXBSrQ1Vb72t6bIXtKRzAHJklNNL94gD8hIi9FwLiiVlr"  # Actual key is 'KeY11PWD24'


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
            for i in range(0, len(config_string[x]) / 2):
                data_slice = int(hex_pairs[i], 16)  # get next hex value

                key_slice = ord(enc_key[i + 1])  # get next Char For Key
                output += chr(xor(data_slice, key_slice))  # xor Hex and Key Char
            print(output)
        except:
            output = "DecodeError"
        config_list.append(output)
    return config_list


# returns pretty config
def parse_config(config_list):
    config_dict = {}
    config_dict["Domain"] = config_list[0]
    config_dict["Port"] = config_list[1]
    config_dict["CampaignID"] = config_list[2]
    config_dict["Password"] = config_list[3]
    config_dict["InstallFlag"] = config_list[4]
    config_dict["RegistryKey"] = config_list[5]
    config_dict["Melt"] = config_list[6]
    config_dict["Persistance"] = config_list[7]
    config_dict["Mutex"] = config_list[8]
    config_dict["ShowMsgBox"] = config_list[9]
    # config_dict['Flag5'] = config_list[10] # MsgBox Icon
    # config_dict['Flag6'] = config_list[11] # MsgBox Buttons
    config_dict["MsgBoxTitle"] = config_list[12]
    config_dict["MsgBoxText"] = config_list[13]
    return config_dict

"""
def decrypt_XOR(enckey, data):
    # ToDo fix it yourself, XOR not defined
    cipher = XOR.new(enckey)  # set the cipher
    return cipher.decrypt(data)  # decrpyt the data
"""

def snortRule(md5, config_dict):
    rules = []
    domain = config_dict["Domain"]
    ipPattern = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    ipTest = ipPattern.search(domain)
    if len(domain) > 1:
        if ipTest:
            rules.append(
                """alert tcp any any -> """
                + domain
                + """ any (msg: "ShadowTech Beacon Domain: """
                + domain
                + """"; classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
        else:
            rules.append(
                """alert udp any any -> any 53 (msg: "ShadowTech Beacon Domain: """
                + domain
                + """"; content:"|0e|"""
                + domain
                + """|00|"; nocase;  classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
            rules.append(
                """alert tcp any any -> any 53 (msg: "ShadowTech Beacon Domain: """
                + domain
                + """"; content:"|0e|"""
                + domain
                + """|00|"; nocase;  classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
    database.insertSnort(md5, rules)


# IOC Creator Two elements Domain or install
def generateIOC(md5, config_dict):
    netIOC = []
    netIOC.append(("is", "PortItem", "PortItem/remotePort", "string", config_dict["Port"]))
    netIOC.append(("contains", "Network", "Network/DNS", "string", config_dict["Domain"]))
    # add each list to our master list
    items = []
    items.append(netIOC)
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
