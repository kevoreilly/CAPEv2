from __future__ import absolute_import
import pefile
import database
import re
import ioc


def run(md5, data):
    dict = {}
    config = data.split("abccba")
    if len(config) > 5:
        dict["Domain"] = config[1]
        dict["Port"] = config[2]
        dict["Campaign Name"] = config[3]
        dict["Copy StartUp"] = config[4]
        dict["StartUp Name"] = config[5]
        dict["Add To Registry"] = config[6]
        dict["Registry Key"] = config[7]
        dict["Melt + Inject SVCHost"] = config[8]
        dict["Anti Kill Process"] = config[9]
        dict["USB Spread"] = config[10]
        dict["Kill AVG 2012-2013"] = config[11]
        dict["Kill Process Hacker"] = config[12]
        dict["Kill Process Explorer"] = config[13]
        dict["Kill NO-IP"] = config[14]
        dict["Block Virus Total"] = config[15]
        dict["Block Virus Scan"] = config[16]
        dict["HideProcess"] = config[17]
        snortRule(md5, dict)
        createIOC(md5, dict)
        database.insertDomain(md5, [dict["Domain"]])
    return dict


def snortRule(md5, dict):
    rules = []
    domain = dict["Domain"]
    ipPattern = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    ipTest = ipPattern.search(domain)
    if len(domain) > 1:
        if ipTest:
            rules.append(
                """alert tcp any any -> """
                + domain
                + """ any (msg: "VirusRat Beacon Domain: """
                + domain
                + """"; classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
        else:
            rules.append(
                """alert udp any any -> any 53 (msg: "VirusRat Beacon Domain: """
                + domain
                + """"; content:"|0e|"""
                + domain
                + """|00|"; nocase;  classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
            rules.append(
                """alert tcp any any -> any 53 (msg: "VirusRat Beacon Domain: """
                + domain
                + """"; content:"|0e|"""
                + domain
                + """|00|"; nocase;  classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
    database.insertSnort(md5, rules)


# IOC Creator Two elements Domain or install
def createIOC(md5, dict):
    items = []
    domain = dict["Domain"]
    items.append(("contains", "Network", "Network/DNS", "string", domain))
    items.append(("is", "PortItem", "PortItem/remotePort", "string", dict["Port"]))

    install = [
        ("is", "ProcessItem", "ProcessItem/name", "string", dict["StartUp Name"]),
        ("is", "RegistryItem", "RegistryItem/Value", "string", dict["Registry Key"]),
    ]
    for x in install:
        items.append(x)
    IOC = ioc.main(items)
    database.insertIOC(md5, IOC)
