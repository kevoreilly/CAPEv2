import re

import database
import ioc


def run(md5, data):
    config_dict = {}
    config = data.split("abccba")
    if len(config) > 5:
        config_dict = {
            "Domain": config[1],
            "Port": config[2],
            "Campaign Name": config[3],
            "Copy StartUp": config[4],
            "StartUp Name": config[5],
            "Add To Registry": config[6],
            "Registry Key": config[7],
            "Melt + Inject SVCHost": config[8],
            "Anti Kill Process": config[9],
            "USB Spread": config[10],
            "Kill AVG 2012-2013": config[11],
            "Kill Process Hacker": config[12],
            "Kill Process Explorer": config[13],
            "Kill NO-IP": config[14],
            "Block Virus Total": config[15],
            "Block Virus Scan": config[16],
            "HideProcess": config[17],
        }
        snortRule(md5, config_dict)
        createIOC(md5, config_dict)
        database.insertDomain(md5, [config_dict["Domain"]])
    return config_dict


def snortRule(md5, config_dict):
    rules = []
    domain = config_dict["Domain"]
    ipPattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    ipTest = ipPattern.search(domain)
    if len(domain) > 1:
        if ipTest:
            rules.append(
                f"""alert tcp any any -> {domain}"""
                f""" any (msg: "VirusRat Beacon Domain: {domain}"""
                """"; classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
        else:
            rules.append(
                f"""alert udp any any -> any 53 (msg: "VirusRat Beacon Domain: {domain}"""
                f""""; content:"|0e|{domain}"""
                """|00|"; nocase; classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)""",
                f"""alert tcp any any -> any 53 (msg: "VirusRat Beacon Domain: {domain}"""
                f""""; content:"|0e|{domain}"""
                """|00|"; nocase; classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)""",
            )
    database.insertSnort(md5, rules)


# IOC Creator Two elements Domain or install
def createIOC(md5, config_dict):
    items = [
        ("contains", "Network", "Network/DNS", "string", config_dict["Domain"]),
        ("is", "PortItem", "PortItem/remotePort", "string", config_dict["Port"]),
        ("is", "ProcessItem", "ProcessItem/name", "string", config_dict["StartUp Name"]),
        ("is", "RegistryItem", "RegistryItem/Value", "string", config_dict["Registry Key"]),
    ]
    IOC = ioc.main(items)
    database.insertIOC(md5, IOC)
