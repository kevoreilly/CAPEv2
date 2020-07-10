# Standard Imports Go Here
from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import string
import pype32

import database
import re
import createIOC


def run(md5, rawData):
    rawconfig = rawData.split("abccba")
    if len(rawconfig) > 1:
        print("Running Abccba")
        conf = oldversions(rawconfig)
    else:
        print("Running pype32")
        pe = pype32.PE(data=rawData)
        rawConfig = getStream(pe)
        conf = parseConfig(rawConfig)
    if not conf:
        return None
    database.insertDomain(md5, [conf["Domain"]])
    return conf


# Confirm if there is Net MetaData in the File
def getStream(pe):
    counter = 0
    for dir in pe.ntHeaders.optionalHeader.dataDirectory:
        if dir.name.value == "NET_METADATA_DIRECTORY":
            rawConfig = findUSStream(pe, counter)
        else:
            counter += 1
    return rawConfig


# I only want to extract the User Strings Section
def findUSStream(pe, dir):
    for i in range(0, 4):
        name = pe.ntHeaders.optionalHeader.dataDirectory[dir].info.netMetaDataStreams[i].name.value
        if name.startswith("#US"):
            return pe.ntHeaders.optionalHeader.dataDirectory[dir].info.netMetaDataStreams[i].info


# Walk the User Strings and create a list of individual strings
def parseConfig(rawConfig):
    stringList = []
    offset = 1
    config = bytearray(rawConfig)
    while offset < len(config):
        length = int(config[offset])
        that = config[offset + 1 : offset + int(length)]
        stringList.append(str(that.replace("\x00", "")))
        offset += int(length + 1)
    print(stringList)
    config = {}
    for i in range(0, 60):
        config["Domain"] = stringList[37]
        config["Port"] = stringList[39]
        config["CampaignID"] = stringList[38]
        config["FolderName"] = stringList[41]
        config["StartUpName"] = stringList[40]
        config["InstallPath"] = stringList[44]
    return config


def oldversions(config):
    config = {}
    if len(config) == 48:
        config["Version"] = "V0.2.6"
        for i in range(1, len(config)):
            config["Domain"] = config[1]  #
            config["Port"] = config[2]  #
            config["CampaignID"] = config[3]  #
            config["DanOption"] = config[5]  #
            config["StartupName"] = config[7]  #
            config["Password"] = config[9]  #
            config["AntiKillServer"] = config[10]  #
            config["USBSpreadlnk"] = config[11]
            config["AntiProcessExplorer"] = config[12]
            config["AntiProcessHacker"] = config[13]
            config["AntiApateDNS"] = config[14]
            config["AntiMalwareBytes"] = config[15]
            config["AntiAntiLogger"] = config[16]
            config["BlockVirusTotal"] = config[17]  #
            config["Mutex"] = config[18]  #
            config["Persistance"] = config[19]  #
            config["SpyGateKey"] = config[20]
            config["StartupFolder"] = config[21]  #
            config["AntiAvira"] = config[23]
            config["USBSpread"] = config[24]
            # 25 if statement below
            config["InstallPath"] = config[26]  #
            config["StartUpName"] = config[27]  #
            config["MeltAfterRun"] = config[28]  #
            config["HideAfterRun"] = config[29]  #
            config["InstallPath2"] = config[33]  #
            # 34 and 35 in if statement below
            config["InstallPath3"] = config[36]
            config["AntiSbieCtrl"] = config[38]
            config["AntiSpyTheSpy"] = config[39]
            config["AntiSpeedGear"] = config[40]
            config["AntiWireshark"] = config[41]
            config["AntiIPBlocker"] = config[42]
            config["AntiCports"] = config[43]
            config["AntiAVG"] = config[44]
            config["AntiOllyDbg"] = config[45]
            config["AntiXNetstat"] = config[46]
        if config[25] == "True":
            config["AppDataFolder"] = "True"
        else:
            config["ApplDataFolder"] = "False"
        if config[34] == "True":
            config["TemplatesFolder"] = "True"
        else:
            config["TemplatesFolder"] = "False"

        if config[35] == "True":
            config["ProgramsFolder"] = "True"
        else:
            config["ProgramsFolder"] = "False"
        return config

    elif len(config) == 18:
        config["Version"] = "V2.0"
        for i in range(1, len(config)):
            print(i, config[i])
            config["Domain"] = config[1]  #
            config["Port"] = config[2]  #
            config["CampaignID"] = config[3]  #
            config["DanOption"] = config[5]  #
            config["AddToStartup"] = config[5]  #
            config["StartupKey"] = config[7]  #
            config["Password"] = config[9]  #
            config["AntiKillServer"] = config[10]  #
            config["USBSpread"] = config[11]  #
            config["KillProcessExplorer"] = config[12]  #
            config["AntiProcessHacker"] = config[13]  #
            config["AntiApateDNS"] = config[14]
            config["AntiMalwareBytes"] = config[15]
            config["AntiAntiLogger"] = config[16]
            config["BlockVirusTotal"] = config[17]
        return config
    else:
        return None


def snortRule(md5, confDict):
    rules = []
    domain = confDict["Domain"]
    ipPattern = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    ipTest = ipPattern.search(domain)
    if len(domain) > 1:
        if ipTest:
            rules.append(
                """alert tcp any any -> """
                + domain
                + """ any (msg: "Pandora Beacon Domain: """
                + domain
                + """"; classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
        else:
            rules.append(
                """alert udp any any -> any 53 (msg: "Pandora Beacon Domain: """
                + domain
                + """"; content:"|0e|"""
                + domain
                + """|00|"; nocase;  classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
            rules.append(
                """alert tcp any any -> any 53 (msg: "Pandora Beacon Domain: """
                + domain
                + """"; content:"|0e|"""
                + domain
                + """|00|"; nocase;  classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
    database.insertSnort(md5, rules)


# IOC Creator Two elements Domain or install
def generateIOC(md5, confDict):
    # Create the list for File Artefacts
    fileIOC = []
    fileIOC.append(("is", "FileItem", "FileItem/FileName", "string", confDict["InstallName"]))
    fileIOC.append(("contains", "FileItem", "FileItem/FilePath", "string", confDict["InstallPath"]))
    fileIOC.append(("is", "FileItem", "FileItem/Md5sum", "md5", md5))
    fileIOC.append(("is", "ProcessItem", "ProcessItem/HandleList/Handle/Name", "string", confDict["Mutex"]))
    # Create the list for Registry Artefacts
    regIOC = []
    regIOC.append(
        ("contains", "RegistryItem", "RegistryItem/Path", "string", "HKEY_LOCAL_MACHINE\Software\Microsoft\Active Setup\Installed Components")
    )
    regIOC.append(("is", "RegistryItem", "RegistryItem/Value", "string", confDict["ActiveXKey"]))
    regIOC.append(
        ("contains", "RegistryItem", "RegistryItem/Path", "string", "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run")
    )
    regIOC.append(("is", "RegistryItem", "RegistryItem/Value", "string", confDict["HKLMValue"]))
    # add each list to our master list
    items = []
    items.append(fileIOC)
    items.append(regIOC)
    domList = []
    domains = confDict["Domains"].split("|")
    for x in domains:
        domain = x.split(":")[0]
        domList.append(domain)
    database.insertDomain(md5, domList)
    for domain in domList:
        if domain != "":
            items.append([("contains", "Network", "Network/DNS", "string", domain)])
    IOC = createIOC.main(items, "PoisonIvy", md5)
    database.insertIOC(md5, IOC)
