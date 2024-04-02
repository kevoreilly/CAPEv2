import re
from base64 import b64decode
from io import StringIO
from zipfile import ZipFile

import database
from Cryptodome.Cipher import AES, DES3


def run(md5, data):
    print("[+] Extracting Data from Jar")
    enckey, conf = get_parts(data)
    if enckey is None:
        return
    print(f"[+] Decoding Config with Key: {enckey.encode().hex()}")
    if len(enckey) == 16:
        # Newer versions use a base64 encoded config.dat
        # this is not a great test but should work 99% of the time
        decrypt_func = new_aes if "==" in conf else old_aes
        raw_config = decrypt_func(conf, enckey)
    elif len(enckey) == 32:
        raw_config = old_des(conf, enckey)
    config_dict = parse_config(raw_config, enckey)
    snortRule(md5, config_dict)
    database.insertDomain(md5, [config_dict["Domain"]])
    return config_dict


# Helper Functions Go Here


# This extracts the Encryption Key and Config File from the Jar and or Dropper
def get_parts(data):
    new_zip = StringIO(data)
    enckey = None
    dropper = None
    conf = None
    try:
        with ZipFile(new_zip, "r") as zip:
            for name in zip.namelist():  # get all the file names
                if name == "key.dat":  # this file contains the encrytpion key
                    enckey = zip.read(name)
                elif name == "enc.dat":  # if this file exists, jrat has an installer / dropper
                    dropper = zip.read(name)
                elif name == "config.dat":  # this is the encrypted config file
                    conf = zip.read(name)
    except Exception:
        print(f"[+] Dropped File is not Jar File starts with Hex Chars: {data[:5].encode().hex()}")
        return None, None
    if enckey and conf:
        return enckey, conf
    elif enckey and dropper:
        newkey, conf = get_dropper(enckey, dropper)
        return newkey, conf
    return None, None


# This extracts the Encryption Key and New conf from a 'Dropper' jar
def get_dropper(enckey, dropper):
    split = enckey.split("\x2c")
    key = split[0][:16]
    print("[+] Dropper Detected")
    for x in split:  # grab each line of the config and decode it.
        try:
            drop = b64decode(x).decode("hex")
            print(f"    [-] {drop}".replace("\x0d\x0a", ""))
        except Exception:
            drop = b64decode(x[16:]).decode("hex")
            print(f"    [-] {drop}")
    new_zipdata = decrypt_aes(key, dropper)
    new_key, conf = get_parts(new_zipdata)
    return new_key, conf


# Returns only printable chars
def string_print(line):
    return "".join((char for char in line if 32 < ord(char) < 127))


# Messy Messy Messy
def messy_split(long_line):
    # this is a messy way to split the data but it works for now.
    """
    Split on = gives me the right sections but deletes the b64 padding
    use modulo math to restore padding.
    return new list.
    """
    new_list = []
    old_list = long_line.split("=")
    for line in old_list:
        if len(line) != 0:
            line += "=" * ((4 - len(line) % 4) % 4)
            new_list.append(line)
    return new_list


# AES Decrypt
def decrypt_aes(enckey, data):
    cipher = AES.new(enckey)  # set the cipher
    return cipher.decrypt(data)  # decrpyt the data


# DES Decrypt
def decrypt_des(enckey, data):
    cipher = DES3.new(enckey)  # set the ciper
    return cipher.decrypt(data)  # decrpyt the data


# Process Versions 3.2.2 > 4.2.
def old_aes(conf, enckey):
    decoded_config = decrypt_aes(enckey, conf)
    clean_config = string_print(decoded_config)
    return clean_config.split("SPLIT")


# Process versions 4.2. >
def new_aes(conf, enckey):
    sections = messy_split(conf)
    decoded_config = "".join(decrypt_aes(enckey, b64decode(x)) for x in sections)
    return string_print(decoded_config).split("SPLIT")


# process versions < 3.2.2
def old_des(conf, enckey):
    decoded_config = decrypt_des(conf, enckey)
    clean_config = string_print(decoded_config)
    return clean_config.split("SPLIT")


def parse_config(raw_config, enckey):
    config_dict = {}
    for kv in raw_config:
        if kv == "":
            continue
        kv = string_print(kv)
        key, value = kv.split("=")
        if key == "ip":
            config_dict["Domain"] = value
        elif key == "port":
            config_dict["Port"] = value
        elif key == "os":
            config_dict["OS"] = value
        elif key == "mport":
            config_dict["MPort"] = value
        elif key == "perms":
            config_dict["Perms"] = value
        elif key == "error":
            config_dict["Error"] = value
        elif key == "reconsec":
            config_dict["RetryInterval"] = value
        elif key == "ti":
            config_dict["TI"] = value
        elif key == "pass":
            config_dict["Password"] = value
        elif key == "id":
            config_dict["CampaignID"] = value
        elif key == "mutex":
            config_dict["Mutex"] = value
        elif key == "toms":
            config_dict["TimeOut"] = value
        elif key == "per":
            config_dict["Persistance"] = value
        elif key == "name":
            config_dict["Name"] = value
        elif key == "tiemout":
            config_dict["TimeOutFlag"] = value
        elif key == "debugmsg":
            config_dict["DebugMsg"] = value
    config_dict["EncryptionKey"] = enckey
    return config_dict


def snortRule(md5, conf):
    rules = []
    domain = conf["Domain"]
    ipPattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
    ipTest = ipPattern.search(domain)
    if len(domain) > 1:
        if ipTest:
            rules.append(
                f"""alert tcp any any -> {domain}"""
                f""" any (msg: "jRat Beacon Domain: {domain}"""
                """"; classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
        else:
            rules.append(
                f"""alert udp any any -> any 53 (msg: "jRat Beacon Domain: {domain}"""
                f""""; content:"|0e|{domain}"""
                """|00|"; nocase;  classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
            rules.append(
                f"""alert tcp any any -> any 53 (msg: "jRat Beacon Domain: {domain}"""
                f""""; content:"|0e|{domain}"""
                """|00|"; nocase;  classtype:trojan-activity; sid:5000000; rev:1; priority:1; reference:url,http://malwareconfig.com;)"""
            )
    database.insertSnort(md5, rules)
