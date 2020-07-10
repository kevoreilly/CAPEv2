from __future__ import absolute_import
import string
from struct import unpack


def calc_length(byte_str):
    try:
        return unpack("<H", byte_str)[0]
    except:
        return None


def clean_string(line):
    return [x for x in line if x in string.printable]


def first_split(data):
    splits = data.split("Software\\Microsoft\\Active Setup\\Installed Components\\")
    if len(splits) == 2:
        return splits[1]
    else:
        return None


def bytetohex(byte_str):
    return "".join(["%02X" % ord(x) for x in byte_str]).strip()


def walk_data(data):
    # Byte array to make things easier.
    stream = bytearray(data)
    # End of file for our while loop.
    EOF = len(stream)
    # Offset to track position.
    offset = 0
    this = []
    max_count = 0
    while offset < EOF and max_count < 22:
        try:
            length = calc_length(stream[offset + 2 : offset + 4])
            temp = []
            for i in range(offset + 4, offset + 4 + length):
                temp.append(chr(stream[i]))
            date_type = bytetohex(data[offset] + data[offset + 1])
            this.append((date_type, "".join(temp)))
            offset += length + 4
            max_count += 1
        except:
            return this
    return this


def walk_domain(raw_stream):
    domains = ""
    offset = 0
    stream = bytearray(raw_stream)
    while offset < len(stream):
        length = stream[offset]
        temp = []
        for i in range(offset + 1, offset + 1 + length):
            temp.append(chr(stream[i]))
        domain = "".join(temp)

        port = calc_length(raw_stream[offset + length + 2 : offset + length + 4])
        offset += length + 4
        domains += "{0}:{1}|".format(domain, port)
    return domains


def extract_config(config_raw):
    config = {}

    for field in config_raw:
        if field[0] == "FA0A":
            config["Campaign ID"] = clean_string(field[1])
        if field[0] == "F90B":
            config["Group ID"] = clean_string(field[1])
        if field[0] == "9001":
            config["Domains"] = walk_domain(field[1])
        if field[0] == "4501":
            config["Password"] = clean_string(field[1])
        if field[0] == "090D":
            config["Enable HKLM"] = bytetohex(field[1])
        if field[0] == "120E":
            config["HKLM Value"] = clean_string(field[1])
        if field[0] == "F603":
            config["Enable ActiveX"] = bytetohex(field[1])
        if field[0] == "6501":
            config["ActiveX Key"] = clean_string(field[1])
        if field[0] == "4101":
            config["Flag 3"] = bytetohex(field[1])
        if field[0] == "4204":
            config["Inject Exe"] = clean_string(field[1])
        if field[0] == "Fb03":
            config["Mutex"] = clean_string(field[1])
        if field[0] == "F40A":
            config["Hijack Proxy"] = bytetohex(field[1])
        if field[0] == "F50A":
            config["Persistent Proxy"] = bytetohex(field[1])
        if field[0] == "2D01":
            config["Install Name"] = clean_string(field[1])
        if field[0] == "F703":
            config["Install Path"] = clean_string(field[1])
        if field[0] == "120D":
            config["Copy to ADS"] = bytetohex(field[1])
        if field[0] == "F803":
            config["Melt"] = bytetohex(field[1])
        if field[0] == "F903":
            config["Enable Thread Persistence"] = bytetohex(field[1])
        if field[0] == "080D":
            config["Inject Default Browser"] = bytetohex(field[1])
        if field[0] == "FA03":
            config["Enable KeyLogger"] = bytetohex(field[1])

    return config


def domain_parse(config):
    domain_list = []
    raw_domains = config["Domains"]
    for domain in raw_domains.split("|"):
        domain_list.append(domain.split(":")[0])
    return domain_list


def config(data):
    try:
        # Split to get start of Config.
        one = first_split(data)
        if not one:
            return None
        # If the split works try to walk the strings.
        two = walk_data(one)
        # Let's Process this and format the config.
        final_config = extract_config(two)
        domain_data = domain_parse(final_config)
        return [final_config, domain_data]
    except:
        return None
