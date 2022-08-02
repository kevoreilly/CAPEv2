import string
from struct import unpack


def calc_length(byte_str):
    try:
        return unpack("<H", byte_str)[0]
    except Exception:
        return None


def clean_string(line):
    return [x for x in line if x in string.printable]


def first_split(data):
    splits = data.split("Software\\Microsoft\\Active Setup\\Installed Components\\".encode())
    return splits[1] if len(splits) == 2 else None


def bytetohex(byte_str):
    return "".join([f"{ord(x):02X}" for x in byte_str]).strip()


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
            length = calc_length(stream[offset + 2: offset + 4])
            temp = [chr(stream[i]) for i in range(offset + 4, offset + 4 + length)]
            date_type = bytetohex(data[offset] + data[offset + 1])
            this.append((date_type, "".join(temp)))
            offset += length + 4
            max_count += 1
        except Exception:
            return this
    return this


def walk_domain(raw_stream):
    domains = []
    offset = 0
    stream = bytearray(raw_stream)
    while offset < len(stream):
        length = stream[offset]
        temp = [chr(stream[i]) for i in range(offset + 1, offset + 1 + length)]
        domain = "".join(temp)

        port = calc_length(raw_stream[offset + length + 2: offset + length + 4])
        offset += length + 4
        domains.append((domain, port))
    return domains


def extract_config(config_raw):
    config = {}

    for field in config_raw:
        if field[0] == "FA0A":
            # Camps
            config.setdefault('campaign_id', []).append(clean_string(field[1]))
        elif field[0] == "F90B":
            # Group ID
            config.setdefault('campaign_id', []).append(clean_string(field[1]))
        elif field[0] == "9001":
            config.setdefault('tcp', []).extend([{
                'server_domain': domain,
                'server_port': port
            } for domain, port in walk_domain(field[1])])
        elif field[0] == "4501":
            config.setdefault('password', []).append(clean_string(field[1]))
        elif field[0] == "120E":
            config.setdefault('registry', []).append({'key': clean_string(field[1])})
        elif field[0] == "6501":
            config.setdefault('registry', []).append({'key': clean_string(field[1])})
        elif field[0] == "4204":
            config.setdefault('inject_exe', []).append(clean_string(field[1]))
        elif field[0] == "Fb03":
            config.setdefault('mutex', []).append(clean_string(field[1]))
        elif field[0] == "2D01":
            config.setdefault('other', {})["Install Name"] = clean_string(field[1])
        elif field[0] == "F703":
            config.setdefault('paths', []).append({'path': clean_string(field[1]), 'usage': 'install'})
        # Below might be capabilities/proxy details?
        elif field[0] == "120D":
            config.setdefault('other', {})["Copy to ADS"] = bytetohex(field[1])
        elif field[0] == "F803":
            config.setdefault('other', {})["Melt"] = bytetohex(field[1])
        elif field[0] == "F903":
            config.setdefault('other', {})["Enable Thread Persistence"] = bytetohex(field[1])
        elif field[0] == "080D":
            config.setdefault('other', {})["Inject Default Browser"] = bytetohex(field[1])
        elif field[0] == "FA03":
            config.setdefault('other', {})["Enable KeyLogger"] = bytetohex(field[1])
        elif field[0] == "090D":
            config.setdefault('other', {})["Enable HKLM"] = bytetohex(field[1])
        elif field[0] == "F603":
            config.setdefault('other', {})["Enable ActiveX"] = bytetohex(field[1])
        elif field[0] == "4101":
            config.setdefault('other', {})["Flag 3"] = bytetohex(field[1])
        elif field[0] == "F40A":
            config.setdefault('other', {})["Hijack Proxy"] = bytetohex(field[1])
        elif field[0] == "F50A":
            config.setdefault('other', {})["Persistent Proxy"] = bytetohex(field[1])

    return config


def domain_parse(config):
    raw_domains = config["Domains"]
    return [domain.split(":", 1)[0] for domain in raw_domains.split("|")]


def extract_config(data):
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
    except Exception:
        return None
