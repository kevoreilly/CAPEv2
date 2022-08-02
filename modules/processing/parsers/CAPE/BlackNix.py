import pefile

AUTHOR = "CAPE"
DESCRIPTION = "BlackNix configuration parser."


def extract_raw_config(raw_data):
    pe = pefile.PE(data=raw_data)
    rt_string_idx = [
        entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(
        pefile.RESOURCE_TYPE["RT_RCDATA"])
    rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
    for entry in rt_string_directory.directory.entries:
        if str(entry.name) == "SETTINGS":
            data_rva = entry.directory.entries[0].data.struct.OffsetToData
            size = entry.directory.entries[0].data.struct.Size
            data = pe.get_memory_mapped_image()[data_rva: data_rva + size]
            return data.split("}")


def decode(line):
    return "".join(chr(ord(char) - 1) for char in line)


def domain_parse(config):
    return [domain.split(":", 1)[0] for domain in config["Domains"].split(";")]


def extract_config(data, apply_MACO=False):
    try:
        config_raw = extract_raw_config(data)
        if config_raw:
            config = {
                'campaign_id': [config['Campaign Name'], config['Campaign Group']],
                'category': ['keylogger', 'apt'],
                'password': [config['Password']],
                'mutex': [config['Mutex']],
                'sleep_delay': config['Delay Time'],
                'paths': [{
                    'path': config['Install Path'],
                    'usage': 'install'
                }],
                'registry': [{
                    'key': config["Registry Key"],
                    'usage': 'other'
                }],
                'other': {
                    'Anti Sandboxie': config['Anti Sandboxie'],
                    'Max Folder Size': config['Max Folder Size'],
                    "Kernel Mode Unhooking": config['Kernel Mode Unhooking'],
                    "User More Unhooking": config["User More Unhooking"],
                    "Melt Server": config["Melt Server"],
                    "Offline Screen Capture": config["Offline Screen Capture"],
                    "Offline Keylogger": config["Offline Keylogger"],
                    "Copy To ADS": config["Copy To ADS"],
                    "Domain": config["Domain"],
                    "Persistence Thread": config["Persistence Thread"],
                    "Active X Key": config["Active X Key"],
                    "Active X Run": config["Active X Run"],
                    "Registry Run": config["Registry Run"],
                    "Safe Mode Startup": config["Safe Mode Startup"],
                    "Inject winlogon.exe": config["Inject winlogon.exe"],
                }
            }

            return config

    except Exception:
        return {}
