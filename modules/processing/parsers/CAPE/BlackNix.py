import pefile

AUTHOR = "CAPE"
DESCRIPTION = "BlackNix configuration parser."


def extract_raw_config(raw_data):
    pe = pefile.PE(data=raw_data)
    rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE["RT_RCDATA"])
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


def extract_config(data):
    try:
        config_raw = extract_raw_config(data)
        if config_raw:
            config = {
                "campaign_id": [config_raw["Campaign Name"], config_raw["Campaign Group"]],
                "category": ["keylogger", "apt"],
                "password": [config_raw["Password"]],
                "mutex": [config_raw["Mutex"]],
                "sleep_delay": config_raw["Delay Time"],
                "paths": [{"path": config_raw["Install Path"], "usage": "install"}],
                "registry": [{"key": config_raw["Registry Key"], "usage": "other"}],
                "other": {
                    "Anti Sandboxie": config_raw["Anti Sandboxie"],
                    "Max Folder Size": config_raw["Max Folder Size"],
                    "Kernel Mode Unhooking": config_raw["Kernel Mode Unhooking"],
                    "User More Unhooking": config_raw["User More Unhooking"],
                    "Melt Server": config_raw["Melt Server"],
                    "Offline Screen Capture": config_raw["Offline Screen Capture"],
                    "Offline Keylogger": config_raw["Offline Keylogger"],
                    "Copy To ADS": config_raw["Copy To ADS"],
                    "Domain": config_raw["Domain"],
                    "Persistence Thread": config_raw["Persistence Thread"],
                    "Active X Key": config_raw["Active X Key"],
                    "Active X Run": config_raw["Active X Run"],
                    "Registry Run": config_raw["Registry Run"],
                    "Safe Mode Startup": config_raw["Safe Mode Startup"],
                    "Inject winlogon.exe": config_raw["Inject winlogon.exe"],
                },
            }

            return config

    except Exception:
        return {}
