import pefile


def extract_raw_config(raw_data):
    try:
        pe = pefile.PE(data=raw_data)
        rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE["RT_RCDATA"])
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "SETTINGS":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                return data.split("}")
    except Exception:
        return None


def decode(line):
    return "".join(chr(ord(char) - 1) for char in line)


def domain_parse(config):
    return [domain.split(":", 1)[0] for domain in config["Domains"].split(";")]


def extract_config(data):
    try:
        config_raw = extract_raw_config(data)
        if config_raw:
            return {
                "Mutex": decode(config_raw[1])[::-1],
                "Anti Sandboxie": decode(config_raw[2])[::-1],
                "Max Folder Size": decode(config_raw[3])[::-1],
                "Delay Time": decode(config_raw[4])[::-1],
                "Password": decode(config_raw[5])[::-1],
                "Kernel Mode Unhooking": decode(config_raw[6])[::-1],
                "User More Unhooking": decode(config_raw[7])[::-1],
                "Melt Server": decode(config_raw[8])[::-1],
                "Offline Screen Capture": decode(config_raw[9])[::-1],
                "Offline Keylogger": decode(config_raw[10])[::-1],
                "Copy To ADS": decode(config_raw[11])[::-1],
                "Domain": decode(config_raw[12])[::-1],
                "Persistence Thread": decode(config_raw[13])[::-1],
                "Active X Key": decode(config_raw[14])[::-1],
                "Registry Key": decode(config_raw[15])[::-1],
                "Active X Run": decode(config_raw[16])[::-1],
                "Registry Run": decode(config_raw[17])[::-1],
                "Safe Mode Startup": decode(config_raw[18])[::-1],
                "Inject winlogon.exe": decode(config_raw[19])[::-1],
                "Install Name": decode(config_raw[20])[::-1],
                "Install Path": decode(config_raw[21])[::-1],
                "Campaign Name": decode(config_raw[22])[::-1],
                "Campaign Group": decode(config_raw[23])[::-1],
            }
    except Exception:
        return None
