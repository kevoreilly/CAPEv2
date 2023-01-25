import pefile


def version_21(raw_config):
    if raw_config is None:
        return None
    return {
        "Version": "2.1",
        "Domain": raw_config[0],
        "Port": raw_config[1],
        "Password": raw_config[2],
        "Install Path": raw_config[3],
        "Install Name": raw_config[4],
        "HKCU Key": raw_config[5],
        "ActiveX Key": raw_config[6],
        "Install Flag": raw_config[7],
        "StartupFlag": raw_config[8],
        "ActiveXFlag": raw_config[9],
        "HKCU Flag": raw_config[10],
        "Mutex": raw_config[11],
        "userMode Hooking": raw_config[12],
        "Melt": raw_config[13],
        "Keylogger": raw_config[14],
        "Campaign ID": raw_config[15],
        "UnknownFlag9": raw_config[16],
    }


def version_22(raw_config):
    if raw_config is None:
        return None
    return {
        "Version": "2.2",
        "Domain": raw_config[0],
        "Port": raw_config[1],
        "Password": raw_config[2],
        "Install Path": raw_config[3],
        "Install Name": raw_config[4],
        "HKCU Key": raw_config[5],
        "ActiveX Key": raw_config[6],
        "Install Flag": raw_config[7],
        "StartupFlag": raw_config[8],
        "ActiveXFlag": raw_config[9],
        "HKCU Flag": raw_config[10],
        "Mutex": raw_config[11],
        "userMode Hooking": raw_config[12],
        "Melt": raw_config[13],
        "Keylogger": raw_config[14],
        "Campaign ID": raw_config[15],
        "UnknownFlag9": raw_config[16],
    }


def get_config(data):
    try:
        pe = pefile.PE(data=data)
        rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE["RT_RCDATA"])
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "CFG":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                cleaned = data.replace("\x00", "")
                return cleaned.split("##")
    except Exception:
        return


def extract_config(data):
    raw_config = get_config(data)
    if raw_config:
        if len(raw_config) == 19:
            clean_config = version_21(raw_config)
        elif len(raw_config) == 20:
            clean_config = version_22(raw_config)
        return clean_config
