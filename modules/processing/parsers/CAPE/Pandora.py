import os
import pefile


def version_21(raw_config):
    if raw_config is None:
        return None
    return {
        'family': "Pandora",
        "version": "2.1",
        'campaign_id': raw_config[15],
        'tcp': [{
            'server_domain': raw_config[0],
            'server_port': raw_config[1]
        }],
        'password': [raw_config[2]],
        'paths': [{
            'path': os.path.join(raw_config[3], raw_config[4]),
            'usage': 'install'
        }, {
            'path': raw_config[14],
            'usage': 'logs'
        }],
        'mutex': [raw_config[11]],
        'registry': [{'key': os.path.join(raw_config[5], raw_config[6])}],
        # Capabilities?
        'other': {
            "Install Flag": raw_config[7],
            "StartupFlag": raw_config[8],
            "ActiveXFlag": raw_config[9],
            "HKCU Flag": raw_config[10],
            "userMode Hooking": raw_config[12],
            "Melt": raw_config[13],
            "UnknownFlag9": raw_config[16],
        }
    }


def version_22(raw_config):
    if raw_config is None:
        return None
    return {
        'family': "Pandora",
        'version': "2.2",
        'campaign_id': raw_config[15],
        'tcp': [{
            'server_domain': raw_config[0],
            'server_port': raw_config[1]
        }],
        'password': [raw_config[2]],
        'paths': [{
            'path': os.path.join(raw_config[3], raw_config[4]),
            'usage': 'install'
        }, {
            'path': raw_config[14],
            'usage': 'logs'
        }],
        'mutex': [raw_config[11]],
        'registry': [{'key': os.path.join(raw_config[5], raw_config[6])}],
        # Capabilities?
        'other': {
            "Install Flag": raw_config[7],
            "StartupFlag": raw_config[8],
            "ActiveXFlag": raw_config[9],
            "HKCU Flag": raw_config[10],
            "userMode Hooking": raw_config[12],
            "Melt": raw_config[13],
            "UnknownFlag9": raw_config[16],
        }
    }


def get_config(data):
    try:
        pe = pefile.PE(data=data)
        rt_string_idx = [
            entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(
            pefile.RESOURCE_TYPE["RT_RCDATA"])
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "CFG":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva: data_rva + size]
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
