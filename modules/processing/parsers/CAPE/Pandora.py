from __future__ import absolute_import
import pefile


def version_21(raw_config):
    if raw_config != None:
        conf_dict = {}
        conf_dict["Version"] = "2.1"
        conf_dict["Domain"] = raw_config[0]
        conf_dict["Port"] = raw_config[1]
        conf_dict["Password"] = raw_config[2]
        conf_dict["Install Path"] = raw_config[3]
        conf_dict["Install Name"] = raw_config[4]
        conf_dict["HKCU Key"] = raw_config[5]
        conf_dict["ActiveX Key"] = raw_config[6]
        conf_dict["Install Flag"] = raw_config[7]
        conf_dict["StartupFlag"] = raw_config[8]
        conf_dict["ActiveXFlag"] = raw_config[9]
        conf_dict["HKCU Flag"] = raw_config[10]
        conf_dict["Mutex"] = raw_config[11]
        conf_dict["userMode Hooking"] = raw_config[12]
        conf_dict["Melt"] = raw_config[13]
        conf_dict["Melt"] = raw_config[13]
        conf_dict["Keylogger"] = raw_config[14]
        conf_dict["Campaign ID"] = raw_config[15]
        conf_dict["UnknownFlag9"] = raw_config[16]
        return conf_dict
    else:
        return None


def version_22(raw_config):
    if raw_config != None:
        conf_dict = {}
        conf_dict["Version"] = "2.2"
        conf_dict["Domain"] = raw_config[0]
        conf_dict["Port"] = raw_config[1]
        conf_dict["Password"] = raw_config[2]
        conf_dict["Install Path"] = raw_config[3]
        conf_dict["Install Name"] = raw_config[4]
        conf_dict["HKCU Key"] = raw_config[5]
        conf_dict["ActiveX Key"] = raw_config[6]
        conf_dict["Install Flag"] = raw_config[7]
        conf_dict["StartupFlag"] = raw_config[8]
        conf_dict["ActiveXFlag"] = raw_config[9]
        conf_dict["HKCU Flag"] = raw_config[10]
        conf_dict["Mutex"] = raw_config[11]
        conf_dict["userMode Hooking"] = raw_config[12]
        conf_dict["Melt"] = raw_config[13]
        conf_dict["Melt"] = raw_config[13]
        conf_dict["Keylogger"] = raw_config[14]
        conf_dict["Campaign ID"] = raw_config[15]
        conf_dict["UnknownFlag9"] = raw_config[16]
        return conf_dict
    else:
        return None


def get_config(data):
    try:
        pe = pefile.PE(data=data)
        try:
            rt_string_idx = [entry.id for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries].index(pefile.RESOURCE_TYPE["RT_RCDATA"])
        except ValueError as e:
            return
        except AttributeError as e:
            return
        rt_string_directory = pe.DIRECTORY_ENTRY_RESOURCE.entries[rt_string_idx]
        for entry in rt_string_directory.directory.entries:
            if str(entry.name) == "CFG":
                data_rva = entry.directory.entries[0].data.struct.OffsetToData
                size = entry.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                cleaned = data.replace("\x00", "")
                raw_config = cleaned.split("##")
                return raw_config
    except:
        return


def config(data):
    raw_config = get_config(data)
    if raw_config:
        if len(raw_config) == 19:
            clean_config = version_21(raw_config)
        if len(raw_config) == 20:
            clean_config = version_22(raw_config)
        return clean_config
