import hashlib
import re
from base64 import b64decode

import pefile
from Cryptodome.Cipher import AES, XOR


def string_print(line):
    return "".join((char for char in line if 32 < ord(char) < 127))


def parse_config(config_list, ver):
    config_dict = {}
    if ver == "V1":
        config_dict["Version"] = "1.0.x"
        config_dict["Domain"] = config_list[1]
        config_dict["Port"] = config_list[2]
        config_dict["Password"] = config_list[3]
        config_dict["CampaignID"] = config_list[4]
        config_dict["InstallName"] = config_list[5]
        config_dict["HKCUKey"] = config_list[6]
        config_dict["InstallDir"] = config_list[7]
        config_dict["Flag1"] = config_list[8]
        config_dict["Flag2"] = config_list[9]
        config_dict["Mutex"] = config_list[10]
    if ver == "V2":
        config_dict["Version"] = config_list[0]
        config_dict["Domain"] = config_list[1]
        config_dict["Password"] = config_list[2]
        config_dict["InstallSub"] = config_list[3]
        config_dict["InstallName"] = config_list[4]
        config_dict["Mutex"] = config_list[5]
        config_dict["RegistryKey"] = config_list[6]
    return config_dict


def get_long_line(data):
    try:
        raw_config = None
        pe = pefile.PE(data=data)
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if str(entry.name) == "RT_RCDATA":
                new_dirs = entry.directory
                for entry in new_dirs.entries:
                    if str(entry.name) == "0":
                        data_rva = entry.directory.entries[0].data.struct.OffsetToData
                        size = entry.directory.entries[0].data.struct.Size
                        data = pe.get_memory_mapped_image()[data_rva : data_rva + size]
                        raw_config = data
    except Exception:
        raw_config = None
    if raw_config is not None:
        return raw_config, "V1"
    try:
        m = re.search("\x69\x00\x6F\x00\x6E\x00\x00\x59(.*)\x6F\x43\x00\x61\x00\x6E", data)
        raw_config = m.group(0)[4:-12]
        return raw_config, "V2"
    except Exception:
        return None, None


def decrypt_XOR(enckey, data):
    cipher = XOR.new(enckey)  # set the cipher
    return cipher.decrypt(data)  # decrpyt the data


# decrypt function
def decrypt_aes(enckey, data):
    iv = data[:16]
    cipher = AES.new(enckey, AES.MODE_CBC, iv)  # set the cipher
    return cipher.decrypt(data[16:])  # decrpyt the data


# converts the enc key to an md5 key
def aes_key(enc_key):
    return hashlib.md5(enc_key).hexdigest().decode("hex")


# This will split all the b64 encoded strings and the encryption key
def get_parts(long_line):
    coded_config = []
    raw_line = long_line
    small_lines = raw_line.split("\x00\x00")
    for line in small_lines:
        new_line = line[1:] if len(line) % 2 == 0 else line[2:]
        coded_config.append(new_line.replace("\x00", ""))
    return coded_config


def extract_config(data):
    long_line, ver = get_long_line(data)
    if ver is None:
        return
    config_list = []
    if ver == "V1":
        # The way the XOR Cypher was implemented the keys are off by 1.
        key1 = "RAT11x"  # Used for First level of encryption actual key is 'xRAT11'
        key2 = "eY11K"  # used for individual sections, actual key is 'KeY11'
        key3 = "eY11PWD24K"  # used for password section only. Actual key is 'KeY11PWD24'
        config = long_line.decode("hex")
        first_decode = decrypt_XOR(key1, config)
        sections = first_decode.split("|//\\\\|")  # Split is |//\\| the extra \\ are for escaping.
        for i, section in enumerate(sections):
            enc_key = key3 if i == 3 else key2
            config_list.append(decrypt_XOR(enc_key, section.decode("hex")))
    elif ver == "V2":
        coded_lines = get_parts(long_line)
        enc_key = aes_key(coded_lines[-1])
        for i in range(1, (len(coded_lines) - 1)):
            decoded_line = b64decode(coded_lines[i])
            decrypt_line = decrypt_aes(enc_key, decoded_line)
            config_list.append(string_print(decrypt_line))
    return parse_config(config_list, ver)
