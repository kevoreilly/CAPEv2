from base64 import b64decode
from binascii import unhexlify

# import pefile
import pype32
from Cryptodome.Cipher import AES
from pbkdf2 import PBKDF2


def extract_config(raw_data):
    try:
        pe = pype32.PE(data=raw_data)
        # pe = pefile.PE(data=raw_data)
        string_list = get_strings(pe, 2)
        vers = get_version(string_list)
        if vers == "v12":
            config_dict = config_12(string_list)
        elif vers == "v13":
            key, salt = "PredatorLogger", unhexlify("3000390039007500370038003700390037003800370038003600")
            config_dict = config_13(key, salt, string_list)
        elif vers == "v14":
            key, salt = "EncryptedCredentials", unhexlify("3000390039007500370038003700390037003800370038003600")
            config_dict = config_14(key, salt, string_list)
        else:
            return False
        # C2 Line is not a straight domain on this one.

        return config_dict or False
    except Exception as e:
        print("PREDATORPAIN EXTRACTOR", e)
        return False


# Helper Functions Go Here


def string_clean(line):
    return "".join((char for char in line if 32 < ord(char) < 127))


# Cryptodome.Stuffs
def decrypt_string(key, salt, coded):
    # try:
    # Derive key
    generator = PBKDF2(key, salt)
    aes_iv = generator.read(16)
    aes_key = generator.read(32)
    # Crypto
    mode = AES.MODE_CBC
    cipher = AES.new(aes_key, mode, IV=aes_iv)
    return cipher.decrypt(b64decode(coded)).replace("\x00", "")


# except Exception:
# return False


# Get a list of strings from a section
def get_strings(pe, dir_type):
    string_list = []
    m = pe.ntHeaders.optionalHeader.DATA_DIRECTORY[14].info
    # m = pe.NT_HEADERS.OPTIONAL_HEADER.DATA_DIRECTORY[14].dump_dict().get("VirtualAddress", {})
    for s in m.netMetaDataStreams[dir_type].info:
        string_list.extend(s.values())
    return string_list


# Find Version
def get_version(string_list):
    # Pred v12
    if "Predator Pain v12 - Server Ran - [" in string_list:
        print("    [-] Found Predator Pain v12")
        return "v12"
    # Pred v13
    elif "Predator Pain v13 - Server Ran - [" in string_list:
        print("    [-] Found Predator Pain v13")
        return "v13"
    # Pred v14
    elif "EncryptedCredentials" in string_list:
        print("    [-] Found Predator Pain v14")
        return "v14"


def config_12(string_list):
    config_dict = {
        "Version": "Predator Pain v12",
        "Email Address": string_list[4],
        "Email Password": string_list[5],
        "SMTP Server": string_list[6],
        "SMTP Port": string_list[7],
        "Interval Timer": string_list[8],
        "BindFile1": "False" if string_list[9].startswith("ReplaceBind") else "True",
    }

    config_dict["BindFile2"] = "False" if string_list[10].startswith("ReplaceBind") else "True"
    return config_dict


# Turn the strings in to a python config_dict
def config_13(key, salt, string_list):
    """
    Identical Strings are not stored multiple times.
    We need to check for duplicate passwords which mess up the positionl arguemnts.
    """

    if "email" in string_list[13]:
        dup = True
    elif "email" in string_list[14]:
        dup = False

    config_dict = {
        "Version": "Predator Pain v13",
        "Email Address": decrypt_string(key, salt, string_list[4]),
        "Email Password": decrypt_string(key, salt, string_list[5]),
        "SMTP Server": decrypt_string(key, salt, string_list[6]),
        "SMTP Port": string_list[7],
        "Interval Timer": string_list[8],
        "FTP Host": decrypt_string(key, salt, string_list[10]),
        "FTP User": decrypt_string(key, salt, string_list[11]),
    }
    if dup:
        config_dict["FTP Pass"] = decrypt_string(key, salt, string_list[5])
        config_dict["PHP Link"] = decrypt_string(key, salt, string_list[12])
        config_dict["Use Email"] = string_list[13]
        config_dict["Use FTP"] = string_list[14]
        config_dict["Use PHP"] = string_list[15]
        config_dict["Download & Exec"] = string_list[20]
        config_dict["Bound Files"] = "False" if string_list[19] == "bindfiles" else "True"
    else:
        config_dict["FTP Pass"] = decrypt_string(key, salt, string_list[12])
        config_dict["PHP Link"] = decrypt_string(key, salt, string_list[13])
        config_dict["Use Email"] = string_list[14]
        config_dict["Use FTP"] = string_list[15]
        config_dict["Use PHP"] = string_list[16]
        config_dict["Download & Exec"] = string_list[21]
        config_dict["Bound Files"] = "False" if string_list[20] == "bindfiles" else True
    return config_dict


# Turn the strings in to a python config_dict
def config_14(key, salt, string_list):
    """
    Identical Strings are not stored multiple times.
    possible pass and date dupes make it harder to test
    """

    # date Duplicate
    if "email" in string_list[18]:
        dup = True
    elif "email" in string_list[19]:
        dup = False

    config_dict = {
        "Version": "Predator Pain v14",
        "Email Address": decrypt_string(key, salt, string_list[4]),
        "Email Password": decrypt_string(key, salt, string_list[5]),
        "SMTP Server": decrypt_string(key, salt, string_list[6]),
        "SMTP Port": string_list[7],
        "Interval Timer": string_list[8],
        "FTP Host": decrypt_string(key, salt, string_list[12]),
        "FTP User": decrypt_string(key, salt, string_list[13]),
        "FTP Pass": decrypt_string(key, salt, string_list[14]),
        "PHP Link": decrypt_string(key, salt, string_list[15]),
    }
    if dup:
        config_dict["PHP Link"] = decrypt_string(key, salt, string_list[15])
        config_dict["Use Email"] = string_list[18]
        config_dict["Use FTP"] = string_list[19]
        config_dict["Use PHP"] = string_list[20]
        config_dict["Download & Exec"] = string_list[25]
        config_dict["Bound Files"] = "False" if string_list[24] == "bindfiles" else "True"
    else:
        config_dict["Use Email"] = string_list[19]
        config_dict["Use FTP"] = string_list[20]
        config_dict["Use PHP"] = string_list[21]
        config_dict["Download & Exec"] = string_list[26]
        config_dict["Bound Files"] = "False" if string_list[25] == "bindfiles" else "True"
    return config_dict
