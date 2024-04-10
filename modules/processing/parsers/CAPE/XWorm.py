import base64
import hashlib
import re
from contextlib import suppress

import dnfile
from Cryptodome.Cipher import AES

confPattern = re.compile(
    rb"""(?x)
    \x72(...)\x70\x80...\x04
    """,
    re.DOTALL,
)

mutexPattern1 = re.compile(
    rb"""(?x)
    \x72(...)\x70\x80...\x04
    \x72...\x70\x28...\x0A
    """,
    re.DOTALL,
)

mutexPattern2 = re.compile(
    rb"""(?x)
    \x72(...)\x70\x80...\x04\x2A
    """,
    re.DOTALL,
)

installBinNamePattern = re.compile(
    rb"""(?x)
    \x72(...)\x70\x80...\x04
    \x72...\x70\x80...\x04
    \x72...\x70\x28...\x0A
    """,
    re.DOTALL,
)

installDirPattern = re.compile(
    rb"""(?x)
    \x72(...)\x70\x80...\x04
    \x72...\x70\x80...\x04
    \x72...\x70\x80...\x04
    \x72...\x70\x28...\x0A
    """,
    re.DOTALL,
)

mutexPatterns = [mutexPattern1, mutexPattern2]


def deriveAESKey(encryptedMutex: str):
    md5Hash = hashlib.md5(encryptedMutex.encode()).hexdigest()
    AESKey = md5Hash[:30] + md5Hash + "00"
    return AESKey


def decryptAES(key: str, ciphertext: str, mode):
    cipher = AES.new(bytes.fromhex(key), mode)
    decodedcipher = base64.b64decode(ciphertext)
    decryptedBuff = cipher.decrypt(decodedcipher)

    ## To exclude garbage bytes (i.e. 'http:\\example.com\\\x03\x03\x03')
    valid_bytes = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/,")

    ## C2 could be one or more delimited by ','
    filtered_bytes = bytes(b for b in decryptedBuff if b in valid_bytes).decode("utf-8").split(",")
    if len(filtered_bytes) > 1:
        return filtered_bytes
    return "".join(filtered_bytes)


def extract_config(data):
    config_dict = {}
    with suppress(Exception):
        if data[:2] == b"MZ":
            dn = dnfile.dnPE(data=data)
            extracted = []
            conf = []

            ## Mutex is used to derive AES key, so if it's not found, the extractor is useless
            ## The main problem is Mutex is not found in fixed location, so this trick is used to find the Mutex
            for pattern in mutexPatterns:
                mutexMatched = pattern.findall(data)
                if mutexMatched:
                    mutex = dn.net.user_strings.get_us(int.from_bytes(mutexMatched[0], "little")).value
                    AESKey = deriveAESKey(mutex)
                    break
                else:
                    return

            for match in confPattern.findall(data):
                er_string = dn.net.user_strings.get_us(int.from_bytes(match, "little")).value
                extracted.append(er_string)

            for i in range(5):
                with suppress(Exception):
                    conf.append(decryptAES(AESKey, extracted[i], AES.MODE_ECB))

            config_dict["C2"] = conf[0]

            ## Sometimes the port is not found in configs and 'AES Key (connections)' is shifted with SPL'
            if 1 <= int(conf[1]) <= 65535:
                config_dict["Port"] = conf[1]
                config_dict["AES Key (connections)"] = conf[2]
                config_dict["SPL"] = conf[3]
            else:
                config_dict["Port"] = ""
                config_dict["AES Key (connections)"] = conf[1]
                config_dict["SPL"] = conf[2]
            config_dict["AES Key (configs)"] = AESKey
            config_dict["Mutex"] = mutex

            installBinMatch = installBinNamePattern.findall(data)
            installDirMatch = installDirPattern.findall(data)

            if installDirMatch:
                installDir = dn.net.user_strings.get_us(int.from_bytes(installDirMatch[0], "little")).value
                config_dict["InstallDir"] = decryptAES(AESKey, installDir, AES.MODE_ECB)
            if installBinMatch:
                installBinName = dn.net.user_strings.get_us(int.from_bytes(installBinMatch[0], "little")).value
                config_dict["InstallBinName"] = decryptAES(AESKey, installBinName, AES.MODE_ECB)
        else:
            lines = data.decode().split("\n")
            if "," in lines[0]:
                c2_list = lines[0].split(",")
                config_dict["C2s"] = c2_list
            else:
                config_dict["C2"] = lines[0]
            config_dict["Port"] = lines[1]
            config_dict["AES Key (connections)"] = lines[2]
            config_dict["SPL"] = lines[3]
            config_dict["USBNM"] = lines[4]

        return config_dict
