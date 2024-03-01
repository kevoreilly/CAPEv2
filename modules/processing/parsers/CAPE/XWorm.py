import re
import dnfile
from Cryptodome.Cipher import AES
import hashlib
import base64

pattern = re.compile(
    rb"""(?x)
    \x72(...)\x70\x80...\x04
    """,
    re.DOTALL
)

mutexPattern = re.compile(
    rb"""(?x)
    \x72(...)\x70\x80...\x04
    \x72...\x70\x28...\x0A
    """,
    re.DOTALL
)

def deriveAESKey(encryptedMutex : str):
    md5Hash = hashlib.md5(encryptedMutex.encode()).hexdigest()
    AESKey = md5Hash[:30] + md5Hash + '00'
    return AESKey

def decrypt_aes_ecb(key : str, ciphertext : str):
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    decodedcipher = base64.b64decode(ciphertext)
    decryptedBuff = cipher.decrypt(decodedcipher)

    ## To exclude garbage bytes (i.e. 'http:\\example.com\\\x03\x03\x03'
    valid_bytes = set(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-/,')
    filtered_bytes = bytes(b for b in decryptedBuff if b in valid_bytes).decode('utf-8').split(',')
    if len(filtered_bytes) > 1:
        return filtered_bytes
    return ''.join(filtered_bytes)

def extract_config(data):
    config_dict = {}
    try:
        dn = dnfile.dnPE(data=data)
        extracted = []
        conf = []

        ## Mutex is used to derive AES key, so if it's not found, the extractor is useless
        ## The main problem is Mutex is not found in fixed location, so this trick is used to find the Mutex
        mutexMatched = mutexPattern.findall(data)
        if mutexMatched:
            mutex = dn.net.user_strings.get_us(int.from_bytes(mutexMatched[0], "little")).value
        else:
            return

        for match in pattern.findall(data):
            er_string = dn.net.user_strings.get_us(int.from_bytes(match, "little")).value
            extracted.append(er_string)
        AESKey = deriveAESKey(mutex)

        for i in range(5):
            try:
                conf.append(decrypt_aes_ecb(AESKey, extracted[i]))
            except:
                continue

        config_dict['C2'] = conf[0]
        
        ## Sometimes the port is not found in configs and 'AES Key (decrypt/encrypt connections)' is shifted with SPL'
        if 1 <= int(conf[1]) <= 65535:
            config_dict['Port'] = conf[1]
            config_dict['AES Key (decrypt/encrypt connections)'] = conf[2]
            config_dict['SPL'] = conf[3]
        else:
            config_dict['Port'] = ''
            config_dict['Key'] = conf[1]
            config_dict['SPL'] = conf[2]
        config_dict['AES Key (decrypt configs)'] = AESKey
        config_dict['Mutex'] = mutex

        return config_dict

    except:
        return
