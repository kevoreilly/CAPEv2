# Thanks to Gi7w0rm
# https://github.com/kevthehermit/RATDecoders/blob/master/malwareconfig/decoders/RedLine.py

import base64
from contextlib import suppress
from lib.cuckoo.common.dotnet_utils import dotnet_user_strings
from lib.cuckoo.common.integrations.strings import extract_strings

import logging
log = logging.getLogger()
log.setLevel(logging.INFO)


def decrypt(str_to_dec, Key):
    dec_xor = ""
    first_dec = base64.b64decode(str_to_dec)
    len_first_dec = len(first_dec)
    for i in range(len_first_dec):
        Key = Key + str(Key[i % len(Key)])
    a_list = [chr(ord(chr(a)) ^ ord(b)) for a,b in zip(first_dec, Key)]
    dec_xor = "".join(a_list)
    third_dec = base64.b64decode(dec_xor)
    tocut = str(third_dec)
    cut = tocut[2:-1]
    return cut


def extract_config(filebuf):
    config_dict = {}
    user_strings = dotnet_user_strings(data=filebuf)
    if not user_strings:
        user_strings = extract_strings(data=filebuf)
    if not user_strings:
        return

    base_location = None
    with suppress(Exception):
        base_location = user_strings.index("Yandex\\YaAddon")

    if base_location is None:
        return

    key = c2 = botnet = None

    # newer samples
    if c2 is None:
        with suppress(Exception):
            key = user_strings[base_location-1]
            c2 = decrypt(user_strings[base_location-3], key)
            if '.' in c2:
                botnet = decrypt(user_strings[base_location-2], key)
            else:
                c2 = decrypt(user_strings[base_location-4], key)
                botnet = decrypt(user_strings[base_location-3], key)

    # older samples
    if c2 is None:
        with suppress(Exception):
            key = user_strings[base_location+3]
            c2 = decrypt(user_strings[base_location+1], key)
            botnet = decrypt(user_strings[base_location+2], key)

    if not c2 or '.' not in c2:
        return

    config_dict = {'C2': c2, 'Botnet': botnet, 'Key': key}

    base_location = None
    with suppress(Exception):
        base_location = user_strings.index("Authorization")
    if base_location:
        config_dict['Authorization'] = user_strings[base_location-1]

    return config_dict
