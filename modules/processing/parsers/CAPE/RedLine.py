# Thanks to Gi7w0rm
# https://github.com/kevthehermit/RATDecoders/blob/master/malwareconfig/decoders/RedLine.py

import base64
import logging
import re
from contextlib import suppress

from lib.cuckoo.common.dotnet_utils import dotnet_user_strings
from lib.cuckoo.common.integrations.strings import extract_strings

try:
    import dnfile

    HAVE_DNFILE = True
except ImportError:
    HAVE_DNFILE = False

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


def decrypt(str_to_dec, Key):
    dec_xor = ""
    first_dec = base64.b64decode(str_to_dec)
    len_first_dec = len(first_dec)
    for i in range(len_first_dec):
        Key = Key + str(Key[i % len(Key)])
    a_list = [chr(ord(chr(a)) ^ ord(b)) for a, b in zip(first_dec, Key)]
    dec_xor = "".join(a_list)
    third_dec = base64.b64decode(dec_xor)
    tocut = str(third_dec)
    cut = tocut[2:-1]
    return cut


def extract_config(data):
    config_dict = {}

    pattern = re.compile(
        Rb"""(?x)
    \x02\x72(...)\x70\x7D...\x04
    \x02\x72(...)\x70\x7D...\x04
    \x02\x72(...)\x70\x7D...\x04
    \x02\x72(...)\x70\x7D...\x04
    """
    )

    pattern2 = re.compile(
        Rb"""(?x)
    \x72(...)\x70\x0A
    \x72(...)\x70\x0B
    \x72(...)\x70\x0C
    \x72(...)\x70\x0D
    """
    )

    pattern3 = re.compile(
        Rb"""(?x)
    \x02\x72(...)\x70\x7D...\x04
    \x02\x72(...)\x70\x7D...\x04
    """
    )

    pattern4 = re.compile(
        Rb"""(?x)
    \x02\x28...\x0A
    \x02\x72(...)\x70\x7D...\x04
    \x02\x72(...)\x70\x7D...\x04
    """
    )

    pattern5 = re.compile(
        Rb"""(?x)
    \x72(...)\x70\x80...\x04
    \x72(...)\x70\x80...\x04
    \x72(...)\x70\x80...\x04
    \x72(...)\x70\x80...\x04
    """
    )

    patterns = [pattern, pattern2, pattern3, pattern4, pattern5]
    key = c2 = botnet = base_location = None

    user_strings = extract_strings(data=data, on_demand=True)
    if not user_strings:
        user_strings = dotnet_user_strings(data=data)
    if not user_strings:
        return

    with suppress(Exception):
        base_location = user_strings.index("Yandex\\YaAddon")
        if base_location:
            # newer samples
            with suppress(Exception):
                key = user_strings[base_location - 1]
                c2 = decrypt(user_strings[base_location - 3], key)
                if not c2 or "." not in c2:
                    c2 = decrypt(user_strings[base_location - 4], key)
                    botnet = decrypt(user_strings[base_location - 3], key)
                else:
                    botnet = decrypt(user_strings[base_location - 2], key)

            # older samples
            if not c2 or "." not in c2:
                with suppress(Exception):
                    key = user_strings[base_location + 3]
                    c2 = decrypt(user_strings[base_location + 1], key)
                    botnet = decrypt(user_strings[base_location + 2], key)

    base_location = None
    with suppress(Exception):
        if "Authorization" in user_strings:
            base_location = user_strings.index("Authorization")
            if base_location:
                if not c2 or "." not in c2:
                    delta = base_location
                    while True:
                        delta += 1
                        if "==" in user_strings[delta]:
                            c2 = user_strings[delta]
                            if "=" in user_strings[delta + 1]:
                                botnet = user_strings[delta + 1]
                                key = user_strings[delta + 2]
                                if "=" in key:
                                    key = user_strings[delta + 3]
                            else:
                                botnet = None
                                key = user_strings[delta + 1]
                            c2 = decrypt(c2, key)
                            if botnet:
                                botnet = decrypt(botnet, key)
                            break

    if not c2 or "." not in c2 and HAVE_DNFILE:
        with suppress(Exception):
            dn = dnfile.dnPE(data=data)
            for p in patterns:
                extracted = []
                for match in p.findall(data):
                    for item in match:
                        user_string = dn.net.user_strings.get_us(int.from_bytes(item, "little")).value
                        if user_string:
                            extracted.append(user_string)
                if extracted:
                    key = extracted[2]
                    c2 = decrypt(extracted[0], key)
                    botnet = decrypt(extracted[1], key)
                    if "." in c2:
                        break
            dn.close()

    if not c2 or "." not in c2:
        return

    config_dict = {"C2": c2, "Botnet": botnet, "Key": key}
    base_location = user_strings.index("Authorization")
    if base_location:
        config_dict["Authorization"] = user_strings[base_location - 1]

    return config_dict
