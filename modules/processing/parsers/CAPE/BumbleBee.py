# Thanks to @MuziSec - https://github.com/MuziSec/malware_scripts/blob/main/bumblebee/extract_config.py
#
import logging
import os
import traceback
from binascii import hexlify, unhexlify

import pefile
import regex as re
from Cryptodome.Cipher import ARC4

log = logging.getLogger()
log.setLevel(logging.INFO)


def rc4_decrypt(key, ciphertext):
    """
    RC4 Decrypt Ciphertext
    """
    arc4 = ARC4.new(key)
    return arc4.decrypt(ciphertext)


def extract_key_data(data, pe, key_match):
    """
    Given key match, convert rva to file offset and return key data at that offset.
    """
    try:
        # Get relative rva. The LEA is using a relative address. This address is relative to the address of the next ins.
        relative_rva = pe.get_rva_from_offset(key_match.start() + int(len(key_match.group()) / 2))
        # Now that we have the relative rva, we need to get the file offset
        key_offset = pe.get_offset_from_rva(relative_rva + int.from_bytes(key_match.group("key"), byteorder="little"))
        # Read arbitrary number of byes from key offset and split on null bytes to extract key
        key = data[key_offset : key_offset + 0x40].split(b"\x00")[0]
    except Exception as e:
        log.debug(f"There was an exception extracting the key: {e}")
        log.debug(traceback.format_exc())
        raise
    return key


def extract_config_data(data, pe, config_match):
    """
    Given config match, convert rva to file offset and return data at that offset.
    The LEA ins are using relative addressing. Referenced data is relative to the address of the NEXT ins.
    This is inefficient but I'm bad at Python, okay?
    """
    try:
        # Get campaign id ciphertext
        campaign_id_rva = pe.get_rva_from_offset(config_match.start() + int(len(config_match.group("campaign_id_ins"))))
        campaign_id_offset = pe.get_offset_from_rva(
            campaign_id_rva + int.from_bytes(config_match.group("campaign_id"), byteorder="little")
        )
        campaign_id_ct = data[campaign_id_offset : campaign_id_offset + 0x10]
    except Exception as e:
        log.debug(f"There was an exception extracting the campaign id: {e}")
        log.debug(traceback.format_exc())
        raise

    try:
        # Get botnet id ciphertext
        botnet_id_rva = pe.get_rva_from_offset(
            config_match.start() + int(len(config_match.group("campaign_id_ins"))) + int(len(config_match.group("botnet_id_ins")))
        )
        botnet_id_offset = pe.get_offset_from_rva(
            botnet_id_rva + int.from_bytes(config_match.group("botnet_id"), byteorder="little")
        )
        botnet_id_ct = data[botnet_id_offset : botnet_id_offset + 0x10]
    except Exception as e:
        log.debug(f"There was an exception extracting the botnet id: {e}")
        log.debug(traceback.format_exc())
        raise

    # Get C2 ciphertext
    try:
        c2s_rva = pe.get_rva_from_offset(
            config_match.start()
            + int(len(config_match.group("campaign_id_ins")))
            + int(len(config_match.group("botnet_id_ins")))
            + int(len(config_match.group("c2s_ins")))
        )
        c2s_offset = pe.get_offset_from_rva(c2s_rva + int.from_bytes(config_match.group("c2s"), byteorder="little"))
        c2s_ct = data[c2s_offset : c2s_offset + 0x400]
    except Exception as e:
        log.debug(f"There was an exception extracting the C2s: {e}")
        log.debug(traceback.format_exc())
        raise

    return campaign_id_ct, botnet_id_ct, c2s_ct


def extract_config(data):
    """
    Extract key and config and decrypt
    """

    cfg = {}
    pe = None
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception:
        pass
    if pe is None:
        return

    key_regex = re.compile(rb"(\x48\x8D.(?P<key>....)\x80\x3D....\x00)", re.DOTALL)
    regex = re.compile(
        rb"(?<campaign_id_ins>\x48\x8D.(?P<campaign_id>....))(?P<botnet_id_ins>\x48\x8D.(?P<botnet_id>....))(?P<c2s_ins>\x48\x8D.(?P<c2s>....))",
        re.DOTALL,
    )
    # Extract Key
    key_match = list(key_regex.finditer(data))
    if len(key_match) > 1:
        for index, match in enumerate(key_match):
            key = extract_key_data(data, pe, match)
            if index == 0:
                cfg["Botnet ID"] = key.decode()
            elif index == 1:
                cfg["Campaign ID"] = key.decode()
            elif index == 2:
                cfg["Data"] = key.decode()
            elif index == 3:
                cfg["C2s"] = list(key.decode().split(","))
                exit(0)
    elif len(key_match) == 1:
        key = extract_key_data(data, pe, key_match[0])
        cfg["RC4 Key"] = key.decode()

    # Extract config ciphertext
    config_match = regex.search(data)
    campaign_id, botnet_id, c2s = extract_config_data(data, pe, config_match)

    # RC4 Decrypt
    cfg["Campaign ID"] = rc4_decrypt(key, campaign_id).split(b"\x00")[0].decode()
    cfg["Botnet ID"] = rc4_decrypt(key, botnet_id).split(b"\x00")[0].decode()
    cfg["C2s"] = list(rc4_decrypt(key, c2s).split(b"\x00")[0].decode().split(","))

    return cfg
