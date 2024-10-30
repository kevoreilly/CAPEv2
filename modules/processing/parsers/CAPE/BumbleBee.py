# Thanks to @MuziSec - https://github.com/MuziSec/malware_scripts/blob/main/bumblebee/extract_config.py
# 2024 updates by @enzok
#
import logging
import traceback
from contextlib import suppress

import pefile
import regex as re
import yara
from Cryptodome.Cipher import ARC4

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)

rule_source = """
rule BumbleBee
{
    meta:
        author = "enzok"
        description = "BumbleBee 2024"
    strings:
        $rc4key = {48 [6] 48 [6] E8 [4] 4C 89 AD [4] 4C 89 AD [4] 4C 89 B5 [4] 4C 89 AD [4] 44 88 AD [4] 48 8D 15 [4] 44 38 2D [4] 75}
        $botidlgt = {4C 8B C1 B? 4F 00 00 00 48 8D 0D [4] E8 [4] 4C 8B C3 48 8D 0D [4] B? 4F 00 00 00 E8 [4] 4C 8B C3 48 8D 0D [4] B? FF 0F 00 00 E8}
        $botid = {90 48 [6] E8 [4] 4C 89 AD [4] 4C 89 AD [4] 4C 89 B5 [4] 4C 89 AD [4] 44 88 AD [4] 48 8D 15 [4] 44 38 2D [4] 75}
        $port = {4C 89 6D ?? 4C 89 6D ?? 4c 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8D 05 [4] 44 38 2D [4] 75}
        $dga1 = {4C 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8B 1D [4] 48 8D 0D [4] E8 [4] 8B F8}
        $dga2 = {48 8D 0D [4] E8 [4] 8B F0 4C 89 6D ?? 4C 89 6D ?? 4C 89 75 ?? 4C 89 6D ?? 44 88 6D ?? 48 8D 15 [4] 44 38 2D [4] 75}
    condition:
        $rc4key and all of ($botid*) and 2 of ($port, $port, $dga1, $dga2)
}
"""

yara_rules = yara.compile(source=rule_source)


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
        return False
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
        return False, False, False

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
        return False, False, False

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
        return False, False, False

    return campaign_id_ct, botnet_id_ct, c2s_ct


def extract_2024(pe, filebuf):
    cfg = {}
    rc4key_init_offset = 0
    botid_init_offset = 0
    port_init_offset = 0
    dga1_init_offset = 0
    dga2_init_offset = 0
    botidlgt_init_offset = 0

    matches = yara_rules.match(data=filebuf)
    if not matches:
        return

    for match in matches:
        if match.rule != "BumbleBee":
            continue
        for item in match.strings:
            for instance in item.instances:
                if "$rc4key" in item.identifier:
                    rc4key_init_offset = int(instance.offset)
                elif "$botidlgt" in item.identifier:
                    botidlgt_init_offset = int(instance.offset)
                elif "$botid" in item.identifier:
                    botid_init_offset = int(instance.offset)
                elif "$port" in item.identifier:
                    port_init_offset = int(instance.offset)
                elif "$dga1" in item.identifier:
                    dga1_init_offset = int(instance.offset)
                elif "$dga2" in item.identifier:
                    dga2_init_offset = int(instance.offset)

    if not rc4key_init_offset:
        return

    key_offset = pe.get_dword_from_offset(rc4key_init_offset + 57)
    key_rva = pe.get_rva_from_offset(rc4key_init_offset + 61) + key_offset
    key = pe.get_string_at_rva(key_rva)
    cfg["RC4 key"] = key.decode()

    botid_offset = pe.get_dword_from_offset(botid_init_offset + 51)
    botid_rva = pe.get_rva_from_offset(botid_init_offset + 55) + botid_offset
    botid_len_offset = pe.get_dword_from_offset(botidlgt_init_offset + 31)
    botid_data = pe.get_data(botid_rva)[:botid_len_offset]
    with suppress(Exception):
        botid = ARC4.new(key).decrypt(botid_data).split(b"\x00")[0].decode()
        cfg["Botid"] = botid

    port_offset = pe.get_dword_from_offset(port_init_offset + 23)
    port_rva = pe.get_rva_from_offset(port_init_offset + 27) + port_offset
    port_len_offset = pe.get_dword_from_offset(botidlgt_init_offset + 4)
    port_data = pe.get_data(port_rva)[:port_len_offset]
    with suppress(Exception):
        port = ARC4.new(key).decrypt(port_data).split(b"\x00")[0].decode()
        cfg["Port"] = port

    dgaseed_offset = pe.get_dword_from_offset(dga1_init_offset + 15)
    dgaseed_rva = pe.get_rva_from_offset(dga1_init_offset + 19) + dgaseed_offset
    dgaseed_data = pe.get_qword_at_rva(dgaseed_rva)
    cfg["DGA seed"] = int(dgaseed_data)

    numdga_offset = pe.get_dword_from_offset(dga1_init_offset + 22)
    numdga_rva = pe.get_rva_from_offset(dga1_init_offset + 26) + numdga_offset
    numdga_data = pe.get_string_at_rva(numdga_rva)
    cfg["Number DGA domains"] = numdga_data.decode()

    domainlen_offset = pe.get_dword_from_offset(dga2_init_offset + 3)
    domainlen_rva = pe.get_rva_from_offset(dga2_init_offset + 7) + domainlen_offset
    domainlen_data = pe.get_string_at_rva(domainlen_rva)
    cfg["Domain length"] = domainlen_data.decode()

    tld_offset = pe.get_dword_from_offset(dga2_init_offset + 37)
    tld_rva = pe.get_rva_from_offset(dga2_init_offset + 41) + tld_offset
    tld_data = pe.get_string_at_rva(tld_rva).decode()
    cfg["TLD"] = tld_data

    return cfg


def extract_config(data):
    """
    Extract key and config and decrypt
    """
    cfg = {}
    pe = None
    try:
        with suppress(Exception):
            pe = pefile.PE(data=data, fast_load=True)

        if not pe:
            return cfg

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
                if not key:
                    continue
                if index == 0:
                    cfg["Botnet ID"] = key.decode()
                elif index == 1:
                    cfg["Campaign ID"] = key.decode()
                elif index == 2:
                    cfg["Data"] = key.decode("latin-1")
                elif index == 3:
                    cfg["C2s"] = list(key.decode().split(","))
        elif len(key_match) == 1:
            key = extract_key_data(data, pe, key_match[0])
            if not key:
                return cfg
            cfg["RC4 Key"] = key.decode()
        # Extract config ciphertext
        config_match = regex.search(data)
        campaign_id, botnet_id, c2s = extract_config_data(data, pe, config_match)
        if campaign_id:
            cfg["Campaign ID"] = ARC4.new(key).decrypt(campaign_id).split(b"\x00")[0].decode()
        if botnet_id:
            cfg["Botnet ID"] = ARC4.new(key).decrypt(botnet_id).split(b"\x00")[0].decode()
        if c2s:
            cfg["C2s"] = list(ARC4.new(key).decrypt(c2s).split(b"\x00")[0].decode().split(","))
    except Exception as e:
        log.error("This is broken: %s", str(e), exc_info=True)

    if not cfg:
        cfg = extract_2024(pe, data)

    return cfg


if __name__ == "__main__":
    import sys

    print(extract_config(open(sys.argv[1], "rb").read()))
