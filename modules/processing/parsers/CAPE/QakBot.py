"""
    Qakbot decoder for Core/Main DLL
"""

DESCRIPTION = "Qakbot configuration parser."
AUTHOR = "threathive, r1n9w0rm"

import datetime
import hashlib
import ipaddress
import logging
import socket
import struct
from contextlib import suppress

import pefile
import yara
from Cryptodome.Cipher import AES, ARC4
from Cryptodome.Hash import SHA256
from Cryptodome.Util.Padding import unpad

try:
    HAVE_BLZPACK = True
    from lib.cuckoo.common import blzpack
except OSError as e:
    print(f"Problem to import blzpack: {e}")
    HAVE_BLZPACK = False

log = logging.getLogger(__name__)

rule_source = """
rule QakBot5
{
    meta:
        author = "kevoreilly, enzok"
        description = "QakBot v5 Payload"
        cape_type = "QakBot Payload"
        packed = "f4bb0089dcf3629b1570fda839ef2f06c29cbf846c5134755d22d419015c8bd2"
        hash = "59559e97962e40a15adb2237c4d01cfead03623aff1725616caeaa5a8d273a35"
    strings:
        $loop = {8B 75 ?? 48 8B 4C [2] FF 15 [4] 48 8B 4C [2] 48 8B 01 FF 50 ?? 8B DE 48 8B 4C [2] 48 85 C9 0F 85 [4] EB 4E}
        $c2list = {0F B7 1D [4] B? [2] 00 00 E8 [4] 8B D3 4? 89 45 ?? 4? 33 C9 4? 8D 0D [4] 4? 8B C0 4? 8B F8 E8}
        $campaign = {0F B7 1D [4] B? [2] 00 00 E8 [4] 8B D3 4? 89 44 24 ?? 4? 33 C9 4? 8D 0D [4] 4? 8B C0 4? 8B F8 E8}
        $decrypt_str = {89 4C 24 ?? 4? 8D 05 [3] 00 C7 44 24 [5] 4? 8D 0D [3] 00 4? B? [4] 4? 89 44 24 ?? 4? 8D 05 [3] 00 B? [4] E8 [3] 00 4? 83 C4}
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

"""

yara_rules = yara.compile(source=rule_source)

"""
    Config Map
"""
CONFIG = {
    b"2": "Install timestamp",
    b"3": "Exe timestamp",
    b"7": "CC main interval current",
    b"10": "Bot group",
    b"11": "Install type",
    b"14": "Cron cache",
    b"39": "External IP",
    b"40": "Worm disabled",
    b"45": "Current CC server",
    b"46": "Current CC port",
    b"48": "CC main start delay",
    b"49": "Sysinfo sent OK",
    b"54": "Stager 1 path",
    b"55": "Bot start timestamp",
    b"58": "Stager 1 PID",
}

BRIEFLZ_HEADER = b"\x62\x6C\x7A\x1A\x00\x00\x00\x01"
QAKBOT_HEADER = b"\x61\x6c\xd3\x1a\x00\x00\x00\x01"


def parse_build(pe):
    """
    Extract build version from parent of core dll.
    """
    for sec in pe.sections:
        if sec.Name == b".data\x00\x00\x00":
            major, minor = struct.unpack("<II", sec.get_data()[:8])
            return b"%X.%d" % (major, minor)


def parse_config(data):
    """
    Parses the config block into a more human readable format.
    Data looks like this initially b'3=1592498872'
    """
    config = {}
    config_entries = list(filter(None, data.split(b"\r\n")))

    for entry in config_entries:
        try:
            k, v = entry.rsplit(b"=", 1)
            if k == b"3":
                config[CONFIG.get(k, k.decode())] = datetime.datetime.fromtimestamp(int(v)).strftime("%H:%M:%S %d-%m-%Y")
            else:
                k = k[-2:]
                k
        except Exception:
            log.info("Failed to parse config entry: %s", entry)

    return config


def parse_controllers(data):
    """
    Parses the CNC block into a more human readable format.
    Data looks like this initially 72.29.181.77;0;2078\r\n'
    """
    controllers = []
    for controller in list(filter(None, data.split(b"\r\n"))):
        ip, _, port = controller.decode().split(";")
        controllers.append(f"{ip}:{port}")

    return controllers


def parse_binary_c2(data):
    """
    Parses the binary CNC block format introduced Nov'20
    """
    length = len(data)
    controllers = []
    if len(data) % 7 == 0:
        alignment = 7
    elif len(data) % 8 == 0:
        alignment = 8

    if not alignment:
        return controllers

    for c2_offset in range(0, length, alignment):
        ip = socket.inet_ntoa(struct.pack("!L", struct.unpack(">I", data[c2_offset + 1 : c2_offset + 5])[0]))
        port = str(struct.unpack(">H", data[c2_offset + 5 : c2_offset + 7])[0])
        controllers.append(f"{ip}:{port}")
    return controllers


def parse_binary_c2_2(data):
    """
    Parses the binary CNC block format introduced April'21
    """
    expected_sha1 = data[:0x14]
    data = data[0x14:]
    actual_sha1 = hashlib.sha1(data).digest()

    if actual_sha1 != expected_sha1:
        log.error("Expected sha1: %s actual: %s", expected_sha1, actual_sha1)
        return

    length = len(data)

    controllers = []
    alignment = 0
    if len(data) % 7 == 0:
        alignment = 7
    elif len(data) % 8 == 0:
        alignment = 8

    if not alignment:
        return controllers

    for c2_offset in range(0, length, alignment):
        ip = socket.inet_ntoa(struct.pack("!L", struct.unpack(">I", data[c2_offset + 1 : c2_offset + 5])[0]))
        port = str(struct.unpack(">H", data[c2_offset + 5 : c2_offset + 7])[0])
        controllers.append(f"{ip}:{port}")
    return controllers


def decompress(data):
    """
    Decompress data with blzpack decompression
    """
    if not HAVE_BLZPACK:
        return
    return blzpack.decompress_data(BRIEFLZ_HEADER.join(data.split(QAKBOT_HEADER)))


def decrypt_data(data):
    """
    Decrypts the data using the last 20 bytes as a rc4 key.
    Validates the decryption with the sha1 sum contained within the first 20 bytes of the decrypted data.
    """
    if not data:
        return

    key = data[:0x14]
    decrypted_data = ARC4.new(key).decrypt(data[0x14:])

    if not decrypted_data:
        return

    if hashlib.sha1(decrypted_data[0x14:]).digest() != decrypted_data[:0x14]:
        return

    return decrypted_data[0x14:]


def decrypt_data2(data):
    if not data:
        return

    hash_obj = hashlib.sha1(b"\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    rc4_key = hash_obj.digest()
    decrypted_data = ARC4.new(rc4_key).decrypt(data)

    if not decrypted_data:
        return

    return decrypted_data


def decrypt_data3(data):
    if not data:
        return

    hash_obj = hashlib.sha1(b"\\System32\\WindowsPowerShel1\\v1.0\\powershel1.exe")
    rc4_key = hash_obj.digest()
    decrypted_data = ARC4.new(rc4_key).decrypt(data)

    if not decrypted_data:
        return

    if hashlib.sha1(decrypted_data[0x14:]).digest() == decrypted_data[:0x14]:
        return decrypted_data

    # From around 403.902 onwards (30-09-2022)
    hash_obj = hashlib.sha1(b"Muhcu#YgcdXubYBu2@2ub4fbUhuiNhyVtcd")
    rc4_key = hash_obj.digest()
    decrypted_data = ARC4.new(rc4_key).decrypt(data)

    if not decrypted_data:
        return

    if rc4_key == decrypted_data[:0x14]:
        return decrypted_data

    decrypted_data = ARC4.new(decrypted_data[0x14:0x28]).decrypt(decrypted_data[0x28:])
    if not decrypted_data:
        return

    if hashlib.sha1(decrypted_data[0x14:]).digest() != decrypted_data[:0x14]:
        return

    return decrypted_data


def decrypt_data4(data):
    if not data:
        return

    hash_obj = hashlib.sha1(b"bUdiuy81gYguty@4frdRdpfko(eKmudeuMncueaN")
    rc4_key = hash_obj.digest()
    decrypted_data = ARC4.new(rc4_key).decrypt(data)

    if not decrypted_data:
        return

    decrypted_data = ARC4.new(decrypted_data[0x14:0x28]).decrypt(decrypted_data[0x28:])
    if not decrypted_data:
        return

    if hashlib.sha1(decrypted_data[0x14:]).digest() != decrypted_data[:0x14]:
        return

    return decrypted_data


def get_sha256_hash(data):
    sha256 = SHA256.new()
    sha256.update(data)
    return sha256.digest()


def decrypt_aes_cbc(encrypted_data, key, iv):
    decoded = ""
    with suppress(Exception):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(encrypted_data)
        decoded = unpad(decrypted_data, AES.block_size)

    return decoded


def get_ips(data):
    ip_addresses = []
    segments = data.split(b"\x00")

    for segment in segments:
        with suppress(Exception):
            (_, ip_int, port) = struct.unpack("!BIH", segment)
            ip_addr = str(ipaddress.ip_address(ip_int))
            ip_addresses.append(f"{ip_addr}:{port}")

    return ip_addresses


def decrypt_strings(data, xor_key):
    decoded_strings = []
    current_string = bytearray()
    key_index = 0
    num = 0
    key_length = len(xor_key)

    for byte in data:
        decoded_byte = byte ^ xor_key[key_index] & 0xFF
        if decoded_byte != 0:
            current_string.append(decoded_byte)
        else:
            with suppress(Exception):
                dec_str = current_string.decode("utf-8")
                dec_str = f"{num - len(dec_str)}|{dec_str}"
                decoded_strings.append(dec_str)
                current_string.clear()
        key_index = (key_index + 1) % key_length
        num += 1

    return decoded_strings


def extract_config(filebuf):
    end_config = {}
    if filebuf[:2] == b"MZ":
        try:
            pe = pefile.PE(data=filebuf, fast_load=False)
            matches = yara_rules.match(data=filebuf)
            if matches:
                decrypt_offset = ""
                c2decrypt = ""
                confdecrypt = ""

                for match in matches:
                    if match.rule != "QakBot5":
                        continue
                    for item in match.strings:
                        if "$c2list" == item.identifier:
                            c2decrypt = item.instances[0].offset
                        elif "$campaign" == item.identifier:
                            confdecrypt = item.instances[0].offset
                        elif "$decrypt_str" == item.identifier:
                            decrypt_offset = item.instances[0].offset

                if not (decrypt_offset and c2decrypt and confdecrypt):
                    return

                aes_pwd_disp = pe.get_dword_from_offset(decrypt_offset + 7)
                aes_pwd_rva = pe.get_rva_from_offset(decrypt_offset + 11) + aes_pwd_disp
                aes_pwd_size = pe.get_dword_from_offset(decrypt_offset + 15)
                aes_pwd = pe.get_data(aes_pwd_rva, aes_pwd_size)
                key = get_sha256_hash(aes_pwd)
                enc_xor_disp = pe.get_dword_from_offset(decrypt_offset + 40)
                enc_xor_rva = pe.get_rva_from_offset(decrypt_offset + 44) + enc_xor_disp
                enc_xor_size = pe.get_dword_from_offset(decrypt_offset + 28)
                enc_xor = pe.get_data(enc_xor_rva, enc_xor_size)
                enc_strs_disp = pe.get_dword_from_offset(decrypt_offset + 22)
                enc_strs_rva = pe.get_rva_from_offset(decrypt_offset + 26) + enc_strs_disp
                enc_strs_size = pe.get_dword_from_offset(decrypt_offset + 45)
                enc_strs = pe.get_data(enc_strs_rva, enc_strs_size)

                iv = enc_xor[:16]
                encrypted_buffer = enc_xor[16:]
                xor_key = decrypt_aes_cbc(encrypted_buffer, key, iv)
                decoded = decrypt_strings(enc_strs, xor_key)

                if not decoded:
                    return

                c2blob_disp = pe.get_dword_from_offset(c2decrypt + 29)
                c2blob_rva = pe.get_rva_from_offset(c2decrypt + 33) + c2blob_disp
                c2blob_size_disp = pe.get_dword_from_offset(c2decrypt + 3)
                c2blob_size_rva = pe.get_rva_from_offset(c2decrypt + 7) + c2blob_size_disp
                c2blob_size = pe.get_word_at_rva(c2blob_size_rva)
                c2blob = pe.get_data(c2blob_rva, c2blob_size)
                c2blob_pwd_index = str(pe.get_dword_from_offset(c2decrypt + 8))

                confblob_disp = pe.get_dword_from_offset(confdecrypt + 30)
                confblob_rva = pe.get_rva_from_offset(confdecrypt + 34) + confblob_disp
                confblob_size_disp = pe.get_dword_from_offset(confdecrypt + 3)
                confblob_size_rva = pe.get_rva_from_offset(confdecrypt + 7) + confblob_size_disp
                confblob_size = pe.get_word_at_rva(confblob_size_rva)
                confblob = pe.get_data(confblob_rva, confblob_size)

                ip_list = []
                config = ""
                for val in decoded:
                    index, aes_pwd = val.split("|")
                    if index == c2blob_pwd_index:
                        key = get_sha256_hash(aes_pwd.encode("utf-8"))
                        iv = c2blob[1:17]
                        encrypted_buffer = c2blob[17:]
                        decoded = decrypt_aes_cbc(encrypted_buffer, key, iv)
                        if decoded:
                            cncs = decoded[32:]
                            ip_list = get_ips(cncs)

                        if ip_list:
                            end_config.setdefault("C2s", ip_list)

                        iv = confblob[1:17]
                        encrypted_buffer = confblob[17:]
                        decoded = decrypt_aes_cbc(encrypted_buffer, key, iv)

                        if decoded:
                            conf = decoded[32:]
                            config = parse_config(conf)

                        if config:
                            end_config.update(config)

                        break

            else:
                if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                    return end_config
                for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for entry in rsrc.directory.entries:
                        if entry.name is None:
                            continue
                        # log.info("id: %s", entry.name)
                        controllers = []
                        config = {}
                        offset = entry.directory.entries[0].data.struct.OffsetToData
                        size = entry.directory.entries[0].data.struct.Size
                        res_data = pe.get_memory_mapped_image()[offset : offset + size]
                        if str(entry.name) == "307":
                            # we found the parent process and still need to decrypt/(blzpack) decompress the main DLL
                            dec_bytes = decrypt_data(res_data)
                            decompressed = decompress(dec_bytes)
                            end_config["Loader Build"] = parse_build(pe).decode()
                            pe2 = pefile.PE(data=decompressed)
                            if not hasattr(pe2, "DIRECTORY_ENTRY_RESOURCE"):
                                continue
                            for rsrc in pe2.DIRECTORY_ENTRY_RESOURCE.entries:
                                for entry in rsrc.directory.entries:
                                    if entry.name is None:
                                        continue
                                    offset = entry.directory.entries[0].data.struct.OffsetToData
                                    size = entry.directory.entries[0].data.struct.Size
                                    res_data = pe2.get_memory_mapped_image()[offset : offset + size]
                                    if str(entry.name) == "308":
                                        dec_bytes = decrypt_data(res_data)
                                        config = parse_config(dec_bytes)
                                        # log.info("qbot_config: %s", config)
                                        end_config["Core DLL Build"] = parse_build(pe2).decode()
                                    elif str(entry.name) == "311":
                                        dec_bytes = decrypt_data(res_data)
                                        controllers = parse_controllers(dec_bytes)
                        elif str(entry.name) == "308":
                            dec_bytes = decrypt_data(res_data)
                            config = parse_config(dec_bytes)
                        elif str(entry.name) == "311":
                            dec_bytes = decrypt_data(res_data)
                            controllers = parse_binary_c2(dec_bytes)
                        elif str(entry.name) in ("118", "3719"):
                            dec_bytes = decrypt_data2(res_data)
                            controllers = parse_binary_c2_2(dec_bytes)
                        elif str(entry.name) in ("524", "5812"):
                            dec_bytes = decrypt_data2(res_data)
                            config = parse_config(dec_bytes)
                        elif str(entry.name) in ("18270D2E", "BABA", "103", "89210AF9"):
                            dec_bytes = decrypt_data3(res_data)
                            config = parse_config(dec_bytes)
                        elif str(entry.name) in ("26F517AB", "EBBA", "102", "3C91E639"):
                            dec_bytes = decrypt_data3(res_data)
                            controllers = parse_binary_c2_2(dec_bytes)
                        elif str(entry.name) in ("89290AF9", "COMPONENT_07"):
                            dec_bytes = decrypt_data4(res_data)
                            config = parse_config(dec_bytes)
                        elif str(entry.name) in ("3C91E539", "COMPONENT_08"):
                            dec_bytes = decrypt_data4(res_data)
                            controllers = parse_binary_c2_2(dec_bytes)
                        end_config["Loader Build"] = parse_build(pe).decode()
                        for k, v in config.items():
                            # log.info({ k: v })
                            end_config.setdefault(k, v)
                        # log.info("controllers: %s", controllers)
                        for controller in controllers:
                            end_config.setdefault("address", []).append(controller)
        except Exception as e:
            log.warning(e)
    elif filebuf[:1] == b"\x01":
        controllers = parse_binary_c2(filebuf[: len(filebuf) - 20])
        for controller in controllers:
            end_config.setdefault("address", []).append(controller)
    elif b"=" in filebuf:
        config = parse_config(filebuf[: len(filebuf) - 20])
        for k, v in config.items():
            end_config.setdefault(k, v)
    return end_config


if __name__ == "__main__":
    import sys
    from pathlib import Path

    log.setLevel(logging.DEBUG)
    data = Path(sys.argv[1]).read_bytes()
    print(extract_config(data))
