"""
    Qakbot decoder for Core/Main DLL
"""

DESCRIPTION = "Qakbot configuration parser."
AUTHOR = "threathive, r1n9w0rm"

import datetime
import hashlib
import logging
import socket
import struct

import pefile
from Cryptodome.Cipher import ARC4

try:
    HAVE_BLZPACK = True
    from lib.cuckoo.common import blzpack
except OSError as e:
    print(f"Problem to import blzpack: {e}")
    HAVE_BLZPACK = False

log = logging.getLogger(__name__)

"""
    Config Map
"""
CONFIG = {b"10": "Campaign ID", b"3": "Config timestamp"}

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
                config[CONFIG.get(k, k)] = datetime.datetime.fromtimestamp(int(v)).strftime("%H:%M:%S %d-%m-%Y")
            else:
                k = k[-2:]
                config[CONFIG.get(k, k)] = v.decode()
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


def extract_config(filebuf):
    end_config = {}
    if filebuf[:2] == b"MZ":
        try:
            pe = pefile.PE(data=filebuf, fast_load=False)
            # image_base = pe.OPTIONAL_HEADER.ImageBase
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
