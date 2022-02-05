"""
    Qakbot decoder for Core/Main DLL
"""

import datetime
import hashlib
import logging
import socket
import struct

import pefile
from Cryptodome.Cipher import ARC4
from mwcp.parser import Parser

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
CONFIG = {b"10": b"Campaign ID", b"3": b"Config timestamp"}

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
            k, v = entry.split(b"=")
            if k == b"3":
                config[CONFIG.get(k, k)] = datetime.datetime.fromtimestamp(int(v)).strftime("%H:%M:%S %d-%m-%Y")
            else:
                k = k[-2:]
                config[CONFIG.get(k, k)] = v
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
    for c2_offset in range(0, length, 7):
        ip = socket.inet_ntoa(struct.pack("!L", struct.unpack(">I", data[c2_offset + 1 : c2_offset + 5])[0]))
        port = str(struct.unpack(">H", data[c2_offset + 5 : c2_offset + 7])[0])
        controllers.append(f"{ip}:{port}")
    return controllers


def parse_binary_c2_2(data):
    """
    Parses the binary CNC block format introduced April'21
    """
    c2_data = data

    expected_sha1 = c2_data[:0x14]
    c2_data = c2_data[0x14:]
    actual_sha1 = hashlib.sha1(c2_data).digest()

    if actual_sha1 != expected_sha1:
        log.error("Expected sha1: %s actual: %s", expected_sha1, actual_sha1)
        return

    length = len(c2_data)

    controllers = []
    for c2_offset in range(0, length, 7):
        ip = socket.inet_ntoa(struct.pack("!L", struct.unpack(">I", c2_data[c2_offset + 1 : c2_offset + 5])[0]))
        port = str(struct.unpack(">H", c2_data[c2_offset + 5 : c2_offset + 7])[0])
        controllers.append(f"{ip}:{port}")
    return controllers


def decompress(data):
    """
    Decompress data with blzpack decompression
    """
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


class QakBot(Parser):
    DESCRIPTION = "Qakbot configuration parser."
    AUTHOR = "threathive, r1n9w0rm"

    def run(self):
        if not HAVE_BLZPACK:
            return
        filebuf = self.file_object.file_data
        try:
            pe = pefile.PE(data=filebuf, fast_load=False)
            # image_base = pe.OPTIONAL_HEADER.ImageBase
            for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for entry in rsrc.directory.entries:
                    if entry.name is not None:
                        # log.info("id: %s", entry.name)
                        config = {}
                        offset = entry.directory.entries[0].data.struct.OffsetToData
                        size = entry.directory.entries[0].data.struct.Size
                        res_data = pe.get_memory_mapped_image()[offset : offset + size]
                        if str(entry.name) == "307":
                            # we found the parent process and still need to decrypt/(blzpack) decompress the main DLL
                            dec_bytes = decrypt_data(res_data)
                            decompressed = decompress(dec_bytes)
                            self.reporter.add_metadata("other", {"Loader Build": parse_build(pe).decode()})
                            pe2 = pefile.PE(data=decompressed)
                            for rsrc in pe2.DIRECTORY_ENTRY_RESOURCE.entries:
                                for entry in rsrc.directory.entries:
                                    if entry.name is not None:
                                        offset = entry.directory.entries[0].data.struct.OffsetToData
                                        size = entry.directory.entries[0].data.struct.Size
                                        res_data = pe2.get_memory_mapped_image()[offset : offset + size]
                                        if str(entry.name) == "308":
                                            dec_bytes = decrypt_data(res_data)
                                            config = parse_config(dec_bytes)
                                            # log.info("qbot_config: %s", config)
                                            self.reporter.add_metadata("other", {"Core DLL Build": parse_build(pe2).decode()})

                                        elif str(entry.name) == "311":
                                            dec_bytes = decrypt_data(res_data)
                                            controllers = parse_controllers(dec_bytes)

                            # log.info("meta data: %s", self.reporter.metadata)

                        elif str(entry.name) == "308":
                            dec_bytes = decrypt_data(res_data)
                            config = parse_config(dec_bytes)

                        elif str(entry.name) == "311":
                            dec_bytes = decrypt_data(res_data)
                            controllers = parse_binary_c2(dec_bytes)

                        elif str(entry.name) == "118":
                            dec_bytes = decrypt_data2(res_data)
                            controllers = parse_binary_c2_2(dec_bytes)

                        elif str(entry.name) == "3719":
                            dec_bytes = decrypt_data2(res_data)
                            controllers = parse_binary_c2_2(dec_bytes)

                        elif str(entry.name) == "524":
                            dec_bytes = decrypt_data2(res_data)
                            config = parse_config(dec_bytes)

                        elif str(entry.name) == "5812":
                            dec_bytes = decrypt_data2(res_data)
                            config = parse_config(dec_bytes)

                        self.reporter.add_metadata("other", {"Loader Build": parse_build(pe).decode()})

                        for k, v in config.items():
                            # log.info({ k.decode(): v.decode() })
                            self.reporter.add_metadata("other", {k: v})

                        # log.info("controllers: %s", controllers)
                        for controller in controllers:
                            self.reporter.add_metadata("address", controller)
                        # log.info("meta data: %s", self.reporter.metadata)

        except Exception as e:
            log.warning(e)
