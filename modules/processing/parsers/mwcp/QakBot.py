"""
    Qakbot decoder for Core/Main DLL
"""

import struct
import socket
import pefile
import hashlib
import datetime
import logging

from mwcp.parser import Parser
from Crypto.Cipher import ARC4

try:
    HAVE_BLZPACK = True
    from lib.cuckoo.common import blzpack
except OSError as e:
    print(f"Problem to import blzpack: {str(e)}")
    HAVE_BLZPACK = False

log = logging.getLogger(__name__)

"""
    Config Map
"""
CONFIG = {b"10": b"Campaign ID", b"3": b"Config timestamp"}

BRIEFLZ_HEADER = b"\x62\x6C\x7A\x1A\x00\x00\x00\x01"
QAKBOT_HEADER = b"\x61\x6c\xd3\x1a\x00\x00\x00\x01"

"""
    Extract build version from parent of core dll.
"""


def parse_build(pe):
    for sec in pe.sections:
        if sec.Name == b".data\x00\x00\x00":
            major, minor = struct.unpack("<II", sec.get_data()[:8])
            return b"%X.%d" % (major, minor)


"""
   Parses the config block into a more human readable format.
   Data looks like this initially b'3=1592498872'
"""


def parse_config(data):
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
        except Exception as e:
            log.info("Failed to parse config entry:{}".format(entry))

    return config


"""
    Parses the CNC block into a more human readable format.
    Data looks like this initially 72.29.181.77;0;2078\r\n'
"""


def parse_controllers(data):
    controllers = []
    for controller in list(filter(None, data.split(b"\r\n"))):
        ip, _, port = controller.decode().split(";")
        controllers.append("{}:{}".format(ip, port))

    return controllers


"""
    Parses the binary CNC block format introduced Nov'20
"""


def parse_binary_c2(data):
    controllers = []
    c2_offset = 0
    length = len(data)
    while c2_offset < length:
        ip = socket.inet_ntoa(struct.pack("!L", struct.unpack(">I", data[c2_offset + 1 : c2_offset + 5])[0]))
        port = str(struct.unpack(">H", data[c2_offset + 5 : c2_offset + 7])[0])
        c2_offset += 7
        controllers.append("{}:{}".format(ip, port))
    return controllers


"""
    Parses the binary CNC block format introduced April'21
"""


def parse_binary_c2_2(data):
    controllers = []
    c2_offset = 0
    c2_data = data

    expected_sha1 = c2_data[:0x14]
    c2_data = c2_data[0x14:]
    actual_sha1 = hashlib.sha1(c2_data).digest()

    if actual_sha1 != expected_sha1:
        log.error(f"Expected sha1: {expected_sha1} actual: {actual_sha1}")
        return

    length = len(c2_data)

    while c2_offset < length:
        ip = socket.inet_ntoa(struct.pack("!L", struct.unpack(">I", c2_data[c2_offset + 1 : c2_offset + 5])[0]))
        port = str(struct.unpack(">H", c2_data[c2_offset + 5 : c2_offset + 7])[0])
        c2_offset += 7
        controllers.append("{}:{}".format(ip, port))
    return controllers


"""
    Decompress data with blzpack decompression
"""


def decompress(data):
    return blzpack.decompress_data(BRIEFLZ_HEADER.join(data.split(QAKBOT_HEADER)))


"""
    Decrypts the data using the last 20 bytes as a rc4 key.
    Validates the decryption with the sha1 sum contained within the first 20 bytes of the decrypted data.
"""


def decrypt_data(data):
    if not data:
        return

    rc4_key = data[:0x14]
    decrypted_data = ARC4.new(rc4_key).decrypt(data[0x14:])

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
                        # log.info("id:{}".format(entry.name.__str__()))
                        config = {}
                        offset = entry.directory.entries[0].data.struct.OffsetToData
                        size = entry.directory.entries[0].data.struct.Size
                        res_data = pe.get_memory_mapped_image()[offset : offset + size]
                        if entry.name.__str__() == "307":
                            # we found the parent process and still need to decrypt/(blzpack) decompress the main DLL
                            dec_bytes = decrypt_data(res_data)
                            decompressed = decompress(dec_bytes)
                            self.reporter.add_metadata("other", {"Loader Build": parse_build(pe).decode("utf-8")})
                            pe2 = pefile.PE(data=decompressed)
                            for rsrc in pe2.DIRECTORY_ENTRY_RESOURCE.entries:
                                for entry in rsrc.directory.entries:
                                    if entry.name is not None:
                                        offset = entry.directory.entries[0].data.struct.OffsetToData
                                        size = entry.directory.entries[0].data.struct.Size
                                        res_data = pe2.get_memory_mapped_image()[offset : offset + size]
                                        if entry.name.__str__() == "308":
                                            dec_bytes = decrypt_data(res_data)
                                            config = parse_config(dec_bytes)
                                            # log.info("qbot_config:{}".format(config))
                                            self.reporter.add_metadata(
                                                "other", {"Core DLL Build": parse_build(pe2).decode("utf-8")}
                                            )

                                        elif entry.name.__str__() == "311":
                                            dec_bytes = decrypt_data(res_data)
                                            controllers = parse_controllers(dec_bytes)

                            # log.info("meta data:{}".format(self.reporter.metadata))

                        elif entry.name.__str__() == "308":
                            dec_bytes = decrypt_data(res_data)
                            config = parse_config(dec_bytes)

                        elif entry.name.__str__() == "311":
                            dec_bytes = decrypt_data(res_data)
                            controllers = parse_binary_c2(dec_bytes)

                        elif entry.name.__str__() == "118":
                            dec_bytes = decrypt_data2(res_data)
                            controllers = parse_binary_c2_2(dec_bytes)

                        elif entry.name.__str__() == "3719":
                            dec_bytes = decrypt_data2(res_data)
                            controllers = parse_binary_c2_2(dec_bytes)

                        elif entry.name.__str__() == "524":
                            dec_bytes = decrypt_data2(res_data)
                            config = parse_config(dec_bytes)

                        elif entry.name.__str__() == "5812":
                            dec_bytes = decrypt_data2(res_data)
                            config = parse_config(dec_bytes)

                        self.reporter.add_metadata("other", {"Loader Build": parse_build(pe).decode("utf-8")})

                        for k, v in config.items():
                            # log.info( { k.decode("utf-8"): v.decode("utf-8") })
                            self.reporter.add_metadata("other", {k: v})

                        # log.info("controllers:{}".format(controllers))
                        for controller in controllers:
                            self.reporter.add_metadata("address", controller)
                        # log.info("meta data:{}".format(self.reporter.metadata))

        except Exception as e:
            log.warning(e)
