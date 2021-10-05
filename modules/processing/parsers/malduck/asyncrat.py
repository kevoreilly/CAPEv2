import string
import logging
import base64
import requests
from malduck.extractor import Extractor
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2

log = logging.getLogger(__name__)

__author__ = "c3rb3ru5"
__version__ = "1.0.0"


class ASyncRAT(Extractor):

    """
    ASyncRAT Configuration Extractor
    """

    family = "asyncrat"
    yara_rules = ("asyncrat",)

    AES_BLOCK_SIZE = 128
    AES_KEY_SIZE = 256
    AES_CIPHER_MODE = AES.MODE_CBC

    @staticmethod
    def get_salt():
        return bytes.fromhex("BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941")

    def decrypt(self, key, ciphertext):
        aes_key = PBKDF2(key, self.get_salt(), 32, 50000)
        cipher = AES.new(aes_key, self.AES_CIPHER_MODE, ciphertext[32 : 32 + 16])
        plaintext = cipher.decrypt(ciphertext[48:]).decode("ascii", "ignore").strip()
        return plaintext

    @staticmethod
    def get_string(data, index):
        return data[index][1:].decode("utf-8", "ignore")

    def decrypt_config_item(self, key, data, index):
        data = base64.b64decode(self.get_string(data, index))
        plaintext = self.decrypt(key, data)
        if plaintext.lower() == "true":
            return True
        if plaintext.lower() == "false":
            return False
        return plaintext

    @staticmethod
    def get_wide_string(data, index):
        data = data[index][1:] + b"\x00"
        return data.decode("utf-16")

    # @staticmethod
    def get_wide_string2(self, key, data, index):
        # data = data[index][2:] + b"\x00"

        result = "".join(
            filter(
                lambda x: x in string.printable,
                self.decrypt(key, base64.b64decode(data[index][2:])),
            )
        )

        # return data.decode("utf-16")
        return result

    def decrypt_config_item_list(self, key, data, index):
        result = "".join(
            filter(
                lambda x: x in string.printable,
                self.decrypt(key, base64.b64decode(data[index][1:])),
            )
        )
        if result == "null":
            return []
        return result.split(",")

    def decrypt_config_item_printable(self, key, data, index):
        result = "".join(
            filter(
                lambda x: x in string.printable,
                self.decrypt(key, base64.b64decode(data[index][1:])),
            )
        )
        return result

    @Extractor.extractor("magic_cslr_0")
    def asyncrat(self, p, addr):
        try:
            strings_offset = p.uint32v(addr + 0x40)
            strings_size = p.uint32v(addr + 0x44)
            data = p.readv(addr + strings_offset, strings_size)
            data = data.split(b"\x00\x00")
            key = base64.b64decode(self.get_string(data, 7))
            config = {
                "family": self.family,
                "hosts": self.decrypt_config_item_list(key, data, 2),
                "ports": self.decrypt_config_item_list(key, data, 1),
                "version": self.decrypt_config_item_printable(key, data, 3),
                "key": self.get_wide_string(data, 7),
                "install_folder": self.get_wide_string(data, 5),
                "install_file": self.get_wide_string(data, 6),
                "install": self.decrypt_config_item_printable(key, data, 4),
                "mutex": self.decrypt_config_item_printable(key, data, 8),
                "pastebin": self.decrypt(key, base64.b64decode(data[12][1:])).encode("ascii").replace(b"\x0f", b""),
                "ServerCertificate": self.get_wide_string2(key, data, 9),
                "ServerSignature": self.get_wide_string2(key, data, 10),
            }
            if config["pastebin"] != "null":
                try:
                    r = requests.get(url=config["pastebin"])
                    if r.status_code == 200:
                        data = r.content.split(b"\x3a")
                        config["host"] = data[0].decode("ascii", "ignore")
                        config["ports"] = [data[1].decode("ascii", "ignore")]
                except Exception as error:
                    log.warning(error)
            return config
        except Exception as error:
            log.warning(error)
            return None
