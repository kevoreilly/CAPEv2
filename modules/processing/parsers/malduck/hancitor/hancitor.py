import binascii
import collections
import hashlib
import logging
import math
import malduck
from malduck.extractor import Extractor
from malduck.pe import PE

log = logging.getLogger(__name__)

__author__  = "myrtus0x0"
__version__ = "1.0.0"

class Hancitor(Extractor):
    """
    Hancitor C2s and Campaign ID Extractor
    """

    family     = 'hancitor'
    yara_rules = 'hancitor',

    @staticmethod
    def estimate_shannon_entropy(data):
        m = len(data)
        bases = collections.Counter([tmp_base for tmp_base in data])
        shannon_entropy_value = 0
        for base in bases:
            n_i = bases[base]
            p_i = n_i / float(m)
            entropy_i = p_i * (math.log(p_i, 2))
            shannon_entropy_value += entropy_i
        return shannon_entropy_value * -1

    @staticmethod
    def string_from_offset(data, offset):
        MAX_STRING_SIZE = 2048
        string = data[offset:offset + MAX_STRING_SIZE].split(b"\0")[0]
        return string

    def parse_config(self, raw_config_blob):
        conf = {}
        split_conf = raw_config_blob.split(b"\x00")
        cleaned_conf = [x for x in split_conf if x]
        log.info(cleaned_conf)
        conf["family"] = self.family
        conf["id"] = cleaned_conf[0].decode("utf-8")
        conf["urls"] = cleaned_conf[1].split(b"|")
        conf["urls"] = [x.decode("utf-8") for x in conf["urls"] if x]
        return conf

    @Extractor.final
    def ref_c2(self, p):
        pe_rep = PE(data=p)
        raw_rc4_key = None
        crypted_data = None
        for section in pe_rep.sections:
            if b".data" in section.Name:
                section_data = section.get_data()
                raw_rc4_key = section_data[16:24]
                crypted_data = section_data[24:24 + 8192]
        if raw_rc4_key is None or crypted_data is None:
            log.error("unable to find .data section")
            return
        log.info("key: %s" % binascii.hexlify(raw_rc4_key))
        flags = 0x280011
        key_length = int((flags >> 16) / 8)
        raw_hash = hashlib.sha1(raw_rc4_key).digest()[:key_length]
        log.info("len of encrypted data: %s, decrypting with %s" % (len(crypted_data), binascii.hexlify(raw_hash)))
        decrypted = malduck.rc4(raw_hash, crypted_data)
        entropy = self.estimate_shannon_entropy(decrypted)
        log.info("decrypted data entropy: %s" % entropy)
        if entropy < 1:
            conf = self.parse_config(decrypted)
            return conf
