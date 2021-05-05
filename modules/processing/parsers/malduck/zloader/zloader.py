import logging
from malduck.extractor import Extractor
from malduck.pe import MemoryPEData
from malduck import rc4

# A Code Cleanup / Port of kevoreilly's ZLoader Configuration to Malduck
# https://github.com/kevoreilly/CAPEv2/blob/master/modules/processing/parsers/mwcp/Zloader.py

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

class ZLoader(Extractor):

    """
    A ZLoader Configuration Extractor
    """

    family = 'zloader'
    yara_rules = ('zloader',)

    @Extractor.extractor('decrypt_conf')
    def decrypt_conf(self, p, addr):
        try:
            key_addr = p.uint32v(addr+21)
            key = p.asciiz(key_addr)
            data_offset = p.uint32v(addr+26)
            config_encrypted = p.readv(addr=data_offset).split(b'\0\0')[0]
            config_raw = rc4(key, config_encrypted)
            config_items = list(filter(None, config_raw.split(b'\x00\x00')))
            for i in range(0, len(config_items)):
                config_items[i] = config_items[i].strip(b'\x00')
            config = {
                'family': 'zloader',
                'name':config_items[1].decode('utf-8'),
                'campaign_id': config_items[2].decode('utf-8'),
                'urls': [config_items[3].decode('utf-8')]
            }
            return config
        except Exception as error:
            log.warning(error)
