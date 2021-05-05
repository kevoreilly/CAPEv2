import logging

from malduck.extractor import Extractor
from malduck.pe import MemoryPEData

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

class Caliber(Extractor):

    family     = '44caliber'
    yara_rules = ('caliber',)

    @Extractor.string
    def webhooks(self, p, addr, match):
        try:
            webhook_len = (p.uint8v(addr-2) * 2) - 16
            data = p.readp(offset=addr, length=webhook_len)
            webhook = data.decode('utf-16')
            return {'family': '44caliber', 'webhooks': [webhook]}
        except Exception as error:
            log.warning(error)
