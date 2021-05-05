import logging

from malduck.extractor import Extractor

log = logging.getLogger(__name__)

__author__  = "CERT.pl"
__version__ = "1.0.0"

class Citadel(Extractor):

    """
    Citadel Configuration Extracto
    """
    
    family     = "citadel"
    yara_rules = "citadel",

    @Extractor.extractor("briankerbs")
    def citadel_found(self, p, addr):
        log.info('[+] `Coded by Brian Krebs` str @ %X' % addr)
        return {'family': 'citadel'}

    @Extractor.extractor
    def cit_salt(self, p, addr):
        salt = p.uint32v(addr - 8)
        log.info('[+] Found salt @ %X - %x' % (addr, salt))
        return {'salt': salt}

    @Extractor.string
    def cit_login(self, p, addr, match):
        log.info('[+] Found login_key xor @ %X' % addr)
        hit = p.uint32v(addr + 4)
        if p.is_addr(hit):
            return {'login_key': p.asciiz(hit)}
        hit = p.uint32v(addr + 5)
        if p.is_addr(hit):
            return {'login_key': p.asciiz(hit)}
