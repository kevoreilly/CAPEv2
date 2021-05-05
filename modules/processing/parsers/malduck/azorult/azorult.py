import logging

from malduck.extractor import Extractor
from malduck.pe import MemoryPEData

log = logging.getLogger(__name__)

__author__  = "c3rb3ru5"
__version__ = "1.0.0"

class Azorult(Extractor):

    """
    Azorult C2 Domain Configuration Extractor
    """

    family     = 'azorult'
    yara_rules = 'azorult',

    @staticmethod
    def string_from_offset(data, offset):
        MAX_STRING_SIZE = 2048
        string = data[offset:offset+MAX_STRING_SIZE].split(b"\0")[0]
        return string

    @Extractor.extractor('ref_c2')
    def ref_c2(self, p, addr):
        image_base = p.imgbase
        c2_list_va = p.uint32v(addr + 21)
        c2_list_rva = c2_list_va - image_base
        pe_mem = MemoryPEData(memory=p, fast_load=True)
        log.debug("c2_list_rva:" + str(c2_list_rva))
        try:
            c2_list_offset = pe_mem.pe.get_offset_from_rva(c2_list_rva)
        except Exception as error:
            log.warning(error)
            return None
        log.debug("c2_list_offset:" + str(c2_list_offset))
        c2 = self.string_from_offset(p.memory, c2_list_offset).decode('utf-8')
        if len(c2) <= 0:
            return None
        return {'family': 'azorult', 'urls': [c2]}
