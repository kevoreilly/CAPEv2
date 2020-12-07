"""
    Hancitor config extractor
"""
import pefile
import hashlib
from mwcp.parser import Parser
from Crypto.Cipher import ARC4
import logging
log = logging.getLogger(__name__)


class Hancitor(Parser):
    DESCRIPTION = "Hancitor config extractor."
    AUTHOR = "threathive"

    def run(self):
        filebuf = self.file_object.file_data
        try:

            pe = pefile.PE(data=filebuf, fast_load=False)
            for i in pe.sections:
                if b".data" in i.Name:
                    DATA_SECTION = i.get_data()
                    RC4_KEY = hashlib.sha1(DATA_SECTION[16:24]).digest()[:5]
                    ENCRYPT_DATA = DATA_SECTION[24:2000]

                    DECRYPTED_DATA = ARC4.new(RC4_KEY).decrypt(ENCRYPT_DATA)
                    build_id, controllers = list(filter(None,  DECRYPTED_DATA.split(b"\x00") ))

                    self.reporter.add_metadata("other", { "Build ID": build_id })
                    for controller in list(filter(None,  controllers.split(b"|") )):
                        self.reporter.add_metadata("address", controller)


        except Exception as e:
            log.warning(e)
