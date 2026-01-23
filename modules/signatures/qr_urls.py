
from lib.cuckoo.common.abstracts import Signature

class QRUrls(Signature):
    name = "qr_urls"
    description = "URLs extracted from QR codes in screenshots"
    severity = 1
    categories = ["info"]
    authors = ["DoomedRaven"]
    minimum = "1.3"
    evented = False

    def run(self):
        qr_urls = self.results.get("qr_urls")
        if qr_urls:
            for url in qr_urls:
                self.data.append({"url": url})
            return True
        return False
