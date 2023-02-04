from lib.cuckoo.common.abstracts import Signature


class overlay(Signature):
    name = "overlay"
    description = "Sample contains Overlay data"
    severity = 1
    weight = 0
    categories = ["obfuscation"]
    authors = ["annoy-o-mus"]

    def run(self):
        overlay = self.results.get("static", {}).get("pe", {}).get("overlay")
        if overlay:
            self.data.append({"Overlay Offset": overlay["offset"]})
            self.data.append({"Overlay Size": overlay["size"]})
            # self.data.append({"Overlay Data": overlay["data"]})
            return True
