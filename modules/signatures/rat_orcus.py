from lib.cuckoo.common.abstracts import Signature

class OrcusRAT(Signature):
    name = "OrcusRAT Behavior"
    description = "Detects OrcusRAT Behavior"
    weight = 3
    severity = 3
    categories = ["RAT"]
    families = ["OrcusRAT"]
    authors = ["@NaxoneZ"]
    minimum = "1.2"
    evented = True
    samples = {
    "OrcusRAT":
        {
            "1": "2373c4b52ac6133345f309ac75b67bbb", #variant1
        }
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.badness_files = 0

    filter_apinames = set(["RegOpenKeyExW"])

    def on_call(self, call, process):

        if call["api"] == "RegOpenKeyExW":
            node = self.get_argument(call,"FullName")
            if "HKEY_CURRENT_USER\\SOFTWARE\\Orcus" in node:
                self.badness_files += 1

            if "Orcus.Plugins" in node:
                self.badness_files += 1

            if "Orcus.Shared" in node:
                self.badness_files += 1

    def on_complete(self):
        if self.badness_files >=3:
            return True
        else:
            return False
