from lib.cuckoo.common.abstracts import Signature


class OrcusRAT(Signature):
    name = "orcusrat_behavior"
    description = "Detects OrcusRAT Behavior"
    weight = 3
    severity = 3
    categories = ["rat"]
    families = ["OrcusRAT"]
    authors = ["@NaxoneZ"]
    minimum = "1.2"
    evented = True
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]

    # Sample List
    # OrcusRAT:
    #  1. 2373c4b52ac6133345f309ac75b67bbb (variant1)

    filter_apinames = set(["RegOpenKeyExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.badness_files = 0

    def on_call(self, call, process):
        if call["api"] == "RegOpenKeyExW":
            node = self.get_argument(call, "FullName")
            if "HKEY_CURRENT_USER\\SOFTWARE\\Orcus" in node:
                self.badness_files += 1
                if self.pid:
                    self.mark_call()

            if "Orcus.Plugins" in node:
                self.badness_files += 1
                if self.pid:
                    self.mark_call()

            if "Orcus.Shared" in node:
                self.badness_files += 1
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        if self.badness_files >= 3:
            return True
        else:
            return False
