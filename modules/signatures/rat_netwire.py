from lib.cuckoo.common.abstracts import Signature

matches = (
    "HKEY_CURRENT_USER\\Software\\NetWire\\HostId",
    "HKEY_CURRENT_USER\\Software\\NetWire\\Install Date",
)


class netwire(Signature):
    name = "netwire_behavior"
    description = "Detects NetWire Behavior"
    weight = 3
    severity = 3
    categories = ["rat"]
    families = ["NetWire"]
    authors = ["@NaxoneZ"]
    minimum = "1.2"
    evented = True
    ttps = ["T1219"]  # MITRE v6,7,8
    mbcs = ["B0022"]

    # Sample List
    # NetWire:
    # 1. e9dc09a5dabdc98350d319469055733c93723d4dd262e577b7599c90de7386b9 (variant1)

    filter_apinames = set(["RegSetValueExA"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.badness_reg = 0

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExA":
            node = self.get_argument(call, "FullName")
            for i in matches:
                if i in node:
                    self.badness_reg += 1
                    if self.pid:
                        self.mark_call()

    def on_complete(self):
        if self.badness_reg > 1:
            return True
        else:
            return False
