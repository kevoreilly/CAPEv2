from lib.cuckoo.common.abstracts import Signature

files = (
        "\\files\\Autofill",
        "\\files\\Cookies",
        "\\files\\CC",
        "\\files\\History",
        "\\files\\Downloads",
        "\\files\\Soft",
        "\\files\\Cookies\\IE_Cookies.txt",
        "\\files\\Cookies\\Edge_Cookies.txt",
        "\\AppData\\Roaming\\.purple\\accounts.xml",
        "\\files\\cookie_list.txt",
        "\\files\\outlook.txt",
        "\\files\\information.txt",
        "\\files\\Files\\default.zip",
        "\\files\\screenshot.jpg",
        "\\files\\Cookies\\cookies_Mozilla",
        "\\files\\History\\history_Mozilla",
)

urls = (
    "freebl3.dll",
    "mozglue.dll",
    "msvcp140.dll",
    "nss3.dll",
    "softokn3.dll",
    "vcruntime140.dll",
)

header = "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1"

class vidar(Signature):
    name = "Vidar Behavior"
    description = "Detects Vidar Behavior"
    weight = 3
    severity = 3
    categories = ["Infostealer"]
    families = ["Vidar"]
    authors = ["@NaxoneZ"]
    minimum = "1.2"
    evented = True
    samples = {
    "Vidar":
        {
            "1": "726aa7c9d286afab16c956639ffe01a47ce556bc893f46d487b3148608a019d7", #variant1
        }
    }

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.badness_urls = 0
        self.badness_files = 0
        self.badness_headers = 0

    filter_apinames = set(["NtCreateFile","HttpOpenRequestA","HttpAddRequestHeadersA"])

    def on_call(self, call, process):

        if call["api"] == "NtCreateFile":
            node = self.get_argument(call,"FileName")
            for i in files:
                if i in node:
                    self.badness_files += 1

        if call["api"] == "HttpOpenRequestA":
            node = self.get_argument(call,"Path")

            for i in urls:
                if i in node:
                    self.badness_urls += 1

        if call["api"] == "HttpAddRequestHeadersA":
            node = self.get_argument(call,"Headers")
            if header in node:
                self.badness_headers +=1

    def on_complete(self):
        if self.badness_files > 40 and self.badness_urls > 5 and self.badness_headers > 5:
            return True
        else:
            return False
