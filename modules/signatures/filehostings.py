import logging

from lib.cuckoo.common.abstracts import Signature

log = logging.getLogger(__name__)


class Modiloader_APIs(Signature):
    name = "downloads_from_filehosting"
    description = "Downloads probably next stage from public file hosting"
    weight = 3
    severity = 3
    categories = ["loader"]
    authors = ["doomedraven"]
    minimum = "1.2"
    evented = True
    ttps = ["T1071"]  # MITRE v6,7,8
    ttps += ["T1071.001"]  # MITRE v7,8
    mbcs = ["OC0006", "C0002"]  # micro-behaviour

    filter_apinames = set(["InternetOpenUrlA", "WinHttpOpenRequest"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.urls = list()

    def on_call(self, call, process):
        url = False
        if call["api"] == "InternetOpenUrlA":
            url = self.get_argument(call, "URL")
        elif call["api"] == "WinHttpOpenRequest":
            url = self.get_argument(call, "ObjectName")

        if url:
            if url.startswith("https://cdn.discordapp.com/attachments/"):
                if self.pid:
                    self.mark_call()
                self.urls.append(url)
            elif url.startswith("/attachments/"):
                if self.pid:
                    self.mark_call()
                self.urls.append("https://cdn.discordapp.com" + url)
            elif url.startswith("/u/0/uc?id="):
                if self.pid:
                    self.mark_call()
                self.urls.append("https://drive.google.com" + url)
            elif "basecamp.com/p/" in url:
                if self.pid:
                    self.mark_call()
                self.urls.append(url)
            elif url.startswith("https://anonymousfiles.io/"):
                if self.pid:
                    self.mark_call()
                self.urls.append(url)

    def on_complete(self):
        if self.urls:
            self.data.append({"urls": self.urls})
