#
# Based on internet_request.py by KillerInstinct
#

from lib.cuckoo.common.abstracts import Signature

try:
    from data.safelist.domains import domain_passlist
except ImportError:
    print("Please update CAPE from main repo")
    domain_passlist = ["acroipm.adobe.com", "acroipm2.adobe.com", "microsoft.com", "ocsp.digicert.com", "apps.identrust.com"]


class HTTP_Request(Signature):
    name = "http_request"
    description = "Performs HTTP requests potentially not found in PCAP."
    severity = 2
    categories = ["network"]
    authors = ["enzok", "ditekshen"]
    minimum = "1.2"
    evented = True
    ttps = ["T1071"]  # MITRE v6,7,8
    ttps += ["T1071.001"]  # MITRE v7,8
    mbcs = ["OC0006", "C0002"]  # micro-behaviour

    filter_apinames = set(
        [
            "HttpOpenRequestA",
            "HttpOpenRequestW",
            "InternetConnectA",
            "InternetConnectW",
            "WinHttpGetProxyForUrl",
            "InternetOpenUrlW",
            "InternetOpenUrlA",
        ]
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.request = dict()
        self.lasthost = str()
        self.urls = set()

    def on_call(self, call, process):
        if call["api"].startswith("InternetConnect"):
            host = self.get_argument(call, "ServerName")
            port = self.get_argument(call, "ServerPort")
            self.lasthost = host
            if host in domain_passlist:
                return None
            if host not in self.request:
                self.request[host] = dict()
                self.request[host]["uris"] = list()
            self.request[host]["curhandle"] = str(call["return"])
            self.request[host]["port"] = port
        elif call["api"].startswith("HttpOpenRequest"):
            handle = str(self.get_argument(call, "InternetHandle"))
            # Sanity check
            if self.lasthost in domain_passlist:
                return None
            if handle == self.request[self.lasthost]["curhandle"]:
                uri = self.get_argument(call, "Path")
                if uri != "/" and uri != "":
                    self.request[self.lasthost]["uris"].append(uri)
                    self.request[self.lasthost]["curhandle"] = call["return"]
        elif call["api"] == "WinHttpGetProxyForUrl":
            url = self.get_argument(call, "Url")
            if url:
                for wlhost in domain_passlist:
                    self.urls.add(url)
                    if self.pid:
                        self.mark_call()
        elif call["api"].startswith("InternetOpenUrl"):
            url = self.get_argument(call, "URL")
            if url:
                for wlhost in domain_passlist:
                    self.urls.add(url)
                    if self.pid:
                        self.mark_call()

    def on_complete(self):
        ret = False
        # Parse to create self.data
        for host in self.request.keys():
            for uri in self.request[host]["uris"]:
                self.data.append({"url": "{}:{}/{}".format(host, self.request[host]["port"], uri)})

        for url in self.urls:
            self.data.append({"url": url})

        if len(self.data) > 0:
            ret = True

        return ret
