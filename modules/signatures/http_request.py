#
# Based on internet_request.py by KillerInstinct
#

from lib.cuckoo.common.abstracts import Signature

class HTTP_Request(Signature):
    name = "http_request"
    description = "Performs HTTP requests potentially not found in PCAP."
    severity = 2
    categories = ["network"]
    authors = ["enzok"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.request = dict()
        self.lasthost = str()
        self.host_whitelist = ["acroipm.adobe.com",
                               "acroipm2.adobe.com",
                               "microsoft.com",
                               "apps.identrust.com"]

    filter_apinames = set(["HttpOpenRequestA", "HttpOpenRequestW", "InternetConnectA",
                           "InternetConnectW"])


    def on_call(self, call, process):
        if call["api"].startswith("InternetConnect"):
            host = self.get_argument(call, "ServerName")
            port = self.get_argument(call, "ServerPort")
            self.lasthost = host
            if host in self.host_whitelist:
                return None
            if host not in self.request:
                self.request[host] = dict()
                self.request[host]["uris"] = list()
            self.request[host]["curhandle"] = str(call["return"])
            self.request[host]["port"] = port
        elif call["api"].startswith("HttpOpenRequest"):
            handle = str(self.get_argument(call, "InternetHandle"))
            # Sanity check
            if self.lasthost in self.host_whitelist:
                return None
            if handle == self.request[self.lasthost]["curhandle"]:
                uri = self.get_argument(call, "Path")
                if uri != "/" and uri != "":
                    self.request[self.lasthost]["uris"].append(uri)
                    self.request[self.lasthost]["curhandle"] = call["return"]

    def on_complete(self):
        ret = False
        # Parse to create self.data
        for host in self.request.keys():
            for uri in self.request[host]["uris"]:
                self.data.append({"url": "{}:{}/{}".format(host, self.request[host]["port"], uri)})

        if len(self.data) > 0:
            ret = True

        return ret
