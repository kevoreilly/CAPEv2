# Copyright (C) 2015 KillerInstinct
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

class Internet_Dropper(Signature):
    name = "internet_dropper"
    description = "Behavior consistent with a dropper attempting to download the next stage."
    severity = 3
    categories = ["network"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.dropper = dict()
        self.lasthost = str()
        self.uris = set()

    # May need to expand this later (eg. InternetSetOption* for handle management)
    filter_apinames = set(["HttpOpenRequestA", "HttpOpenRequestW", "InternetConnectA",
                           "InternetConnectW"])

    def on_call(self, call, process):
        if call["api"].startswith("InternetConnect"):
            host = self.get_argument(call, "ServerName")
            self.lasthost = host
            if host not in self.dropper:
                self.dropper[host] = dict()
                self.dropper[host]["uris"] = list()
            self.dropper[host]["curhandle"] = str(call["return"])
        elif call["api"].startswith("HttpOpenRequest"):
            handle = str(self.get_argument(call, "InternetHandle"))
            # Sanity check
            if self.lasthost and handle == self.dropper[self.lasthost]["curhandle"]:
                uri = self.get_argument(call, "Path")
                if uri != "/" and uri != "":
                    self.uris.add(uri)
                    self.dropper[self.lasthost]["uris"].append(uri)
                    self.dropper[self.lasthost]["curhandle"] = call["return"]

    def on_complete(self):
        ret = False
        matched_uris = list()
        buf = dict()
        # Loop through collected URIs
        for uri in self.uris:
            count = 0
            # Count the different hosts it requested the URI from
            for host in self.dropper.keys():
                if uri in self.dropper[host]["uris"]:
                    count += 1
            # Log the URI if we saw it from multiple hosts
            if count > 1:
                matched_uris.append(uri)
        if matched_uris:
            for item in matched_uris:
                buf = {"uri": item, "hosts": list()}
                # Parse dropper again to grab info for self.data
                for host in self.dropper.keys():
                    if uri in self.dropper[host]["uris"]:
                        buf["hosts"].append(host)

        if "uri" in buf and "hosts" in buf and buf["uri"].endswith("/rdr/ENU/win/nooem/none/message.zip") and \
            set(["acroipm.adobe.com", "acroipm2.adobe.com"]) == set(buf["hosts"]):
            return False

        if "hosts" in buf and len(buf["hosts"]) > 1:
            ret = True
            self.data.append({"File": "%s was requested from hosts: %s" %
                                      (buf["uri"], ", ".join(buf["hosts"]))})

        return ret
