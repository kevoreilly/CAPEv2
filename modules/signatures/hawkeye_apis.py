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

try:
    import re2 as re
except:
    import re

from lib.cuckoo.common.abstracts import Signature


def unbuffered_b64decode(data):
    data = data.replace("\r", "").replace("\n", "")
    data += "=" * ((4 - len(data) % 4) % 4)
    try:
        data = data.decode("base64")
    except Exception as e:
        pass

    return data


class HawkEye_APIs(Signature):
    name = "hawkeye_behavior"
    description = "Exhibits behavior characteristics of HawkEye keylogger."
    severity = 3
    weight = 3
    categories = ["trojan", "keylogger"]
    families = ["HawkEye"]
    authors = ["KillerInstinct"]
    minimum = "1.3"
    evented = True
    ttps = ["T1056"]  # MITRE v6,7,8
    ttps += ["T1056.001"]  # MITRE v7,8
    mbcs = ["OB0003", "F0002"]

    filter_apinames = set(["send", "WSAConnect", "getaddrinfo", "NtCreateEvent", "NtCreateSection"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.badness = 0
        self.sockets = dict()
        self.lastcall = str()
        self.nodename = str()
        self.badsocks = set()
        self.keywords = [
            # SMTP Keywords
            "AUTH",
            "MAIL FROM",
            "RCPT TO",
            # FTP Keywords
            "USER",
        ]
        self.emailterms = [
            "hawkeye keylogger",
            "dear hawkeye customers",
            "dear invisiblesoft users",
        ]
        self.guidpat = "([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{13})\.\d+Event"
        self.evguid = str()
        self.evmatch = False

    def on_call(self, call, process):
        if call["api"] == "getaddrinfo":
            buf = self.get_argument(call, "NodeName")
            if buf:
                self.nodename = buf

        elif call["api"] == "WSAConnect":
            if self.lastcall == "getaddrinfo":
                sock = self.get_argument(call, "socket")
                ip = self.get_argument(call, "ip")
                port = self.get_argument(call, "port")
                if sock not in self.sockets.keys():
                    self.sockets[sock] = dict()
                    self.sockets[sock]["conn"] = "%s:%s" % (ip, port)
                    self.sockets[sock]["node"] = self.nodename
                    self.sockets[sock]["data"] = list()

        elif call["api"] == "send":
            sock = self.get_argument(call, "socket")
            if sock in self.sockets:
                buf = self.get_argument(call, "buffer")
                tmp = unbuffered_b64decode(buf)
                for term in self.emailterms:
                    if term in buf.lower() or term in tmp.lower():
                        self.badness += 10
                for word in self.keywords:
                    if buf.startswith(word):
                        self.sockets[sock]["data"].append(buf)
                        self.badsocks.add(sock)

        elif call["api"] == "NtCreateEvent":
            evname = self.get_argument(call, "EventName")
            check = re.match(self.guidpat, evname)
            if check:
                self.evguid = check.group(1)

        elif call["api"] == "NtCreateSection":
            if self.evguid:
                buf = self.get_argument(call, "ObjectAttributes")
                if self.evguid in buf:
                    self.evmatch = True
                    if self.pid:
                        self.mark_call()

        self.lastcall = call["api"]

    def on_complete(self):
        if self.check_file(pattern=".*\\\\pid.txt$", regex=True):
            self.badness += 2
        if self.check_file(pattern=".*\\\\pidloc.txt$", regex=True):
            self.badness += 2
        if self.check_file(pattern=".*\\\\holdermail.txt$", regex=True):
            self.badness += 4
        if self.check_file(pattern=".*\\\\holderwb.txt$", regex=True):
            self.badness += 4
        if self.evmatch:
            self.badness += 5
        if self.badness > 5:
            # Delete the non-malicious related sockets
            for sock in self.sockets.keys():
                if sock not in self.badsocks:
                    del self.sockets[sock]
            # Parse for indicators
            for sock in self.sockets.keys():
                ioc = {"Host": self.sockets[sock]["conn"]}
                if ioc not in self.data:
                    self.data.append(ioc)
                ioc = {"Hostname": self.sockets[sock]["node"]}
                if ioc not in self.data:
                    self.data.append(ioc)
                for item in self.sockets[sock]["data"]:
                    if "AUTH" in item:
                        buf = item.split()[2].decode("base64")
                        ioc = {"SMTP_Auth_Email": buf}
                        if ioc not in self.data:
                            self.data.append(ioc)
                    elif "MAIL FROM" in item:
                        buf = item.split(":")[1].strip()
                        ioc = {"SMTP_Mail_From": buf}
                        if ioc not in self.data:
                            self.data.append(ioc)
                    elif "RCPT TO" in item:
                        buf = item.split(":")[1].strip()
                        ioc = {"SMTP_Send_To": buf}
                        if ioc not in self.data:
                            self.data.append(ioc)
                    elif "USER" in item:
                        buf = item.split()[1].strip()
                        ioc = {"FTP_User": buf}
                        if ioc not in self.data:
                            self.data.append(ioc)

            return True

        return False
