# Copyright (C) 2017 KillerInstinct
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

class Kelihos_APIs(Signature):
    name = "kelihos_behavior"
    description = "Exhibits behavior characteristic of Kelihos malware"
    weight = 3
    severity = 3
    categories = ["bot"]
    families = ["kelihos"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.config_key = str()
        self.peer_connect = set()
        self.socket_tracker = dict()
        self.bad_pid = 0

    filter_apinames = set(["RegSetValueExA", "connect", "ioctlsocket", "socket",
                           "setsockopt", "WSASocketA", "closesocket"])

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExA":
            buf = self.get_argument(call, "Buffer")
            if buf and buf.startswith(r"\xa2IM\xf3\xd9\x1e\x9f\x88\x01"):
                print "Check"
                self.bad_pid = process["process_id"]
                self.config_key = self.get_argument(call, "FullName")
                return None

        if self.bad_pid and process["process_id"] == self.bad_pid:
            if call["api"] in ["socket", "WSASocketA"] and call["return"]:
                created_socket = self.get_argument(call, "socket")
                self.socket_tracker[created_socket] = {
                    "has_cmd": False,
                    "sets_opt": False
                }

            elif call["api"] == "ioctlsocket":
                requested_socket = self.get_argument(call, "socket")
                if requested_socket in self.socket_tracker:
                    if "0x8004667e" == self.get_argument(call, "command"):
                        self.socket_tracker[requested_socket]["has_cmd"] = True

            elif call["api"] == "setsockopt":
                requested_socket = self.get_argument(call, "socket")
                if requested_socket in self.socket_tracker:
                    level = self.get_argument(call, "level")
                    optname = self.get_argument(call, "optname")
                    optval = self.get_argument(call, "optval")
                    if level == "0x00000006" and optname == "0x00000001" and optval == r"\x01\x00\x00\x00":
                        self.socket_tracker[requested_socket]["sets_opt"] = True

            elif call["api"] == "connect":
                requested_socket = self.get_argument(call, "socket")
                if requested_socket in self.socket_tracker:
                    if self.socket_tracker[requested_socket]["has_cmd"]:
                        if self.socket_tracker[requested_socket]["sets_opt"]:
                            ip = self.get_argument(call, "ip")
                            port = self.get_argument(call, "port")
                            self.peer_connect.add("{0}:{1}".format(ip, port))

            elif call["api"] == "closesocket":
                requested_socket = self.get_argument(call, "socket")
                if requested_socket in self.socket_tracker:
                    del self.socket_tracker[requested_socket]

        return None

    def on_complete(self):
        if self.config_key:
            self.data.append({"ConfigLocation": self.config_key})
            if self.peer_connect:
                for peer in self.peer_connect:
                    self.data.append({"C2": peer})

            return True

        return False
