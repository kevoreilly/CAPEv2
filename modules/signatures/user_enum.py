# Copyright (C) 2016 KillerInstinct
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

class UserEnum(Signature):
    name = "user_enum"
    description = "Enumerates user accounts on the system"
    weight = 2
    categories = ["recon"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.users = dict()

    filter_apinames = set(["NetUserGetInfo"])

    def on_call(self, call, process):
        if call["status"]:
            if call["api"] == "NetUserGetInfo":
                buf = self.get_argument(call, "UserName")
                if buf:
                    if process["process_id"] not in self.users.keys():
                        self.users[process["process_id"]] = set()
                    self.users[process["process_id"]].add(buf)
        return None

    def on_complete(self):
        ret = False
        for proc in self.users:
            if len(self.users[proc]) >= 3:
                ret = True
                self.data.append({"Process": "{0} ({1})".format(
                    self.get_name_from_pid(proc), proc)})

        return ret
