# Copyright (C) 2020 doomedraven
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


class NetworkHTTPS(Signature):
    name = "https_urls"
    description = "HTTPS urls from behavior."
    severity = 2
    categories = ["network"]
    authors = ["doomedraven"]
    minimum = "1.2"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.urls = list()

    filter_apinames = set(["InternetOpenUrlA", "InternetOpenUrlW"])

    def on_call(self, call, process):
        if call["api"] in ("InternetOpenUrlA", "InternetOpenUrlW"):
            self.urls.append(self.get_argument(call, "URL"))

    def on_complete(self):
        ret = False
        print(self.urls)
        urls = list(set(self.urls))
        if urls:
            ret = True

        for url in urls:
            self.data.append({"URL": url})

        return ret
