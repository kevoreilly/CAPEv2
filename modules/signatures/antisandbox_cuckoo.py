# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
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

class AntiCuckoo(Signature):
    name = "antisandbox_cuckoo"
    description = "Employs AntiCuckoo detection techniques"
    severity = 3
    weight = 3
    categories = ["anti-sandbox"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True

    filter_categories = set(["__notification__"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    def on_call(self, call, process):
        subcategory = self.check_argument_call(call,
                                               api="__anomaly__",
                                               name="Subcategory",
                                               pattern="anticuckoo")
        if subcategory:
            return True
