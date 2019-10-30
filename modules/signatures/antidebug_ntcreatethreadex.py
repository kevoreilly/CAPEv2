# CAPE - Config And Payload Extraction
# Copyright(C) 2018 redsand (redsand@redsand.net)
# 
# This program is free software : you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.If not, see <http://www.gnu.org/licenses/>.

from lib.cuckoo.common.abstracts import Signature

THREAD_CREATE_HIDE_FROM_DEBUGGER = 0x4

class antidebug_ntcreatethreadex(Signature):
    name = "antidebug_ntcreatethreadex"
    description = "NtCreateThreadEx: newly created thread hidden from debugger"
    severity = 2
    categories = ["anti-debug"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["NtCreateThreadEx"])

    def on_call(self, call, process):
        if call["api"] == "NtCreateThreadEx":
            ThreadCreationFlags = int(self.get_raw_argument(call, "CreateFlags"), 0)
            if ThreadCreationFlags & THREAD_CREATE_HIDE_FROM_DEBUGGER:
                return True
