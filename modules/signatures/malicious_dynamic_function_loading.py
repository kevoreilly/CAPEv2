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

class malicious_dynamic_function_loading(Signature):
    name = "malicious_dynamic_function_loading"
    description = "Possible malicious dynamic function loading detected"
    severity = 1
    categories = ["malware"]
    authors = ["redsand"]
    minimum = "1.3"
    evented = True
    malicious_functions = [ "LookupAccountNameLocalW", "LookupAccountNameLocalA", "LookupAccountSidW", "LookupAccountSidA",
			    "LookupAccountSidLocalW", "LookupAccountSidLocalA", "CoTaskMemAlloc", "CoTaskMemFree", 
			    "LookupAccountNameW", "LookupAccountNameA", "NetLocalGroupGetMembers", "SamConnect", "SamLookupNamesInDomain",
			    "OpenProcessToken", "SetThreadToken", "DuplicateTokenEx", "AdjustTokenPrivileges", "OpenThreadToken"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.dll_loaded = False
        self.loadctr = 0
        self.list = [ ]

    filter_apinames = set(["LdrGetProcedureAddress", "LdrLoadDll"])

    def on_call(self, call, process):
        if call["api"] == "LdrLoadDll":
            self.dll_loaded = True
        elif self.dll_loaded and call["api"] == "LdrGetProcedureAddress":
            arg = self.get_argument(call, "FunctionName")
            if arg in self.malicious_functions:
                self.data.append({"SuspiciousDynamicFunction" : "%s/%s" % (self.get_argument(call, "ModuleName"), self.get_argument(call, "FunctionName")) })

    def on_complete(self):
        if self.loadctr > 0:
            return True

