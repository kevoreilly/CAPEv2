# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class InjectionExtension(Signature):
    name = "injection_needextension"
    description = "Attempted to execute a copy of itself but requires an .exe extension to work"
    severity = 3
    categories = ["injection"]
    authors = ["Optiv"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["CreateProcessInternalW"])

    def on_call(self, call, process):
        if call["status"] == False:
            procname = process["process_name"].lower()
            if procname.endswith(".exe") == False:
                procname += ".exe"
                apiarg1 = self.get_argument(call, "ApplicationName")
                apiarg2 = self.get_argument(call, "CommandLine")
                if apiarg1.endswith(procname) or apiarg2.endswith(procname):
                    createdpid = str(self.get_argument(call, "ProcessId"))
                    desc = "{0}({1}) -> {2}({3})".format(process["process_name"],
                        process["process_id"], self.get_name_from_pid(createdpid),
                        createdpid)
                    self.data.append({"Injection": desc})
                    return True
