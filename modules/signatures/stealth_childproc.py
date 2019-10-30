# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class StealthChildProc(Signature):
    name = "stealth_childproc"
    description = "Forces a created process to be the child of an unrelated process"
    severity = 3
    confidence = 100
    categories = ["stealth"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    references = "https://www.countercept.com/blog/detecting-parent-pid-spoofing/"

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    filter_apinames = set(["NtCreateProcess","NtCreateProcessEx","RtlCreateUserProcess","CreateProcessInternalW"])

    def on_call(self, call, process):
        parenthandle = self.get_argument(call, "ParentHandle")
        pname = process["process_name"].lower()
        cmdline = self.get_argument(call, "CommandLine")
        if parenthandle and parenthandle != "0xffffffff" and parenthandle != "0xffffffffffffffff":
            self.ret = True
            self.data.append({"created_process": "Process %s has spoofed parent process with real parent process %s" % (cmdline,pname)})

    def on_complete(self):
        return self.ret
