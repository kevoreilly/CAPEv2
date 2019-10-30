# Copyright (C) 2016 KillerInstinct, Brad Spengler
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

class APISpamming(Signature):
    name = "api_spamming"
    description = "Attempts to repeatedly call a single API many times in order to delay analysis time"
    severity = 3
    categories = ["anti-analysis"]
    authors = ["KillerInstinct", "Brad Spengler"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.spam = dict()
        self.spam_limit = 10000
        self.processes = dict()
 
    def on_call(self, call, process):
        if call["repeated"] < self.spam_limit:
            return None
        pid = process["process_id"]
        if pid not in self.processes:
            self.processes[pid] = process
            self.spam[pid] = {}
        if call["api"] not in self.spam[pid]:
            self.spam[pid][call["api"]] = call["repeated"]
        else:
            self.spam[pid][call["api"]] += call["repeated"]

    def on_complete(self):
        spam_apis_whitelist = {
             "c:\\program files (x86)\\internet explorer\\iexplore.exe": ["NtQuerySystemTime", "GetSystemTimeAsFileTime", "GetSystemTime"],
             "c:\\program files\\internet explorer\\iexplore.exe": ["NtQuerySystemTime", "GetSystemTimeAsFileTime", "GetSystemTime"],
             "c:\\program files\\microsoft office\\office14\\winword.exe": ["GetLocalTime"],
             "c:\\program files (x86)\\microsoft office\\office14\\winword.exe": ["GetLocalTime"],
             "c:\\windows\\system32\\wbem\\wmiprvse.exe": ["GetSystemTimeAsFileTime"],
             "c:\\windows\\system32\\wscript.exe": ["GetLocalTime", "NtQuerySystemTime"],
        }
        ret = False
        for pid, apis in self.spam.iteritems():
            modulepathlower = self.processes[pid]["module_path"].lower()
            do_check = False
            if modulepathlower in spam_apis_whitelist:
                do_check = True
            for apiname, count in apis.iteritems():
                if not do_check or apiname not in spam_apis_whitelist[modulepathlower]:
                    self.data.append({"Spam": "{0} ({1}) called API {2} {3} times".format(
                            self.processes[pid]["process_name"], self.processes[pid]["process_id"], apiname, count)})
                    ret = True

        return ret
