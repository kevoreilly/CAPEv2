# Copyright (C) 2016 KillerInstinct
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class InfostealerBrowserPassword(Signature):
    name = "infostealer_browser_password"
    description = "A process attempted to collect browser passwords"
    severity = 3
    categories = ["infostealer"]
    authors = ["KillerInstinct"]
    minimum = "1.2"
    evented = True
    ttps = ["T1081", "T1503"]  # MITRE v6
    ttps += ["T1003", "T1005"]  # MITRE v6,7,8
    ttps += ["T1552", "T1552.001", "T1555", "T1555.003"]  # MITRE v7,8
    mbcs = ["OB0005", "OC0003"]

    filter_apinames = set(["LdrGetProcedureAddress", "NtReadFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pidTrack = dict()
        self.readsSqlite = set()
        self.suspicious = [
            "PK11_CheckUserPassword",
            "PK11_Authenticate",
            "PK11SDR_Decrypt",
        ]

    def on_call(self, call, process):
        if call["api"] == "LdrGetProcedureAddress":
            api = self.get_argument(call, "FunctionName")
            if api:
                pid = process["process_id"]
                if api in self.suspicious:
                    if pid not in self.pidTrack:
                        self.pidTrack[pid] = set()
                    self.pidTrack[pid].add(api)
                    if self.pid:
                        self.mark_call()
                # Check using 'in' to cover the varients of .*sqlite3_prepare.*
                # which apparently changes based on the dll you load from
                elif "sqlite3_prepare" in api:
                    if pid not in self.pidTrack:
                        self.pidTrack[pid] = set()
                    self.pidTrack[pid].add("sqlite3_prepare")
                    if self.pid:
                        self.mark_call()

        elif call["api"] == "NtReadFile":
            buf = self.get_argument(call, "Buffer")
            if buf and "sqlite format" in buf.lower():
                self.readsSqlite.add(process["process_id"])
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        ret = False
        for pid in self.pidTrack:
            if len(self.pidTrack[pid]) == 4:
                if pid in self.readsSqlite:
                    ret = True
                    self.data.append({"process": "{0} ({1})".format(self.get_name_from_pid(str(pid)), pid)})

        return ret
