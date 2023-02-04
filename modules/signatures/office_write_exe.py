# Copyright (C) 2015 Will Metcalf william.metcalf@gmail.com
#
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature

try:
    import re2 as re
except ImportError:
    import re


class OfficeWriteEXE(Signature):
    name = "office_write_exe"
    description = "An office file wrote an executable file to disk"
    severity = 3
    categories = ["virus"]
    authors = ["Will Metcalf"]
    minimum = "1.2"
    evented = True
    ttps = ["T1137"]  # MITRE v6,7,8
    mbcs = ["OC0001", "C0016"]  # micro-behaviour

    filter_apinames = set(["NtWriteFile"])
    filter_analysistypes = set(["file"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.data = []
        self.exere = re.compile(r"\.exe$")
        self.office_proc_list = ["wordview.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"]

    def on_call(self, call, process):
        pname = process["process_name"].lower()
        if pname in self.office_proc_list:
            if call["api"] == "NtWriteFile":
                buff = self.get_raw_argument(call, "Buffer")
                if buff and len(buff) > 2 and buff[0:1] == "MZ" and "This program" in buff:
                    self.data.append({"office_dl_write_exe": "%s_NtWriteFile_%s" % (pname, self.get_argument(call, "HandleName"))})
                    if self.pid:
                        self.mark_call()

        return None

    def on_complete(self):
        if self.data:
            return True

        return False
