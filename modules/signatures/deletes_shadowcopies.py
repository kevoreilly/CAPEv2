# Copyright (C) 2015 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class DeletesShadowCopies(Signature):
    name = "deletes_shadow_copies"
    description = "Attempts to delete or modify volume shadow copies"
    severity = 3
    categories = ["ransomware"]
    authors = ["Optiv", "Zane C. Bowers-Hadley"]
    minimum = "1.2"
    evented = True
    ttps = ["T1490"]  # MITRE v6,7,8
    mbcs = ["OB0008", "F0014", "F0014.001"]

    filter_apinames = set(["CreateProcessInternalW", "ShellExecuteExW", "NtCreateUserProcess"])

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            cmdline = self.get_argument(call, "CommandLine").lower()
            if (
                "vssadmin" in cmdline
                and ("delete" in cmdline and "shadows" in cmdline)
                or ("resize" in cmdline and "shadowstorage" in cmdline)
            ):
                if self.pid:
                    self.mark_call()
                return True
            elif "wmic" in cmdline and "shadowcopy" in cmdline and "delete" in cmdline:
                if self.pid:
                    self.mark_call()
                return True
        elif call["api"] == "ShellExecuteExW":
            filepath = self.get_argument(call, "FilePath").lower()
            params = self.get_argument(call, "Parameters").lower()
            if (
                "vssadmin" in filepath
                and ("delete" in params and "shadows" in params)
                or ("resize" in params and "shadowstorage" in params)
            ):
                if self.pid:
                    self.mark_call()
                return True
            elif "wmic" in filepath and "shadowcopy" in params and "delete" in params:
                if self.pid:
                    self.mark_call()
                return True
        elif call["api"] == "NtCreateUserProcess":
            cmd_line = self.get_argument(call, "CommandLine").lower()
            if (
                "vssadmin" in cmd_line
                and ("delete" in cmd_line and "shadows" in cmd_line)
                or ("resize" in cmd_line and "shadowstorage" in cmd_line)
            ):
                if self.pid:
                    self.mark_call()
                return True
            elif "wmic" in cmd_line and "shadowcopy" in cmd_line and "delete" in cmd_line:
                if self.pid:
                    self.mark_call()
                return True
