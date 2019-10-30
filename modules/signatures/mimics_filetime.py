# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

try:
    import re2 as re
except ImportError:
    import re

import struct
from lib.cuckoo.common.abstracts import Signature

class HandleInfo:
    def __init__(self, handle, filename):
        self.handle = handle
        self.filename = filename
        self.createtime = 0
        self.lastaccesstime = 0
        self.lastwritetime = 0
        self.changetime = 0

    def __repr__(self):
        return "HandleInfo(%x)" % self.handle

    def __eq__(self, other):
        if isinstance(other, HandleInfo):
                return self.handle == other.handle
        else:
                return False

    def __ne__(self, other):
        return (not self.__eq__(other))

    def __hash__(self):
        return hash(self.__repr__())

    def set_file_times(self, buffer):
        crt, lat, lwt, cht = struct.unpack_from("QQQQ", buffer)
        if crt != 0:
            self.createtime = crt
        if lat != 0:
            self.lastaccesstime = lat
        if lwt != 0:
            self.lastwritetime = lwt
        if cht != 0:
            self.changetime = cht

    def check_file_times(self, other):
        if ((self.createtime != 0 and self.createtime == other.createtime) or
            (self.lastwritetime != 0 and self.lastwritetime == other.lastwritetime) or
            (self.changetime != 0 and self.changetime == other.changetime)):
                file = other.filename.lower()
                if re.match(r'^[A-Z]?:\\Windows\\.*', file, re.IGNORECASE) or "\\system32\\" in file or "\\syswow64\\" in file:
                        return other.filename
        return None

class MimicsFiletime(Signature):
    name = "mimics_filetime"
    description = "Mimics the file times of a Windows system file"
    severity = 3
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "1.0"
    evented = True

    BasicFileInformation = 4

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = 0
        self.handles = dict()
        self.old_handles = []
        self.saw_mimic = False
        self.mimics = set()

    filter_apinames = set(["NtOpenFile","NtCreateFile","NtClose","NtQueryInformationFile","NtSetInformationFile"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.handles = dict()
            self.old_handles = []
            self.lastprocess = process

        if (call["api"] == "NtOpenFile" or call["api"] == "NtCreateFile") and call["status"]:
            handle = int(self.get_argument(call, "FileHandle"), 16)
            filename = self.get_argument(call, "FileName")
            if handle not in self.handles:
                self.handles[handle] = HandleInfo(handle, filename)
        elif call["api"] == "NtClose":
            handle = int(self.get_argument(call, "Handle"), 16)
            try:
                self.old_handles.append(self.handles[handle])
                del self.handles[handle]
            except:
                        pass
        elif call["api"] == "NtQueryInformationFile":
            handle = int(self.get_argument(call, "FileHandle"), 16)
            querytype = int(self.get_argument(call, "FileInformationClass"), 10)
            if querytype == self.BasicFileInformation:
                try:
                    obj = self.handles[handle]
                    obj.set_file_times(self.get_raw_argument(call, "FileInformation"))
                except:
                    pass
        elif call["api"] == "NtSetInformationFile":
            handle = int(self.get_argument(call, "FileHandle"), 16)
            settype = int(self.get_argument(call, "FileInformationClass"), 10)
            if settype != self.BasicFileInformation:
                return None
            try:
                obj = self.handles[handle]
                obj.set_file_times(self.get_raw_argument(call, "FileInformation"))
            except:
                return None
            for val in self.handles.itervalues():
                filename = obj.check_file_times(val)
                if filename:
                    break
            if not filename:
                for val in self.old_handles:
                    filename = obj.check_file_times(val)
                    if filename:
                        break
            if filename and filename != obj.filename:
                # prevent a false-positive with IE as the destination
                if obj.filename.lower() == "c:\\program files\\internet explorer\\iexplore.exe":
                    return None
                self.mimics.add((filename, obj.filename))
                self.saw_mimic = True
        return None

    def on_complete(self):
        if self.saw_mimic:
            for mimic in self.mimics:
                self.data.append({"mimic_source" : mimic[0], "mimic_dest" : mimic[1]})
            return True
        return False