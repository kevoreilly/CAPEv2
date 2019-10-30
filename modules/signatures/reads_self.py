# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import struct
from lib.cuckoo.common.abstracts import Signature

class HandleInfo:
    def __init__(self, handle, filename):
        self.handle = handle
        self.filename = filename
        self.fpos = 0
        self.performed_read = False

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

    def set_file_pos(self, buffer):
        self.fpos = struct.unpack_from("Q", buffer)[0]

    def read(self, len):
        self.fpos = self.fpos + len

class ProcResults:
    def __init__(self, process):
        self.process = process
        self.handles = dict()
        self.old_handles = []
        self.reads = []

    def merge_reads(self):
        # cheap implementation, just merges typical linear accesses broke up into chunks
        outlist = []
        slist = sorted(self.reads)
        laststart = slist[0][0]
        for i, read in enumerate(slist):
            if i == len(slist) - 1:
                outlist.append((laststart, read[1]))
            elif read[1] != slist[i+1][0]:
                    outlist.append((laststart, read[1]))
                    laststart = slist[i+1][0]
        return outlist

    def add_handle(self, handle, filename):
        if handle not in self.handles:
            self.handles[handle] = HandleInfo(handle, filename)

    def close_handle(self, handle):
        if handle in self.handles:
            self.old_handles.append(self.handles[handle])
            del self.handles[handle]

class ReadsSelf(Signature):
    name = "reads_self"
    description = "Reads data out of its own binary image"
    severity = 2
    confidence = 30
    categories = ["generic"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True

    filter_analysistypes = set(["file"])

    FilePositionInformation = 14

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = 0
        self.lastres = None
        self.processes = []
        self.is_office = False
        office_pkgs = ["ppt","doc","xls","eml","js"]
        if any(e in self.results["info"]["package"] for e in office_pkgs):
            self.is_office = True


    filter_apinames = set(["NtOpenFile","NtCreateFile","NtClose","NtReadFile","NtSetInformationFile"])

    def on_call(self, call, process):
        if self.is_office:
            return False

        if process is not self.lastprocess:
            self.lastprocess = process
            self.lastres = ProcResults(process)
            self.processes.append(self.lastres)

        if call["api"] == "NtOpenFile" or call["api"] == "NtCreateFile" and call["status"]:
            handle = int(self.get_argument(call, "FileHandle"), 16)
            filename = self.get_argument(call, "FileName")
            if filename.lower() == self.lastprocess["module_path"].lower():
                self.lastres.add_handle(handle, filename)
        elif call["api"] == "NtClose":
            handle = int(self.get_argument(call, "Handle"), 16)
            self.lastres.close_handle(handle)
        elif call["api"] == "NtReadFile" and call["status"]:
            handle = int(self.get_argument(call, "FileHandle"), 16)
            if handle in self.lastres.handles:
                obj = self.lastres.handles[handle]
                length = self.get_raw_argument(call, "Length")
                if (obj.fpos, obj.fpos + length) not in self.lastres.reads:
                    self.lastres.reads.append((obj.fpos, obj.fpos + length))
                obj.read(length)
        elif call["api"] == "NtSetInformationFile" and call["status"]:
            handle = int(self.get_argument(call, "FileHandle"), 16)
            settype = int(self.get_argument(call, "FileInformationClass"), 10)
            if settype == self.FilePositionInformation:
                if handle in self.lastres.handles:
                    obj = self.lastres.handles[handle]
                    obj.set_file_pos(self.get_raw_argument(call, "FileInformation"))

        return None

    def on_complete(self):
        performed_read = False
        for res in self.processes:
            if not res.reads:
                continue
            performed_read = True
            newreads = res.merge_reads()
            for read in newreads:
                self.data.append({"self_read" : "process: " + res.process["process_name"] + ", pid: " +
                    str(res.process["process_id"]) + ", offset: " + "0x{0:08x}".format(read[0]) +
                    ", length: " + "0x{0:08x}".format(read[1] - read[0])})
        return performed_read