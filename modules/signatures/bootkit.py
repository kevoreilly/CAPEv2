# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature
import struct

class Bootkit(Signature):
    name = "bootkit"
    description = "Likely installs a bootkit via raw harddisk modifications"
    severity = 3
    categories = ["rootkit"]
    authors = ["Optiv"]
    minimum = "1.2"
    ttp = ["T1067"]

    evented = True

    BasicFileInformation = 4

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = 0
        self.handles = dict()
        self.saw_stealth = False

    filter_apinames = set(["NtCreateFile", "NtDuplicateObject", "NtOpenFile", "NtClose", "NtSetInformationFile", "NtWriteFile", "DeviceIoControl", "NtDeviceIoControlFile"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.handles = dict()
            self.lastprocess = process

        if call["api"] == "NtDuplicateObject" and call["status"]:
            tgtarg = self.get_argument(call, "TargetHandle")
            if tgtarg:
                srchandle = int(self.get_argument(call, "SourceHandle"), 16)
                tgthandle = int(tgtarg, 16)
                if srchandle in self.handles:
                    self.handles[tgthandle] = self.handles[srchandle]
        elif call["api"] == "NtClose":
            handle = int(self.get_argument(call, "Handle"), 16)
            self.handles.pop(handle, None)
        elif (call["api"] == "NtCreateFile" or call["api"] == "NtOpenFile") and call["status"]:
            filename = self.get_argument(call, "FileName")
            handle = int(self.get_argument(call, "FileHandle"), 16)
            access = int(self.get_argument(call, "DesiredAccess"), 16)
            # FILE_WRITE_ACCESS or GENERIC_WRITE
            if filename and (filename.lower() == "\\??\\physicaldrive0" or filename.lower().startswith("\\device\\harddisk")) and access & 0x40000002:
                if handle not in self.handles:
                    self.handles[handle] = filename
        elif call["api"] == "DeviceIoControl" or call["api"] == "NtDeviceIoControlFile":
            ioctl = int(self.get_argument(call, "IoControlCode"), 16)
            if call["api"] == "DeviceIoControl":
                handle = int(self.get_argument(call, "DeviceHandle"), 16)
            else:
                handle = int(self.get_argument(call, "FileHandle"), 16) 
            # IOCTL_SCSI_PASS_THROUGH_DIRECT
            if handle in self.handles and ioctl == 0x4d014:
                return True
        elif call["api"] == "NtWriteFile":
            handle = int(self.get_argument(call, "FileHandle"), 16)
            if handle in self.handles:
                return True
        
        return None
    
class DirectHDDAccess(Signature):
    name = "direct_hdd_access"
    description = "Attempted to write to a harddisk volume"
    severity = 2
    categories = ["bootkit", "rootkit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1014", "T1067"]

    def run(self):
        ret = False
        match = self.check_write_file(pattern="^\\\\Device\\\\HarddiskVolume.*", regex=True)
        if match:
            self.data.append({"file" : match})
            ret = True

        return ret

class AccessesPrimaryPartition(Signature):
    name = "accesses_primary_patition"
    description = "Attempted to write to the primary disk partition"
    severity = 3
    categories = ["bootkit", "rootkit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1014", "T1067"]

    def run(self):
        ret = False
        match = self.check_write_file(pattern="^\\\\Device\\\\HarddiskVolume0\\\\DR0$", regex=True)
        if match:
            self.data.append({"file" : match})
            ret = True

        return ret

class PhysicalDriveAccess(Signature):
    name = "physical_drive_access"
    description = "Attempted to write directly to a physical drive"
    severity = 3
    categories = ["bootkit", "rootkit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttp = ["T1014", "T1067"]

    def run(self):
        ret = False
        match = self.check_write_file(pattern="^\\\\\?\?\\\\PhysicalDrive.*", regex=True)
        if match:
            self.data.append({"physical drive access" : match})
            ret = True

        return ret
