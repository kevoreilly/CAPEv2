# Copyright (C) 2014 Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.abstracts import Signature


class Bootkit(Signature):
    name = "bootkit"
    description = "Likely installs a bootkit via raw harddisk modifications"
    severity = 3
    categories = ["rootkit"]
    authors = ["Optiv"]
    minimum = "1.2"
    evented = True
    ttps = ["T1067"]  # MITRE v6
    ttps += ["T1542", "T1542.003"]  # MITRE v7,8
    mbcs = ["OB0006", "F0013"]

    filter_apinames = set(
        [
            "NtCreateFile",
            "NtDuplicateObject",
            "NtOpenFile",
            "NtClose",
            "NtSetInformationFile",
            "NtWriteFile",
            "DeviceIoControl",
            "NtDeviceIoControlFile",
        ]
    )

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = 0
        self.handles = dict()
        self.saw_stealth = False

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
            if (
                filename
                and (filename.lower() == "\\??\\physicaldrive0" or filename.lower().startswith("\\device\\harddisk"))
                and access & 0x40000002
            ):
                if handle not in self.handles:
                    self.handles[handle] = filename
        elif call["api"] == "DeviceIoControl" or call["api"] == "NtDeviceIoControlFile":
            ioctl = int(self.get_argument(call, "IoControlCode"), 16)
            if call["api"] == "DeviceIoControl":
                handle = int(self.get_argument(call, "DeviceHandle"), 16)
            else:
                handle = int(self.get_argument(call, "FileHandle"), 16)
            # IOCTL_SCSI_PASS_THROUGH_DIRECT
            if handle in self.handles and ioctl == 0x4D014:
                if self.pid:
                    self.mark_call()
                return True
        elif call["api"] == "NtWriteFile":
            handle = int(self.get_argument(call, "FileHandle"), 16)
            if handle in self.handles:
                if self.pid:
                    self.mark_call()
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
    ttps = ["T1067"]  # MITRE v6
    ttps += ["T1014"]  # MITRE v6,7,8
    ttps += ["T1542", "T1542.003"]  # MITRE v7,8
    mbcs = ["OB0006", "E1014", "F0013"]

    def run(self):
        ret = False
        match = self.check_write_file(pattern="^\\\\Device\\\\HarddiskVolume.*", regex=True)
        if match:
            self.data.append({"file": match})
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
    ttps = ["T1067"]  # MITRE v6
    ttps += ["T1014"]  # MITRE v6,7,8
    ttps += ["T1542", "T1542.003"]  # MITRE v7,8
    mbcs = ["OB0006", "E1014", "F0013"]

    def run(self):
        ret = False
        match = self.check_write_file(pattern="^\\\\Device\\\\HarddiskVolume0\\\\DR0$", regex=True)
        if match:
            self.data.append({"file": match})
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
    ttps = ["T1067"]  # MITRE v6
    ttps += ["T1014"]  # MITRE v6,7,8
    ttps += ["T1542", "T1542.003"]  # MITRE v7,8
    mbcs = ["OB0006", "E1014", "F0013"]

    def run(self):
        ret = False
        match = self.check_write_file(pattern="^\\\\\?\?\\\\PhysicalDrive.*", regex=True)
        if match:
            self.data.append({"physical drive access": match})
            ret = True

        return ret


class SuspiciousIoctlSCSIPassthough(Signature):
    name = "suspicious_ioctl_scsipassthough"
    description = "Uses IOCTL_SCSI_PASS_THROUGH control codes to manipulate drive/MBR which may be indicative of a bootkit"
    severity = 3
    categories = ["bootkit", "rootkit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1067"]  # MITRE v6
    ttps += ["T1542", "T1542.003"]  # MITRE v7,8
    mbcs = ["OB0006", "F0013"]
    references = ["http://www.ioctls.net/"]

    filter_apinames = set(["DeviceIoControl", "NtDeviceIoControlFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.pnames = []
        self.ret = False

    def on_call(self, call, process):
        ioctl = self.get_argument(call, "IoControlCode")
        if ioctl == "0x0004d004" or ioctl == "0x0004d014":
            pname = process["process_name"]
            if pname not in self.pnames:
                self.pnames.append(pname)
                self.data.append(
                    {
                        "suspicious_deviceiocontrol_ioctl_use": "%s is using the IOCTL_SCSI_PASS_THROUGH or IOCTL_SCSI_PASS_THROUGH_DIRECT control codes to make modifications"
                        % (pname)
                    }
                )
                self.ret = True
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        return self.ret


class PotentialOverWriteMBR(Signature):
    name = "potential_overwrite_mbr"
    description = "Wrote 512 bytes to physical drive potentially indicative of overwriting the Master Boot Record (MBR)"
    severity = 3
    categories = ["bootkit"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True
    ttps = ["T1067"]

    filter_apinames = set(["NtWriteFile"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.ret = False

    def on_call(self, call, process):
        if call["api"] == "NtWriteFile":
            filepath = self.get_raw_argument(call, "HandleName")
            writelength = self.get_raw_argument(call, "Length")
            if (
                filepath.lower() == "\\??\\physicaldrive0" or filepath.lower().startswith("\\device\\harddisk")
            ) and writelength == 512:
                self.data.append({"modified_drive": "%s" % (filepath)})
                self.ret = True
                if self.pid:
                    self.mark_call()

    def on_complete(self):
        return self.ret
