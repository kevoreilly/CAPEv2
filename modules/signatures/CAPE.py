# CAPE - Config And Payload Extraction
# Copyright(C) 2015 - 2018 Context Information Security. (kevin.oreilly@contextis.com)
#
# This program is free software : you can redistribute it and / or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.If not, see <http://www.gnu.org/licenses/>.

import struct
from lib.cuckoo.common.abstracts import Signature

IMAGE_DOS_SIGNATURE                 = 0x5A4D
IMAGE_NT_SIGNATURE                  = 0x00004550
OPTIONAL_HEADER_MAGIC_PE            = 0x10b
OPTIONAL_HEADER_MAGIC_PE_PLUS       = 0x20b
IMAGE_FILE_EXECUTABLE_IMAGE         = 0x0002
IMAGE_FILE_MACHINE_I386             = 0x014c
IMAGE_FILE_MACHINE_AMD64            = 0x8664
DOS_HEADER_LIMIT                    = 0x40
PE_HEADER_LIMIT                     = 0x200

EXECUTABLE_FLAGS                    = 0x10 | 0x20 | 0x40 | 0x80
EXTRACTION_MIN_SIZE                 = 0x1001

PLUGX_SIGNATURE                     = 0x5658

def IsPEImage(buf, size):
    if not size:
        return False
    if size < DOS_HEADER_LIMIT:
        return False
    buf = buf.encode("utf-8")
    dos_header = buf[:DOS_HEADER_LIMIT]
    nt_headers = None

    if size < PE_HEADER_LIMIT:
        return False

    # Check for sane value in e_lfanew
    e_lfanew, = struct.unpack("<L", dos_header[60:64])
    if not e_lfanew or e_lfanew > PE_HEADER_LIMIT:
        offset = 0
        while offset < PE_HEADER_LIMIT-86:
            #ToDo
            machine_probe = struct.unpack("<H", buf[offset:offset+2])[0]
            if machine_probe == IMAGE_FILE_MACHINE_I386 or machine_probe == IMAGE_FILE_MACHINE_AMD64:
                nt_headers = buf[offset-4:offset+252]
                break
            offset = offset + 2
    else:
        nt_headers = buf[e_lfanew:e_lfanew+256]

    if nt_headers is None:
        return False

    #if ((pNtHeader->FileHeader.Machine == 0) || (pNtHeader->FileHeader.SizeOfOptionalHeader == 0 || pNtHeader->OptionalHeader.SizeOfHeaders == 0))
    if struct.unpack("<H", nt_headers[4:6]) == 0 or struct.unpack("<H", nt_headers[20:22]) == 0 or struct.unpack("<H", nt_headers[84:86]) == 0:
        return False

    #if (!(pNtHeader->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
    if (struct.unpack("<H", nt_headers[22:24])[0] & IMAGE_FILE_EXECUTABLE_IMAGE) == 0:
        return False

    #if (pNtHeader->FileHeader.SizeOfOptionalHeader & (sizeof (ULONG_PTR) - 1))
    if struct.unpack("<H", nt_headers[20:22])[0] & 3 != 0:
        return False

    #if ((pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) && (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    if struct.unpack("<H", nt_headers[24:26])[0] != OPTIONAL_HEADER_MAGIC_PE and struct.unpack("<H", nt_headers[24:26])[0] != OPTIONAL_HEADER_MAGIC_PE_PLUS:
        return False

    # To pass the above tests it should now be safe to assume it's a PE image
    return True

class CAPE_Compression(Signature):
    name = "Compression"
    description = "Behavioural detection: Decompression of executable module(s)."
    severity = 1
    categories = ["malware"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RtlDecompressBuffer"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.compressed_binary = False

    def on_call(self, call, process):
        if call["api"] == "RtlDecompressBuffer":
            buf = self.get_raw_argument(call, "UncompressedBuffer")
            size = int(self.get_raw_argument(call, "UncompressedBufferLength"), 0)
            self.compressed_binary = IsPEImage(buf, size)

    def on_complete(self):
        if self.compressed_binary is True:
            return True

class CAPE_RegBinary(Signature):
    name = "RegBinary"
    description = "Behavioural detection: PE binary written to registry."
    severity = 3
    categories = ["malware"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.reg_binary = False

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExA" or call["api"] == "RegSetValueExW":
            buf = self.get_raw_argument(call, "Buffer")
            size = self.get_raw_argument(call, "BufferLength")
            self.reg_binary = IsPEImage(buf, size)

    def on_complete(self):
        if self.reg_binary is True:
            return True

class CAPE_Decryption(Signature):
    name = "Decryption"
    description = "Behavioural detection: Decryption of executable module(s)."
    severity = 1
    categories = ["malware"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["CryptDecrypt"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.encrypted_binary = False

    def on_call(self, call, process):
        if call["api"] == "CryptDecrypt":
            buf = self.get_raw_argument(call, "Buffer")
            size = self.get_raw_argument(call, "Length")
            self.encrypted_binary = IsPEImage(buf, size)

    def on_complete(self):
        if self.encrypted_binary is True:
            return True

class CAPE_RegBinary(Signature):
    name = "RegBinary"
    description = "Behavioural detection: PE binary written to registry."
    severity = 1
    categories = ["malware"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.reg_binary = False

    def on_call(self, call, process):
        if call["api"] == "RegSetValueExA" or call["api"] == "RegSetValueExW":
            buf = self.get_raw_argument(call, "Buffer")
            size = self.get_raw_argument(call, "BufferLength")
            self.reg_binary = IsPEImage(buf, size)

    def on_complete(self):
        if self.reg_binary is True:
            return True

class CAPE_Extraction(Signature):
    name = "Extraction"
    description = "Behavioural detection: Executable code extraction"
    severity = 1
    categories = ["allocation"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)

    filter_apinames = set(["NtAllocateVirtualMemory","NtProtectVirtualMemory","VirtualProtectEx"])

    def on_call(self, call, process):

        if process["process_name"] == "WINWORD.EXE" or process["process_name"] == "EXCEL.EXE" or process["process_name"] == "POWERPNT.EXE":
            return False
        if call["api"] == "NtAllocateVirtualMemory":
            protection = int(self.get_raw_argument(call, "Protection"), 0)
            regionsize = int(self.get_raw_argument(call, "RegionSize"), 0)
            handle = self.get_argument(call, "ProcessHandle")
            if handle == "0xffffffff" and protection & EXECUTABLE_FLAGS and regionsize >= EXTRACTION_MIN_SIZE:
                return True
        if call["api"] == "VirtualProtectEx":
            protection = int(self.get_raw_argument(call, "Protection"), 0)
            size = int(self.get_raw_argument(call, "Size"), 0)
            handle = self.get_argument(call, "ProcessHandle")
            if handle == "0xffffffff" and protection & EXECUTABLE_FLAGS and size >= EXTRACTION_MIN_SIZE:
                return True
        elif call["api"] == "NtProtectVirtualMemory":
            protection = int(self.get_raw_argument(call, "NewAccessProtection"), 0)
            size = int(self.get_raw_argument(call, "NumberOfBytesProtected"), 0)
            handle = self.get_argument(call, "ProcessHandle")
            if handle == "0xffffffff" and protection & EXECUTABLE_FLAGS and size >= EXTRACTION_MIN_SIZE:
                return True

class CAPE_InjectionCreateRemoteThread(Signature):
    name = "InjectionCreateRemoteThread"
    description = "Behavioural detection: Injection with CreateRemoteThread in a remote process"
    severity = 3
    categories = ["injection"]
    authors = ["JoseMi Holguin", "nex", "Optiv", "kevoreilly", "KillerInstinct"]
    minimum = "1.3"
    evented = True
    ttp = ["T1055"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None
        self.write_detected = False
        self.remote_thread = False

    filter_categories = set(["process","threading"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.process_handles = set()
            self.process_pids = set()
            self.lastprocess = process

        if call["api"] == "OpenProcess" and call["status"] is True:
            if self.get_argument(call, "ProcessId") != process["process_id"]:
                self.process_handles.add(call["return"])
                self.process_pids.add(self.get_argument(call, "ProcessId"))
        elif call["api"] == "NtOpenProcess" and call["status"] is True:
            if self.get_argument(call, "ProcessIdentifier") != process["process_id"]:
                self.process_handles.add(self.get_argument(call, "ProcessHandle"))
                self.process_pids.add(self.get_argument(call, "ProcessIdentifier"))
        elif call["api"] == "CreateProcessInternalW":
            if self.get_argument(call, "ProcessId") != process["process_id"]:
                self.process_handles.add(self.get_argument(call, "ProcessHandle"))
                self.process_pids.add(self.get_argument(call, "ProcessId"))
        elif (call["api"] == "NtMapViewOfSection"):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.write_detected = True
        elif (call["api"] == "VirtualAllocEx" or call["api"] == "NtAllocateVirtualMemory"):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.write_detected = True
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "NtWow64WriteVirtualMemory64" or call["api"] == "WriteProcessMemory"):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.write_detected = True
                addr = int(self.get_argument(call, "BaseAddress"), 16)
                buf = self.get_argument(call, "Buffer")
                if addr >= 0x7c900000 and addr < 0x80000000 and buf.startswith("\\xe9"):
                    self.description = "Code injection via WriteProcessMemory-modified NTDLL code in a remote process"
                    #procname = self.get_name_from_pid(self.handle_map[handle])
                    #desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["process_id"]),
                    #                                     procname, self.handle_map[handle])
                    self.data.append({"Injection": desc})
                    return True
        elif (call["api"] == "CreateRemoteThread" or call["api"].startswith("NtCreateThread") or call["api"].startswith("NtCreateThreadEx")):
            handle = self.get_argument(call, "ProcessHandle")
            if handle in self.process_handles:
                #procname = self.get_name_from_pid(self.handle_map[handle])
                #desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["process_id"]),
                #                                     procname, self.handle_map[handle])
                #self.data.append({"Injection": desc})
                self.remote_thread = True
        elif call["api"].startswith("NtQueueApcThread"):
            if str(self.get_argument(call, "ProcessId")) in self.process_pids:
                #self.description = "Code injection with NtQueueApcThread in a remote process"
                #desc = "{0}({1}) -> {2}({3})".format(self.lastprocess["process_name"], str(self.lastprocess["process_id"]),
                #                                     process["process_name"], str(process["process_id"]))
                #self.data.append({"Injection": desc})
                self.remote_thread = True

    def on_complete(self):
        if self.write_detected is True and self.remote_thread is True:
            return True

class CAPE_InjectionProcessHollowing(Signature):
    name = "InjectionProcessHollowing"
    description = "Behavioural detection: Injection (Process Hollowing)"
    severity = 3
    categories = ["injection"]
    authors = ["glysbaysb", "Optiv", "KillerInstinct"]
    minimum = "1.3"
    evented = True
    ttp = ["T1055", "T1093"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    filter_categories = set(["process","threading"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.sequence = 0
            self.process_handles = set()
            self.thread_handles = set()
            self.process_map = dict()
            self.thread_map = dict()
            self.lastprocess = process

        if call["api"] == "CreateProcessInternalW":
            phandle = self.get_argument(call, "ProcessHandle")
            thandle = self.get_argument(call, "ThreadHandle")
            pid = self.get_argument(call, "ProcessId")
            self.process_handles.add(phandle)
            self.process_map[phandle] = pid
            self.thread_handles.add(thandle)
            self.thread_map[thandle] = pid
        elif (call["api"] == "NtUnmapViewOfSection" or call["api"] == "NtAllocateVirtualMemory") and self.sequence == 0:
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.sequence = 1
        elif call["api"] == "NtGetContextThread" and self.sequence == 0:
           if self.get_argument(call, "ThreadHandle") in self.thread_handles:
                self.sequence = 1
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "NtWow64WriteVirtualMemory64" or call["api"] == "WriteProcessMemory" or call["api"] == "NtMapViewOfSection") and (self.sequence == 1 or self.sequence == 2):
            if self.get_argument(call, "ProcessHandle") in self.process_handles:
                self.sequence = self.sequence + 1
        elif (call["api"] == "NtSetContextThread") and (self.sequence == 1 or self.sequence == 2):
            if self.get_argument(call, "ThreadHandle") in self.thread_handles:
                self.sequence = self.sequence + 1
        elif call["api"] == "NtResumeThread" and (self.sequence == 2 or self.sequence == 3):
            handle = self.get_argument(call, "ThreadHandle")
            if handle in self.thread_handles:
                desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["process_id"]),
                                                     self.get_name_from_pid(self.thread_map[handle]), self.thread_map[handle])
                self.data.append({"Injection": desc})
                return True
        elif call["api"] == "NtResumeProcess" and (self.sequence == 2 or self.sequence == 3):
            handle = self.get_argument(call, "ProcessHandle")
            if handle in self.process_handles:
                desc = "{0}({1}) -> {2}({3})".format(process["process_name"], str(process["process_id"]),
                                                     self.get_name_from_pid(self.process_map[handle]), self.process_map[handle])
                self.data.append({"Injection": desc})
                return True

class CAPE_InjectionSetWindowLong(Signature):
    name = "InjectionSetWindowLong"
    description = "Behavioural detection: Injection with SetWindowLong in a remote process"
    severity = 3
    categories = ["injection"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True
    ttp = ["T1055", "T1181"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None
        self.sharedsections = ["\\basenamedobjects\\shimsharedmemory",
                                "\\basenamedobjects\\windows_shell_global_counters",
                                "\\basenamedobjects\\msctf.shared.sfm.mih",
                                "\\basenamedobjects\\msctf.shared.sfm.amf",
                                "\\basenamedobjects\\urlzonessm_administrator",
                                "\\basenamedobjects\\urlzonessm_system"]

    filter_apinames = set(["NtMapViewOfSection", "NtOpenSection", "NtCreateSection", "FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW", "PostMessageA", "PostMessageW", "SendNotifyMessageA", "SendNotifyMessageW", "SetWindowLongA", "SetWindowLongW", "SetWindowLongPtrA", "SetWindowLongPtrW"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.lastprocess = process
            self.window_handles = set()
            self.sharedmap = False
            self.windowfound = False

        if (call["api"] == ("NtMapViewOfSection")):
            handle = self.get_argument(call, "ProcessHandle")
            if handle != "0xffffffff":
                self.sharedmap = True
        elif call["api"] == "NtOpenSection" or call["api"] == "NtCreateSection":
            name = self.get_argument(call, "ObjectAttributes")
            if name.lower() in self.sharedsections:
                self.sharedmap = True
        elif call["api"].startswith("FindWindow") and call["status"] is True:
            self.windowfound = True
        elif call["api"].startswith("SetWindowLong") and call["status"] is True:
            if self.sharedmap is True and self.windowfound is True:
                return True

class CAPE_Injection(Signature):
    name = "InjectionInterProcess"
    description = "Behavioural detection: Injection (inter-process)"
    severity = 3
    categories = ["injection"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True
    ttp = ["T1055"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None
        self.process_handles = None
        self.write_handles = None
        self.injection_detected = False

    filter_categories = set(["process"])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            if self.process_handles:
                for handle in self.process_handles:
                    if handle in self.write_handles:
                        self.injection_detected = True
            self.process_handles = set()
            self.write_handles = set()
            self.lastprocess = process

        if call["api"] == "CreateProcessInternalW" or call["api"] == "OpenProcess" or call["api"] == "NtOpenProcess":
            phandle = self.get_argument(call, "ProcessHandle")
            self.process_handles.add(phandle)
        elif (call["api"] == "NtWriteVirtualMemory" or call["api"] == "NtWow64WriteVirtualMemory64" or call["api"] == "WriteProcessMemory" or call["api"] == "NtMapViewOfSection"):
            whandle = self.get_argument(call, "ProcessHandle")
            self.write_handles.add(whandle)

    def on_complete(self):
        if self.injection_detected is True:
            return True
        elif self.process_handles:
            for handle in self.process_handles:
                if handle in self.write_handles:
                    return True

class CAPE_EvilGrab(Signature):
    name = "EvilGrab"
    description = "Behavioural detection: EvilGrab"
    severity = 3
    categories = ["malware"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True
    ttp = ["T1219"]

    filter_apinames = set(["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.reg_evilgrab_keyname = False
        self.reg_binary = False

    def on_call(self, call, process):
        if call["api"] == "RegCreateKeyExA" or call["api"] == "RegCreateKeyExW":
            buf = self.get_argument(call, "SubKey")
            if buf == "Software\\rar":
                self.reg_evilgrab_keyname = True

        if call["api"] == "RegSetValueExA" or call["api"] == "RegSetValueExW":
            length = self.get_raw_argument(call, "BufferLength")
            if length and length > 0x10000 and self.reg_evilgrab_keyname is True:
                self.reg_binary = True

    def on_complete(self):
        if self.reg_binary is True:
            return True
        else:
            return False

class CAPE_PlugX(Signature):
    name = "PlugX"
    description = "Behavioural detection: PlugX"
    severity = 3
    categories = ["chinese", "malware"]
    families = ["plugx"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True
    ttp = ["T1219"]

    filter_apinames = set(["RtlDecompressBuffer", "memcpy"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.compressed_binary = False
        self.config_copy = False

    def on_call(self, call, process):
        if call["api"] == "RtlDecompressBuffer":
            dos_header = self.get_raw_argument(call, "UncompressedBuffer")[:2]
            #IMAGE_DOS_SIGNATURE or PLUGX_SIGNATURE
            if dos_header in ("MZ", "VX"):
                self.compressed_binary = True

        if call["api"] == "memcpy":
            count = self.get_raw_argument(call, "count")
            if count in (0xae4, 0xbe4, 0x150c, 0x1510, 0x1516, 0x170c, 0x1b18, 0x1d18, 0x2540, 0x254c, 0x2d58, 0x36a4, 0x4ea4):
                self.config_copy = True

    def on_complete(self):
        if self.config_copy is True and self.compressed_binary is True:
            return True

class CAPE_Doppelganging(Signature):
    name = "Doppelganging"
    description = "Behavioural detection: Process Doppelganging"
    severity = 3
    categories = ["injection"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True
    ttp = ["T1055", "T1186"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.lastprocess = None

    filter_categories = set(["process", "thread", "filesystem",])

    def on_call(self, call, process):
        if process is not self.lastprocess:
            self.section_handles = set()
            self.lastprocess = process
            self.filehandle = None
            self.sectionhandle = None

        if call["api"] == "CreateFileTransactedA" or call["api"] == "CreateFileTransactedW":
            self.filehandle = self.get_argument(call, "FileHandle")
        elif call["api"] == "NtCreateSection":
            if self.filehandle and self.filehandle == self.get_argument(call, "FileHandle"):
                self.sectionhandle = self.get_argument(call, "SectionHandle")
        elif call["api"] == "NtCreateProcessEx":
            if self.get_argument(call, "SectionHandle") == self.sectionhandle:
                return True

class CAPE_TransactedHollowing(Signature):
    name = "TransactedHollowing"
    description = "Behavioural detection: Transacted Hollowing"
    severity = 3
    categories = ["injection"]
    authors = ["kevoreilly"]
    minimum = "1.3"
    evented = True
    ttp = ["T1055", "T1093"]

    filter_apinames = set(["RtlSetCurrentTransaction", "NtRollbackTransaction", "NtMapViewOfSection"])

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.transaction_set = False
        self.transaction_rollback = False
        self.transacted_hollowing = False

    def on_call(self, call, process):

        if call["api"] == "RtlSetCurrentTransaction":
            self.transaction_set = True

        if call["api"] == "NtRollbackTransaction":
            if self.transaction_set is True:
                self.transaction_rollback = True

        if (call["api"] == "NtMapViewOfSection"):
            handle = self.get_argument(call, "ProcessHandle")
            if handle != "0xffffffff" and self.transaction_rollback is True:
                self.transacted_hollowing = True

    def on_complete(self):
        if self.transacted_hollowing is True:
            return True

class CAPEDetectedThreat(Signature):
    name = "cape_detected_threat"
    description = "CAPE detected a specific malware threat"
    severity = 3
    categories = ["malware"]
    authors = ["Kevin Ross"]
    minimum = "1.3"
    evented = True

    def run(self):
        if self.results.get("detections", False):
            self.description = "CAPE detected the %s malware family" % self.results["detections"]
            return True

        return False
