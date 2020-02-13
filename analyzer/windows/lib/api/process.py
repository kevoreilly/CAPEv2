# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import sys
import logging
import random
import subprocess
import platform
import urllib.request, urllib.parse, urllib.error
import base64
from time import time
from ctypes import byref, c_ulong, create_string_buffer, create_unicode_buffer, c_int, sizeof
from shutil import copy

from lib.common.results import upload_to_host
from lib.common.constants import PIPE, PATHS, SHUTDOWN_MUTEX, TERMINATE_EVENT, LOGSERVER_PREFIX
from lib.common.constants import CAPEMON32_NAME, CAPEMON64_NAME, LOADER32_NAME, LOADER64_NAME
from lib.common.defines import ULONG_PTR
from lib.common.defines import KERNEL32, NTDLL, SYSTEM_INFO, STILL_ACTIVE
from lib.common.defines import THREAD_ALL_ACCESS, PROCESS_ALL_ACCESS, TH32CS_SNAPPROCESS
from lib.common.defines import STARTUPINFO, PROCESS_INFORMATION, PROCESSENTRY32
from lib.common.defines import CREATE_NEW_CONSOLE, CREATE_SUSPENDED
from lib.common.defines import MEM_RESERVE, MEM_COMMIT, PAGE_READWRITE
from lib.common.defines import MEMORY_BASIC_INFORMATION
from lib.common.defines import WAIT_TIMEOUT, EVENT_MODIFY_STATE
from lib.common.defines import MEM_IMAGE, MEM_MAPPED, MEM_PRIVATE
from lib.common.defines import GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING
from lib.common.errors import get_error_string
from lib.common.rand import random_string
from lib.core.config import Config
from lib.core.log import LogServer

INJECT_CREATEREMOTETHREAD = 0
INJECT_QUEUEUSERAPC       = 1

IOCTL_PID = 0x222008
IOCTL_CUCKOO_PATH = 0x22200C
PATH_KERNEL_DRIVER = "\\\\.\\DriverSSDT"

LOGSERVER_POOL = dict()
ATTEMPTED_APC_INJECTS = dict()
ATTEMPTED_THREAD_INJECTS = dict()

log = logging.getLogger(__name__)

def is_os_64bit():
    return platform.machine().endswith('64')

def get_referrer_url(interest):
    """Get a Google referrer URL
    @return: URL to be added to the analysis config
    """

    if "://" not in interest:
        return ""

    escapedurl = urllib.parse.quote(interest, '')
    itemidx = str(random.randint(1, 30))
    vedstr = "0CCEQfj" + base64.urlsafe_b64encode(random_string(random.randint(5, 8) * 3))
    eistr = base64.urlsafe_b64encode(random_string(12))
    usgstr = "AFQj" + base64.urlsafe_b64encode(random_string(12))
    referrer = "http://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd={0}&ved={1}&url={2}&ei={3}&usg={4}".format(itemidx, vedstr, escapedurl, eistr, usgstr)
    return referrer

class Process:
    """Windows process."""
    process_num = 0
    # This adds 1 up to 30 times of 20 minutes to the startup
    # time of the process, therefore bypassing anti-vm checks
    # which check whether the VM has only been up for <10 minutes.
    startup_time = random.randint(1, 30) * 20 * 60 * 1000

    def __init__(self, options={}, config=None, pid=0, h_process=0, thread_id=0, h_thread=0, suspended=False):
        """@param pid: PID.
        @param h_process: process handle.
        @param thread_id: thread id.
        @param h_thread: thread handle.
        """
        self.config = config
        self.options = options
        self.pid = pid
        self.h_process = h_process
        self.thread_id = thread_id
        self.h_thread = h_thread
        self.suspended = suspended
        self.system_info = SYSTEM_INFO()
        self.critical = False

    def __del__(self):
        """Close open handles."""
        if self.h_process and self.h_process != KERNEL32.GetCurrentProcess():
            KERNEL32.CloseHandle(self.h_process)
        if self.h_thread:
            KERNEL32.CloseHandle(self.h_thread)

    def get_system_info(self):
        """Get system information."""
        KERNEL32.GetSystemInfo(byref(self.system_info))

    def open(self):
        """Open a process and/or thread.
        @return: operation status.
        """
        ret = bool(self.pid or self.thread_id)
        if self.pid and not self.h_process:
            if self.pid == os.getpid():
                self.h_process = KERNEL32.GetCurrentProcess()
            else:
                self.h_process = KERNEL32.OpenProcess(PROCESS_ALL_ACCESS,
                                                      False,
                                                      self.pid)
            ret = True

        if self.thread_id and not self.h_thread:
            self.h_thread = KERNEL32.OpenThread(THREAD_ALL_ACCESS,
                                                False,
                                                self.thread_id)
            ret = True
        return ret

    def close(self):
        """Close any open handles.
        @return: operation status.
        """
        ret = bool(self.h_process or self.h_thread)
        NT_SUCCESS = lambda val: val >= 0

        if self.h_process:
            ret = NT_SUCCESS(KERNEL32.CloseHandle(self.h_process))
            self.h_process = None

        if self.h_thread:
            ret = NT_SUCCESS(KERNEL32.CloseHandle(self.h_thread))
            self.h_thread = None

        return ret

    def exit_code(self):
        """Get process exit code.
        @return: exit code value.
        """
        if not self.h_process:
            self.open()

        exit_code = c_ulong(0)
        KERNEL32.GetExitCodeProcess(self.h_process, byref(exit_code))

        return exit_code.value

    def get_filepath(self):
        """Get process image file path.
        @return: decoded file path.
        """
        if not self.h_process:
            self.open()

        NT_SUCCESS = lambda val: val >= 0

        pbi = create_string_buffer(530)
        size = c_int()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(self.h_process,
                                              27,
                                              byref(pbi),
                                              sizeof(pbi),
                                              byref(size))

        if NT_SUCCESS(ret) and size.value > 8:
            try:
                fbuf = pbi.raw[8:]
                fbuf = fbuf[:fbuf.find(b'\0\0')+1]
                return fbuf.decode('utf16', errors="ignore")
            except Exception as e:
                log.info(e)
                return ""

        return ""

    def is_alive(self):
        """Process is alive?
        @return: process status.
        """
        return self.exit_code() == STILL_ACTIVE

    def is_critical(self):
        """Determines if process is 'critical' or not, so we can prevent
           terminating it
        """
        if not self.h_process:
            self.open()

        NT_SUCCESS = lambda val: val >= 0

        val = c_ulong(0)
        retlen = c_ulong(0)
        ret = NTDLL.NtQueryInformationProcess(self.h_process, 29, byref(val), sizeof(val), byref(retlen))
        if NT_SUCCESS(ret) and val.value:
            return True
        return False

    def get_parent_pid(self):
        """Get the Parent Process ID."""
        if not self.h_process:
            self.open()

        NT_SUCCESS = lambda val: val >= 0

        pbi = (ULONG_PTR * 6)()
        size = c_ulong()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(self.h_process,
                                              0,
                                              byref(pbi),
                                              sizeof(pbi),
                                              byref(size))

        if NT_SUCCESS(ret) and size.value == sizeof(pbi):
            return pbi[5]

        return None

    def kernel_analyze(self):
        """zer0m0n kernel analysis
        """
        log.info("Starting kernel analysis")
        log.info("Installing driver")
        if is_os_64bit():
            sys_file = os.path.join(os.getcwd(), "dll", "zer0m0n_x64.sys")
        else:
            sys_file = os.path.join(os.getcwd(), "dll", "zer0m0n.sys")
        exe_file = os.path.join(os.getcwd(), "dll", "logs_dispatcher.exe")
        if not sys_file or not exe_file or not os.path.exists(sys_file) or not os.path.exists(exe_file):
                log.warning("No valid zer0m0n files to be used for process with pid %d, injection aborted", self.pid)
                return False

        exe_name = random_string(6)
        service_name = random_string(6)
        driver_name = random_string(6)
        inf_data = '[Version]\r\nSignature = "$Windows NT$"\r\nClass = "ActivityMonitor"\r\nClassGuid = {b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}\r\nProvider= %Prov%\r\nDriverVer = 22/01/2014,1.0.0.0\r\nCatalogFile = %DriverName%.cat\r\n[DestinationDirs]\r\nDefaultDestDir = 12\r\nMiniFilter.DriverFiles = 12\r\n[DefaultInstall]\r\nOptionDesc = %ServiceDescription%\r\nCopyFiles = MiniFilter.DriverFiles\r\n[DefaultInstall.Services]\r\nAddService = %ServiceName%,,MiniFilter.Service\r\n[DefaultUninstall]\r\nDelFiles = MiniFilter.DriverFiles\r\n[DefaultUninstall.Services]\r\nDelService = %ServiceName%,0x200\r\n[MiniFilter.Service]\r\nDisplayName= %ServiceName%\r\nDescription= %ServiceDescription%\r\nServiceBinary= %12%\\%DriverName%.sys\r\nDependencies = "FltMgr"\r\nServiceType = 2\r\nStartType = 3\r\nErrorControl = 1\r\nLoadOrderGroup = "FSFilter Activity Monitor"\r\nAddReg = MiniFilter.AddRegistry\r\n[MiniFilter.AddRegistry]\r\nHKR,,"DebugFlags",0x00010001 ,0x0\r\nHKR,"Instances","DefaultInstance",0x00000000,%DefaultInstance%\r\nHKR,"Instances\\"%Instance1.Name%,"Altitude",0x00000000,%Instance1.Altitude%\r\nHKR,"Instances\\"%Instance1.Name%,"Flags",0x00010001,%Instance1.Flags%\r\n[MiniFilter.DriverFiles]\r\n%DriverName%.sys\r\n[SourceDisksFiles]\r\n'+driver_name+'.sys = 1,,\r\n[SourceDisksNames]\r\n1 = %DiskId1%,,,\r\n[Strings]\r\n'+'Prov = "'+random_string(8)+'"\r\nServiceDescription = "'+random_string(12)+'"\r\nServiceName = "'+service_name+'"\r\nDriverName = "'+driver_name+'"\r\nDiskId1 = "'+service_name+' Device Installation Disk"\r\nDefaultInstance = "'+service_name+' Instance"\r\nInstance1.Name = "'+service_name+' Instance"\r\nInstance1.Altitude = "370050"\r\nInstance1.Flags = 0x0'

        new_inf = os.path.join(os.getcwd(), "dll", "{0}.inf".format(service_name))
        new_sys = os.path.join(os.getcwd(), "dll", "{0}.sys".format(driver_name))
        copy(sys_file, new_sys)
        new_exe = os.path.join(os.getcwd(), "dll", "{0}.exe".format(exe_name))
        copy(exe_file, new_exe)
        log.info("[-] Driver name : "+new_sys)
        log.info("[-] Inf name : "+new_inf)
        log.info("[-] Application name : "+new_exe)
        log.info("[-] Service : "+service_name)

        fh = open(new_inf,"w")
        fh.write(inf_data)
        fh.close()

        os_is_64bit = is_os_64bit()
        if os_is_64bit:
            wow64 = c_ulong(0)
            KERNEL32.Wow64DisableWow64FsRedirection(byref(wow64))

        os.system('cmd /c "rundll32 setupapi.dll, InstallHinfSection DefaultInstall 132 '+new_inf+'"')
        os.system("net start "+service_name)

        si = STARTUPINFO()
        si.cb = sizeof(si)
        pi = PROCESS_INFORMATION()
        cr = CREATE_NEW_CONSOLE

        ldp = KERNEL32.CreateProcessW(new_exe, None, None, None, None, cr, None, os.getenv("TEMP"), byref(si), byref(pi))
        if not ldp:
            if os_is_64bit:
                KERNEL32.Wow64RevertWow64FsRedirection(wow64)
            log.error("Failed starting "+exe_name+".exe.")
            return False

        config_path = os.path.join(os.getenv("TEMP"), "%s.ini" % self.pid)
        with open(config_path, "w") as config:
            cfg = Config("analysis.conf")

            config.write("host-ip={0}\n".format(cfg.ip))
            config.write("host-port={0}\n".format(cfg.port))
            config.write("pipe={0}\n".format(PIPE))

        log.info("Sending startup information")
        hFile = KERNEL32.CreateFileW(PATH_KERNEL_DRIVER, GENERIC_READ|GENERIC_WRITE,
                                    0, None, OPEN_EXISTING, 0, None)
        if os_is_64bit:
            KERNEL32.Wow64RevertWow64FsRedirection(wow64)
        if hFile:
            p = Process(pid=os.getpid())
            ppid = p.get_parent_pid()
            pid_vboxservice = 0
            pid_vboxtray = 0

            # get pid of VBoxService.exe and VBoxTray.exe
            proc_info = PROCESSENTRY32()
            proc_info.dwSize = sizeof(PROCESSENTRY32)

            snapshot = KERNEL32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            flag = KERNEL32.Process32First(snapshot, byref(proc_info))
            while flag:
                if proc_info.sz_exeFile == "VBoxService.exe":
                    log.info("VBoxService.exe found !")
                    pid_vboxservice = proc_info.th32ProcessID
                    flag = 0
                elif proc_info.sz_exeFile == "VBoxTray.exe":
                    pid_vboxtray = proc_info.th32ProcessID
                    log.info("VBoxTray.exe found !")
                    flag = 0
                flag = KERNEL32.Process32Next(snapshot, byref(proc_info))
            bytes_returned = c_ulong(0)
            msg = str(self.pid)+"_"+str(ppid)+"_"+str(os.getpid())+"_"+str(pi.dwProcessId)+"_"+str(pid_vboxservice)+"_"+str(pid_vboxtray)+'\0'
            KERNEL32.DeviceIoControl(hFile, IOCTL_PID, msg, len(msg), None, 0, byref(bytes_returned), None)
            msg = os.getcwd()+'\0'
            KERNEL32.DeviceIoControl(hFile, IOCTL_CUCKOO_PATH, str(msg, 'utf-8'), len(str(msg, 'utf-8')), None, 0, byref(bytes_returned), None)
        else:
            log.warning("Failed to access kernel driver")

        return True

    def execute(self, path, args=None, suspended=False, kernel_analysis=False):
        """Execute sample process.
        @param path: sample path.
        @param args: process args.
        @param suspended: is suspended.
        @return: operation status.
        """
        if not os.access(path, os.X_OK):
            log.error("Unable to access file at path \"%s\", "
                      "execution aborted", path)
            return False

        startup_info = STARTUPINFO()
        startup_info.cb = sizeof(startup_info)
        # STARTF_USESHOWWINDOW
        startup_info.dwFlags = 1
        # SW_SHOWNORMAL
        startup_info.wShowWindow = 1
        process_info = PROCESS_INFORMATION()

        arguments = "\"" + path + "\" "
        if args:
            arguments += args

        creation_flags = CREATE_NEW_CONSOLE
        if suspended:
            self.suspended = True
            creation_flags += CREATE_SUSPENDED

        created = KERNEL32.CreateProcessW(path,
                                          arguments,
                                          None,
                                          None,
                                          None,
                                          creation_flags,
                                          None,
                                          os.getenv("TEMP"),
                                          byref(startup_info),
                                          byref(process_info))

        if created:
            self.pid = process_info.dwProcessId
            self.h_process = process_info.hProcess
            self.thread_id = process_info.dwThreadId
            self.h_thread = process_info.hThread
            log.info("Successfully executed process from path \"%s\" with "
                     "arguments \"%s\" with pid %d", path, args or "", self.pid)
            if kernel_analysis:
                return self.kernel_analyze()
            return True
        else:
            log.error("Failed to execute process from path \"%s\" with "
                      "arguments \"%s\" (Error: %s)", path, args,
                      get_error_string(KERNEL32.GetLastError()))
            return False

    def resume(self):
        """Resume a suspended thread.
        @return: operation status.
        """
        if not self.suspended:
            log.warning("The process with pid %d was not suspended at creation"
                        % self.pid)
            return False

        if not self.h_thread:
            return False

        KERNEL32.Sleep(2000)

        if KERNEL32.ResumeThread(self.h_thread) != -1:
            self.suspended = False
            log.info("Successfully resumed process with pid %d", self.pid)
            return True
        else:
            log.error("Failed to resume process with pid %d", self.pid)
            return False

    def set_terminate_event(self):
        """Sets the termination event for the process.
        """
        if self.h_process == 0:
            self.open()

        event_name = TERMINATE_EVENT + str(self.pid)
        self.terminate_event_handle = KERNEL32.OpenEventW(EVENT_MODIFY_STATE, False, event_name)
        if self.terminate_event_handle:
            # make sure process is aware of the termination
            KERNEL32.SetEvent(self.terminate_event_handle)
            log.info("Terminate event set for process %d", self.pid)
            KERNEL32.CloseHandle(self.terminate_event_handle)
        else:
            log.error("Failed to open terminate event for pid %d", self.pid)
            return

        # recreate event for monitor 'reply'
        self.terminate_event_handle = KERNEL32.CreateEventW(0, False, False, event_name)
        if not self.terminate_event_handle:
            log.error("Failed to create terminate-reply event for process %d", self.pid)
            return

        KERNEL32.WaitForSingleObject(self.terminate_event_handle, 0xFFFFFFFF)
        log.info("Termination confirmed for process %d", self.pid)
        KERNEL32.CloseHandle(self.terminate_event_handle)
        return

    def terminate(self):
        """Terminate process.
        @return: operation status.
        """
        if self.h_process == 0:
            self.open()

        if KERNEL32.TerminateProcess(self.h_process, 1):
            log.info("Successfully terminated process with pid %d.", self.pid)
            return True
        else:
            log.error("Failed to terminate process with pid %d.", self.pid)
            return False

    def is_64bit(self):
        """Determines if a process is 64bit.
        @return: True if 64bit, False if not
        """
        if self.h_process == 0:
            self.open()

        try:
            val = c_int(0)
            ret = KERNEL32.IsWow64Process(self.h_process, byref(val))
            if ret and not val.value and is_os_64bit():
                return True
        except:
            pass

        return False

    def check_inject(self):
        if not self.pid:
            return False

        if self.thread_id or self.suspended:
            if (self.pid,self.thread_id) in ATTEMPTED_APC_INJECTS:
                return False
            ATTEMPTED_APC_INJECTS[(self.pid,self.thread_id)] = True
        else:
            if self.pid in ATTEMPTED_THREAD_INJECTS:
                return False
            ATTEMPTED_THREAD_INJECTS[self.pid] = True

        return True

    def write_monitor_config(self, interest=None, nosleepskip=False):

        config_path = "C:\\%s.ini" % self.pid

        with open(config_path, "w", encoding="utf-8") as config:
            # start the logserver for this monitored process
            logserver_path = LOGSERVER_PREFIX + str(self.pid)
            if logserver_path not in LOGSERVER_POOL:
                LOGSERVER_POOL[logserver_path] = LogServer(self.config.ip, self.config.port, logserver_path)

            Process.process_num += 1
            firstproc = Process.process_num == 1

            config.write("host-ip={0}\n".format(self.config.ip))
            config.write("host-port={0}\n".format(self.config.port))
            config.write("pipe={0}\n".format(PIPE))
            config.write("logserver={0}\n".format(logserver_path))
            config.write("results={0}\n".format(PATHS["root"]))
            config.write("analyzer={0}\n".format(os.getcwd()))
            config.write("pythonpath={0}\n".format(os.path.dirname(sys.executable)))
            config.write("first-process={0}\n".format("1" if firstproc else "0"))
            config.write("startup-time={0}\n".format(Process.startup_time))
            config.write("file-of-interest={0}\n".format(interest))
            config.write("shutdown-mutex={0}\n".format(SHUTDOWN_MUTEX))
            config.write("terminate-event={0}{1}\n".format(TERMINATE_EVENT, self.pid))

            if nosleepskip or ("force-sleepskip" not in self.options and len(interest) > 2 and interest[1] != ':' and interest[0] != '\\' and Process.process_num <= 2):
                config.write("force-sleepskip=0\n")

            if "norefer" not in self.options and "referrer" not in self.options:
                config.write("referrer={0}\n".format(get_referrer_url(interest)))

            server_options = [
                "disable_cape",
                "dll",
                "dll_64",
                "loader",
                "loader_64",
                "route",
                "nohuman",
                "unpack",
                "main_task_id",
            ]

            for optname, option in self.options.items():
                if optname not in server_options:
                    config.write("{0}={1}\n".format(optname, option))
                    log.info("Option '%s' with value '%s' sent to monitor", optname, option)

    def inject(self, injectmode=INJECT_QUEUEUSERAPC, interest=None, nosleepskip=False):
        """Cuckoo DLL injection.
        @param dll: Cuckoo DLL path.
        @param interest: path to file of interest, handed to cuckoomon config
        @param apc: APC use.
        """
        global LOGSERVER_POOL

        if not self.pid:
            return False

        thread_id = 0
        if self.thread_id:
            thread_id = self.thread_id

        if not self.is_alive():
            log.warning("The process with pid %s is not alive, "
                        "injection aborted", self.pid)
            return False

        is_64bit = self.is_64bit()

        if is_64bit:
            dll = CAPEMON64_NAME
        else:
            dll = CAPEMON32_NAME

        dll = os.path.join(os.getcwd(), dll)

        if not dll:
            log.warning("No DLL specified to be injected in process "
                        "with pid %d, injection aborted.", self.pid)
            return False

        if not os.path.exists(dll):
            log.warning("Invalid path %s for monitor DLL to be injected in process "
                        "with pid %d, injection aborted.", dll, self.pid)
            return False

        self.write_monitor_config(interest, nosleepskip)

        orig_bin_name = ""
        bit_str = ""
        if is_64bit:
            orig_bin_name = LOADER64_NAME
            bit_str = "64-bit"
        else:
            orig_bin_name = LOADER32_NAME
            bit_str = "32-bit"

        bin_name = os.path.join(os.getcwd(), orig_bin_name)

        log.info("%s DLL to inject is %s, loader %s", bit_str, dll, bin_name)

        if os.path.exists(bin_name):
            if thread_id or self.suspended:
                ret = subprocess.run([bin_name, "inject", str(self.pid), str(thread_id), dll, str(INJECT_QUEUEUSERAPC)])
            else:
                ret = subprocess.run([bin_name, "inject", str(self.pid), str(thread_id), dll, str(INJECT_CREATEREMOTETHREAD)])
            if ret.returncode != 0:
                if ret.returncode == 1:
                    log.info("Injected into suspended %s process with pid %d", bit_str, self.pid)
                else:
                    log.error("Unable to inject into %s process with pid %d, error: %d", bit_str, self.pid, ret.returncode)
                return False
            else:
                return True
        else:
            log.error("Please ensure the %s loader is in analyzer/windows/bin in order to analyze %s binaries.", bit_str, bit_str)
            return False

    def upload_memdump(self):
        """Upload process memory dump.
        @return: operation status.
        """
        if not self.pid:
            log.warning("No valid pid specified, memory dump cannot be uploaded")
            return False

        file_path = os.path.join(PATHS["memory"], "{0}.dmp".format(self.pid))
        try:
            file_path = os.path.join(PATHS["memory"], "{0}.dmp".format(self.pid))
            upload_to_host(file_path, os.path.join("memory", "{0}.dmp".format(self.pid)), category="memory")
        except Exception as e:
            print(e)
            log.error(e, exc_info=True)
            log.error(os.path.join("memory", "{0}.dmp".format(self.pid)), file_path)
        log.info("Memory dump of process %d uploaded", self.pid)

        return True


    def dump_memory(self):
        """Dump process memory.
        @return: operation status.
        """
        if not self.pid:
            log.warning("No valid pid specified, memory dump aborted")
            return False

        if not self.is_alive():
            log.warning("The process with pid %d is not alive, memory "
                        "dump aborted", self.pid)
            return False

        bin_name = ""
        bit_str = ""
        #file_path = os.path.join(PATHS["memory"], "{0}.dmp".format(self.pid))
        file_path = (os.path.join(PATHS["memory"], str(self.pid) + ".dmp"))
        if self.is_64bit():
            orig_bin_name = LOADER64_NAME
            bit_str = "64-bit"
        else:
            orig_bin_name = LOADER32_NAME
            bit_str = "32-bit"

        bin_name = os.path.join(os.getcwd(), orig_bin_name)

        if os.path.exists(bin_name):
            ret = subprocess.call([bin_name, "dump", str(self.pid), file_path])
            if ret == 1:
                log.info("Dumped %s process with pid %d", bit_str, self.pid)
            else:
                log.error("Unable to dump %s process with pid %d, error: %d", bit_str, self.pid, ret)
                return False
        else:
            log.error("Please place the %s binary from cuckoomon into analyzer/windows/bin in order to analyze %s binaries.", os.path.basename(bin_name), bit_str)
            return False

        try:
            file_path = os.path.join(PATHS["memory"], str(self.pid)+".dmp")
            upload_to_host(file_path, os.path.join("memory", str(self.pid)+".dmp"))
        except Exception as e:
            print(e)
            log.error(e, exc_info=True)
            log.error(os.path.join("memory", "{0}.dmp".format(self.pid)), file_path)

        log.info("Memory dump of process with pid %d completed", self.pid)

        return True
