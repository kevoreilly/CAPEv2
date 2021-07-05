# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
# TODO
#  https://github.com/cuckoosandbox/cuckoo/blob/ad5bf8939fb4b86d03c4d96014b174b8b56885e3/cuckoo/core/plugins.py#L29

from __future__ import absolute_import
import os
import sys
import socket
import struct
import pkgutil
import logging
import hashlib
import traceback
import subprocess
from ctypes import create_string_buffer, create_unicode_buffer, POINTER
from ctypes import c_wchar_p, byref, c_int, sizeof, cast, c_void_p, c_ulong, addressof

from threading import Lock, Thread
from datetime import datetime, timedelta
from shutil import copy
from urllib.parse import urlencode
from urllib.request import urlopen

from lib.common.rand import random_string
from lib.api.process import Process
from lib.common.abstracts import Package, Auxiliary
from lib.common.constants import PATHS, PIPE, SHUTDOWN_MUTEX, TERMINATE_EVENT, LOGSERVER_PREFIX
from lib.common.constants import CAPEMON32_NAME, CAPEMON64_NAME, LOADER32_NAME, LOADER64_NAME
from lib.common.defines import ADVAPI32, KERNEL32, NTDLL
from lib.common.defines import ERROR_MORE_DATA, ERROR_PIPE_CONNECTED
from lib.common.defines import PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE
from lib.common.defines import PIPE_READMODE_MESSAGE, PIPE_WAIT
from lib.common.defines import PIPE_UNLIMITED_INSTANCES, INVALID_HANDLE_VALUE
from lib.common.defines import SYSTEM_PROCESS_INFORMATION
from lib.common.defines import EVENT_MODIFY_STATE, SECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, SYSTEMTIME
from lib.common.exceptions import CuckooError, CuckooPackageError
from lib.common.hashing import hash_file
from lib.common.results import upload_to_host
from lib.core.config import Config
from lib.core.pipe import PipeServer, PipeForwarder, PipeDispatcher
from lib.core.pipe import disconnect_pipes
from lib.core.packages import choose_package
from lib.core.privileges import grant_debug_privilege
from lib.core.startup import create_folders, init_logging, disconnect_logger, set_clock
from modules import auxiliary

log = logging.getLogger()

INJECT_CREATEREMOTETHREAD = 0
INJECT_QUEUEUSERAPC = 1

BUFSIZE = 512
FILES_LIST_LOCK = Lock()
FILES_LIST = []
DUMPED_LIST = []
CAPE_DUMPED_LIST = []
PROC_DUMPED_LIST = []
UPLOADPATH_LIST = []
PROCESS_LIST = []
INJECT_LIST = []
PROTECTED_PATH_LIST = []
AUX_ENABLED = []
MONITOR_DLL = None
MONITOR_DLL_64 = None
LOADER32 = None
LOADER64 = None
ANALYSIS_TIMED_OUT = False

PID = os.getpid()
PPID = Process(pid=PID).get_parent_pid()
HIDE_PIDS = None


def pid_from_service_name(servicename):
    sc_handle = ADVAPI32.OpenSCManagerA(None, None, 0x0001)
    serv_handle = ADVAPI32.OpenServiceW(sc_handle, servicename, 0x0005)
    buf = create_string_buffer(36)
    needed = c_int(0)
    ADVAPI32.QueryServiceStatusEx(serv_handle, 0, buf, sizeof(buf), byref(needed))
    thepid = struct.unpack("IIIIIIIII", buf.raw)[7]
    ADVAPI32.CloseServiceHandle(serv_handle)
    ADVAPI32.CloseServiceHandle(sc_handle)
    return thepid


def in_protected_path(fname):
    """Checks file name against some protected names."""
    if not fname:
        return False

    fnamelower = fname.lower()

    for name in PROTECTED_PATH_LIST:
        if name[-1] == "\\" and fnamelower.startswith(name):
            return True
        elif fnamelower == name:
            return True

    return False


def add_pid_to_aux_modules(pid):
    for aux in AUX_ENABLED:
        try:
            aux.add_pid(pid)
        except:
            continue


def del_pid_from_aux_modules(pid):
    for aux in AUX_ENABLED:
        try:
            aux.del_pid(pid)
        except:
            continue


def add_protected_path(name):
    """Adds a pathname to the protected list"""
    if os.path.isdir(name) and name[-1] != b"\\":
        PROTECTED_PATH_LIST.append(name.lower() + b"\\")
    else:
        PROTECTED_PATH_LIST.append(name.lower())


def upload_files(folder):
    """Create a copy of the given file path."""
    log_folder = PATHS["root"] + "\\" + folder
    try:
        if os.path.exists(log_folder):
            log.info('Uploading files at path "%s" ', log_folder)
        else:
            log.warning('Folder at path "%s" does not exist, skip.', log_folder)
            return
    except IOError as e:
        log.warning('Unable to access folder at path "%s": %s', log_folder, e)
        return

    for root, dirs, files in os.walk(log_folder):
        for file in files:
            file_path = os.path.join(root, file)
            upload_path = os.path.join(folder, file)
            try:
                upload_to_host(file_path, upload_path, category=folder)
            except (IOError, socket.error) as e:
                log.error('Unable to upload file at path "%s": %s', file_path, e)


class Analyzer:
    """CAPE Windows Analyzer.

    This class handles the initialization and execution of the analysis
    procedure, including handling of the pipe server, the auxiliary modules and
    the analysis packages.
    """

    PIPE_SERVER_COUNT = 4

    def __init__(self):
        self.config = None
        self.target = None
        self.do_run = True
        self.time_counter = 0

        self.process_lock = Lock()
        self.files_list_lock = Lock()
        self.pid = os.getpid()
        self.ppid = Process(pid=self.pid).get_parent_pid()
        self.files = Files()
        self.process_list = ProcessList()
        self.package = None

        self.CRITICAL_PROCESS_LIST = []
        self.SERVICES_PID = None
        self.MONITORED_SERVICES = False
        self.MONITORED_WMI = False
        self.MONITORED_DCOM = False
        self.MONITORED_TASKSCHED = False
        self.MONITORED_BITS = False
        self.LASTINJECT_TIME = None
        self.NUM_INJECTED = 0

    def get_pipe_path(self, name):
        """Return \\\\.\\PIPE on Windows XP and \\??\\PIPE elsewhere."""
        version = sys.getwindowsversion()
        if version.major == 5 and version.minor == 1:
            return "\\\\.\\PIPE\\" + name
        return "\\??\\PIPE\\" + name

    def pids_from_process_name_list(self, namelist):
        proclist = []
        pidlist = []
        buf = create_unicode_buffer(1024 * 1024)
        p = cast(buf, c_void_p)
        retlen = c_ulong(0)
        retval = NTDLL.NtQuerySystemInformation(5, buf, 1024 * 1024, byref(retlen))
        if retval:
            return []
        proc = cast(p, POINTER(SYSTEM_PROCESS_INFORMATION)).contents
        while proc.NextEntryOffset:
            p.value += proc.NextEntryOffset
            proc = cast(p, POINTER(SYSTEM_PROCESS_INFORMATION)).contents
            # proclist.append((proc.ImageName.Buffer[:proc.ImageName.Length/2], proc.UniqueProcessId))
            proclist.append((proc.ImageName.Buffer, proc.UniqueProcessId))

        for proc in proclist:
            lowerproc = proc[0].lower()
            for name in namelist:
                if lowerproc == name:
                    pidlist.append(proc[1])
                    break
        return pidlist

    def prepare(self):
        """Prepare env for analysis."""
        global MONITOR_DLL
        global MONITOR_DLL_64
        # global SERVICES_PID
        global HIDE_PIDS

        # Get SeDebugPrivilege for the Python process. It will be needed in
        # order to perform the injections.
        grant_debug_privilege()
        # grant_privilege("SeLoadDriverPrivilege")

        # Create the folders used for storing the results.
        create_folders()

        add_protected_path(os.getcwd().encode("utf-8"))
        add_protected_path(PATHS["root"].encode("utf-8"))

        # Initialize logging.
        init_logging()

        # Parse the analysis configuration file generated by the agent.
        self.config = Config(cfg="analysis.conf")
        self.options = self.config.get_options()

        # Set the default DLL to be used for this analysis.
        self.default_dll = self.options.get("dll")

        # self.get_pipe_path(self.options.get("pipe", random_string(16, 32)))
        self.config.pipe = PIPE
        # Generate a random name for the logging pipe server.
        # self.get_pipe_path(random_string(16, 32))
        self.config.logpipe = LOGSERVER_PREFIX
        # Set virtual machine clock.
        set_clock(self.config.clock, self.config.timeout)

        # Set the DLL to be used by the PipeHandler.
        MONITOR_DLL = self.options.get("dll")
        MONITOR_DLL_64 = self.options.get("dll_64")

        # get PID for services.exe for monitoring services
        svcpid = self.pids_from_process_name_list(["services.exe"])
        if svcpid:
            self.SERVICES_PID = svcpid[0]
            self.config.services_pid = svcpid[0]
            self.CRITICAL_PROCESS_LIST.append(int(svcpid[0]))

        HIDE_PIDS = set(self.pids_from_process_name_list(self.files.PROTECTED_NAMES))

        # Initialize and start the Pipe Servers. This is going to be used for
        # communicating with the injected and monitored processes.

        self.command_pipe = PipeServer(PipeDispatcher, self.config.pipe, message=True, dispatcher=CommandPipeHandler(self))
        self.command_pipe.daemon = True
        self.command_pipe.start()

        # Initialize and start the Log Pipe Server - the log pipe server will
        # open up a pipe that monitored processes will use to send logs to
        # before they head off to the host machine.
        destination = self.config.ip, self.config.port
        self.log_pipe_server = PipeServer(PipeForwarder, self.config.logpipe, destination=destination)

        # We update the target according to its category. If it's a file, then
        # we store the path.
        if self.config.category == "file":
            self.target = os.path.join(os.environ["TEMP"] + os.sep, str(self.config.file_name))
        # If it's a URL, well.. we store the URL.
        else:
            self.target = self.config.target

    def stop(self):
        """Allow an auxiliary module to stop the analysis."""
        self.do_run = False

    def complete(self):
        """End analysis."""
        # Dump all the notified files.
        self.files.dump_files()

        # Copy the debugger log.
        upload_files("debugger")

        # TLS secrets (if any)
        upload_files("tlsdump")

        # Stop the Pipe Servers.
        if hasattr(self, "command_pipe"):
            self.command_pipe.stop()
        else:
            log.error("Analyzer object has no attribute 'command_pipe'")
        self.log_pipe_server.stop()

        # Cleanly close remaining connections
        disconnect_pipes()
        disconnect_logger()

        # Report missed injections
        for pid in INJECT_LIST:
            log.warning("Monitor injection attempted but failed for process %d.", pid)

        log.info("Analysis completed.")

    def get_completion_key(self):
        if hasattr(self.config, "completion_key"):
            return self.config.completion_key
        else:
            return ""

    def run(self):
        """Run analysis.
        @return: operation status.
        """
        global MONITOR_DLL
        global MONITOR_DLL_64
        global LOADER32
        global LOADER64
        global ANALYSIS_TIMED_OUT

        log.debug("Starting analyzer from: %s", os.getcwd())
        log.debug("Storing results at: %s", PATHS["root"])
        log.debug("Pipe server name: %s", PIPE)
        log.debug("Python path: %s", os.path.dirname(sys.executable))

        # If no analysis package was specified at submission, we try to select
        # one automatically.
        if not self.config.package:
            log.debug("No analysis package specified, trying to detect " "it automagically.")

            # If the analysis target is a file, we choose the package according
            # to the file format.
            if self.config.category == "file":
                package = choose_package(self.config.file_type, self.config.file_name, self.config.exports, self.target)
            # If it's an URL, we'll just use the default Internet Explorer
            # package.
            else:
                package = "ie"

            # If we weren't able to automatically determine the proper package,
            # we need to abort the analysis.
            if not package:
                raise CuckooError("No valid package available for file " "type: {0}".format(self.config.file_type))

            log.info('Automatically selected analysis package "%s"', package)
        # Otherwise just select the specified package.
        else:
            package = self.config.package
            log.info('Analysis package "%s" has been specified.', package)
        # Generate the package path.
        package_name = "modules.packages.%s" % package
        # Try to import the analysis package.
        try:
            log.debug('Importing analysis package "%s"...', package)
            __import__(package_name, globals(), locals(), ["dummy"])
            #log.debug('Imported analysis package "%s".', package)
        # If it fails, we need to abort the analysis.
        except ImportError:
            raise CuckooError('Unable to import package "{0}", does ' "not exist.".format(package_name))
        except Exception as e:
            log.exception(e)
        # Initialize the package parent abstract.
        Package()
        # Enumerate the abstract subclasses.
        try:
            package_class = Package.__subclasses__()[0]
        except IndexError as e:
            raise CuckooError("Unable to select package class " "(package={0}): {1}".format(package_name, e))
        except Exception as e:
            log.exception(e)

        # Initialize the analysis package.
        log.debug('Initializing analysis package "%s"...', package)
        self.package = package_class(self.options, self.config)
        #log.debug('Initialized analysis package "%s".', package)

        # Move the sample to the current working directory as provided by the
        # task - one is able to override the starting path of the sample.
        # E.g., for some samples it might be useful to run from %APPDATA%
        # instead of %TEMP%.
        if self.config.category == "file":
            self.target = self.package.move_curdir(self.target)

        # Set the DLL to that specified by package
        if "dll" in self.package.options and self.package.options["dll"] is not None:
            MONITOR_DLL = self.package.options["dll"]
            log.info("Analyzer: DLL set to %s from package %s", MONITOR_DLL, package_name)
        else:
            log.info("Analyzer: Package %s does not specify a DLL option", package_name)

        # Set the DLL_64 to that specified by package
        if "dll_64" in self.package.options and self.package.options["dll_64"] is not None:
            MONITOR_DLL_64 = self.package.options["dll_64"]
            log.info("Analyzer: DLL_64 set to %s from package %s", MONITOR_DLL_64, package_name)
        else:
            log.info("Analyzer: Package %s does not specify a DLL_64 option", package_name)

        # Set the loader to that specified by package
        if "loader" in self.package.options and self.package.options["loader"] is not None:
            LOADER32 = self.package.options["loader"]
            log.info("Analyzer: Loader set to %s from package %s", LOADER32, package_name)
        else:
            log.info("Analyzer: Package %s does not specify a loader option", package_name)

        # Set the loader_64 to that specified by package
        if "loader_64" in self.package.options and self.package.options["loader_64"] is not None:
            LOADER64 = self.package.options["loader_64"]
            log.info("Analyzer: Loader_64 set to %s from package %s", LOADER64, package_name)
        else:
            log.info("Analyzer: Package %s does not specify a loader_64 option", package_name)

        # randomize monitor DLL and loader executable names
        if MONITOR_DLL is not None:
            copy(os.path.join("dll", MONITOR_DLL), CAPEMON32_NAME)
        else:
            copy("dll\\capemon.dll", CAPEMON32_NAME)
        if MONITOR_DLL_64 is not None:
            copy(os.path.join("dll", MONITOR_DLL_64), CAPEMON64_NAME)
        else:
            copy("dll\\capemon_x64.dll", CAPEMON64_NAME)
        if LOADER32 is not None:
            copy(os.path.join("bin", LOADER32), LOADER32_NAME)
        else:
            copy("bin\\loader.exe", LOADER32_NAME)
        if LOADER64 is not None:
            copy(os.path.join("bin", LOADER64), LOADER64_NAME)
        else:
            copy("bin\\loader_x64.exe", LOADER64_NAME)

        # Initialize Auxiliary modules
        Auxiliary()
        prefix = auxiliary.__name__ + "."

        # disable_screens = True
        # if "disable_screens" in self.options and self.options["disable_screens"] == "0":
        #    disable_screens = False

        for loader, name, ispkg in pkgutil.iter_modules(auxiliary.__path__, prefix):
            # if ispkg or (name=="modules.auxiliary.screenshots" and disable_screens):
            #    continue
            # Import the auxiliary module.
            try:
                log.debug('Importing auxiliary module "%s"...', name)
                __import__(name, globals(), locals(), ["dummy"])
                #log.debug('Imported auxiliary module "%s".', name)
            except ImportError as e:
                log.warning("Unable to import the auxiliary module " '"%s": %s', name, e)
        # Walk through the available auxiliary modules.
        aux_avail = []

        for module in Auxiliary.__subclasses__():
            # Try to start the auxiliary module.
            # if module.__name__ == "Screenshots" and disable_screens:
            #    continue
            try:
                log.debug('Initializing auxiliary module "%s"...', module.__name__)
                aux = module(self.options, self.config)
                #log.debug('Initialized auxiliary module "%s".', module.__name__)
                aux_avail.append(aux)
                #log.debug('Trying to start auxiliary module "%s"...', module.__name__)
                aux.start()
            except (NotImplementedError, AttributeError):
                log.warning("Auxiliary module %s was not implemented", module.__name__)
            except Exception as e:
                log.warning("Cannot execute auxiliary module %s: %s", module.__name__, e)
            else:
                log.debug("Started auxiliary module %s", module.__name__)
                AUX_ENABLED.append(aux)

        """
        # Inform zer0m0n of the ResultServer address.
        zer0m0n.resultserver(self.config.ip, self.config.port)

        # Forward the command pipe and logpipe names on to zer0m0n.
        zer0m0n.cmdpipe(self.config.pipe)
        zer0m0n.channel(self.config.logpipe)

        # Hide the Cuckoo Analyzer & Cuckoo Agent.
        zer0m0n.hidepid(self.pid)
        zer0m0n.hidepid(self.ppid)

        # Initialize zer0m0n with our compiled Yara rules.
        zer0m0n.yarald("bin/rules.yarac")

        # Propagate the requested dump interval, if set.
        zer0m0n.dumpint(int(self.options.get("dumpint", "0")))
        """

        si = subprocess.STARTUPINFO()
        # STARTF_USESHOWWINDOW
        si.dwFlags = 1
        # SW_HIDE
        si.wShowWindow = 0
        #log.info("Stopping WMI Service")
        subprocess.call(["net", "stop", "winmgmt", "/y"], startupinfo=si)
        #log.info("Stopped WMI Service")
        subprocess.call("sc config winmgmt type= own", startupinfo=si)

        log.info("Restarting WMI Service")
        subprocess.call("net start winmgmt", startupinfo=si)
        #log.info("Started WMI Service")

        # Start analysis package. If for any reason, the execution of the
        # analysis package fails, we have to abort the analysis.
        try:
            pids = self.package.start(self.target)
        except NotImplementedError:
            raise CuckooError('The package "{0}" doesn\'t contain a start ' "function.".format(package_name))
        except CuckooPackageError as e:
            raise CuckooError('The package "{0}" start function raised an ' "error: {1}".format(package_name, e))
        except Exception as e:
            raise CuckooError('The package "{0}" start function encountered ' "an unhandled exception: " "{1}".format(package_name, e))

        # If the analysis package returned a list of process IDs, we add them
        # to the list of monitored processes and enable the process monitor.
        if pids:
            self.process_list.add_pids(pids)
            pid_check = True

        # If the package didn't return any process ID (for example in the case
        # where the package isn't enabling any behavioral analysis), we don't
        # enable the process monitor.
        else:
            log.info("No process IDs returned by the package, running for the full timeout.")
            pid_check = False

        # Check in the options if the user toggled the timeout enforce. If so,
        # we need to override pid_check and disable process monitor.
        if self.config.enforce_timeout:
            log.info("Enabled timeout enforce, running for the full timeout.")
            pid_check = False

        time_start = datetime.now()
        kernel_analysis = self.options.get("kernel_analysis", False)

        emptytime = None

        while self.do_run:
            self.time_counter = datetime.now() - time_start
            if self.time_counter.total_seconds() < 0 or self.time_counter.total_seconds() >= int(self.config.timeout):
                log.info("Analysis timeout hit, terminating analysis.")
                ANALYSIS_TIMED_OUT = True
                break

            # If the process lock is locked, it means that something is
            # operating on the list of monitored processes. Therefore we
            # cannot proceed with the checks until the lock is released.
            if self.process_lock.locked():
                log.info("we are locked")
                KERNEL32.Sleep(1000)
                continue

            try:
                # If the process monitor is enabled we start checking whether
                # the monitored processes are still alive.
                if pid_check:
                    # We also track the PIDs provided by zer0m0n.
                    # self.process_list.add_pids(zer0m0n.getpids())
                    if not kernel_analysis:
                        for pid in self.process_list.pids:
                            if not Process(pid=pid).is_alive():
                                if self.options.get("procmemdump", False):
                                    try:
                                        Process(pid=pid).upload_memdump()
                                    except Exception as e:
                                        log.error(e, exc_info=True)
                                else:
                                    log.info("procdump not enabled")
                                log.info("Process with pid %s appears to have terminated", pid)
                                if pid in self.process_list.pids:
                                    self.process_list.remove_pid(pid)

                        # If none of the monitored processes are still alive, we
                        # can terminate the analysis.
                        if not self.process_list.pids and (
                            not self.LASTINJECT_TIME or (datetime.now() >= (self.LASTINJECT_TIME + timedelta(seconds=15)))
                        ):
                            if emptytime and (datetime.now() >= (emptytime + timedelta(seconds=5))):
                                log.info("Process list is empty, terminating analysis.")
                                break
                            elif not emptytime:
                                emptytime = datetime.now()
                        else:
                            emptytime = None

                    # Update the list of monitored processes available to the
                    # analysis package. It could be used for internal
                    # operations within the module.
                    self.package.set_pids(self.process_list.pids)

                try:
                    # The analysis packages are provided with a function that
                    # is executed at every loop's iteration. If such function
                    # returns False, it means that it requested the analysis
                    # to be terminate.
                    if not self.package.check():
                        log.info("The analysis package requested the " "termination of the analysis.")
                        break

                # If the check() function of the package raised some exception
                # we don't care, we can still proceed with the analysis but we
                # throw a warning.
                except Exception as e:
                    log.warning('The package "%s" check function raised ' "an exception: %s", package_name, e)
            finally:
                # Zzz.
                KERNEL32.Sleep(1000)

        # Tell all processes to complete their monitoring
        if not kernel_analysis:
            for pid in self.process_list.pids:
                proc = Process(pid=pid)
                if proc.is_alive():
                    try:
                        proc.set_terminate_event()
                    except:
                        log.error("Unable to set terminate event for process %d.", proc.pid)
                        continue
                    log.info("Terminate event set for process %d.", proc.pid)
                if self.config.terminate_processes:
                    # Try to terminate remaining active processes.
                    # (This setting may render full system memory dumps less useful!)
                    if proc.is_alive() and not pid in self.CRITICAL_PROCESS_LIST and not proc.is_critical():
                        log.info("Terminating process %d before shutdown.", proc.pid)
                        proc_counter = 0
                        while proc.is_alive():
                            if proc_counter > 5:
                                try:
                                    proc.terminate()
                                except:
                                    continue
                            log.info("Waiting for process %d to exit.", proc.pid)
                            KERNEL32.Sleep(1000)
                            proc_counter += 1

        # Create the shutdown mutex.
        KERNEL32.CreateMutexA(None, False, SHUTDOWN_MUTEX)
        log.info("Created shutdown mutex.")
        # since the various processes poll for the existence of the mutex, sleep
        # for a second to ensure they see it before they're terminated
        KERNEL32.Sleep(1000)

        log.info("Shutting down package.")
        try:
            # Before shutting down the analysis, the package can perform some
            # final operations through the finish() function.
            self.package.finish()
        except Exception as e:
            log.warning('The package "%s" finish function raised an ' "exception: %s", package_name, e)

        try:
            # Upload files the package created to package_files in the
            # results folder.
            for path, name in self.package.package_files() or []:
                upload_to_host(path, os.path.join("package_files", name))
        except Exception as e:
            log.warning('The package "%s" package_files function raised an ' "exception: %s", package_name, e)

        log.info("Stopping auxiliary modules.")
        # Terminate the Auxiliary modules.
        for aux in AUX_ENABLED:
            if not hasattr(aux, "stop"):
                continue
            try:
                aux.stop()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Cannot terminate auxiliary module %s: %s", aux.__class__.__name__, e)

        log.info("Finishing auxiliary modules.")
        # Run the finish callback of every available Auxiliary module.
        for aux in aux_avail:
            try:
                aux.finish()
            except (NotImplementedError, AttributeError):
                continue
            except Exception as e:
                log.warning("Exception running finish callback of auxiliary " "module %s: %s", aux.__class__.__name__, e)

        log.info("Shutting down pipe server and dumping dropped files.")

        return True


class Files(object):
    PROTECTED_NAMES = [
        "vmwareuser.exe",
        "vmwareservice.exe",
        "vboxservice.exe",
        "vboxtray.exe",
        "sandboxiedcomlaunch.exe",
        "sandboxierpcss.exe",
        "procmon.exe",
        "regmon.exe",
        "filemon.exe",
        "wireshark.exe",
        "netmon.exe",
        "prl_tools_service.exe",
        "prl_tools.exe",
        "prl_cc.exe",
        "sharedintapp.exe",
        "vmtoolsd.exe",
        "vmsrvc.exe",
        "python.exe",
        "perl.exe",
    ]

    def __init__(self):
        self.files = {}
        self.files_orig = {}
        self.dumped = []

    def is_protected_filename(self, file_name):
        """Return whether or not to inject into a process with this name."""
        return file_name.lower() in self.PROTECTED_NAMES

    def add_pid(self, filepath, pid, verbose=True):
        """Track a process identifier for this file."""
        if not pid or filepath.lower() not in self.files:
            return

        if pid not in self.files[filepath.lower()]:
            self.files[filepath.lower()].append(pid)
            verbose and log.info("Added pid %s for %r", pid, filepath)

            # PROCESS_LIST.append(int(pid))
            add_pid_to_aux_modules(int(pid))

    def add_file(self, filepath, pid=None, category="files", metadata=""):
        """Add filepath to the list of files and track the pid."""
        if filepath.lower() not in self.files:
            log.info("Added new file to list with pid %s and path %s", pid, filepath)
            self.files[filepath.lower()] = []
            self.files_orig[filepath.lower()] = {"category": category, "metadata": metadata, "path": filepath}

        self.add_pid(filepath, pid, verbose=False)

    def dump_file(self, filepath, metadata="", pids=False, category="files"):
        """Dump a file to the host."""
        if not os.path.isfile(filepath):
            log.warning("File at path %r does not exist, skip.", filepath)
            return False

        duplicated = False
        # Check whether we've already dumped this file - in that case skip it.
        try:
            sha256 = hash_file(hashlib.sha256, filepath)
            if sha256 in self.dumped:
                duplicated = True
        except IOError as e:
            log.info('Error dumping file from path "%s": %s', filepath, e)
            return

        # load metadata
        if self.files_orig.get(filepath.lower()):
            file_details = self.files_orig.get(filepath.lower())
            category = file_details["category"]
            metadata = file_details["metadata"]
            path = self.files_orig.get(filepath.lower(), {}).get("path") or filepath
            pids = self.files.get(filepath.lower(), [])
            filepath = self.files_orig.get(filepath.lower(), {}).get("path") or filepath

        if category == "memory":
            if pids:
                upload_path = os.path.join(category, "{}.dmp".format(pids[0]))
            else:
                pids = [os.path.basename(filepath).split(".")[0]]
                upload_path = os.path.join(category, os.path.basename(filepath))

        else:
            upload_path = os.path.join(category, sha256)

        try:
            # If available use the original filepath, the one that is not lowercased.
            upload_to_host(filepath, upload_path, pids, metadata=metadata, category=category, duplicated=duplicated)
            self.dumped.append(sha256)
        except (IOError, socket.error) as e:
            log.error('Unable to upload dropped file at path "%s": %s', filepath, e)
        except Exception as e:
            log.error(e, exc_info=True)

    def delete_file(self, filepath, pid=None):
        """A file is about to removed and thus should be dumped right away."""
        self.add_pid(filepath, pid)
        self.dump_file(filepath)

        # Remove the filepath from the files list.
        self.files.pop(filepath.lower(), None)
        self.files_orig.pop(filepath.lower(), None)

    def move_file(self, oldfilepath, newfilepath, pid=None):
        """A file will be moved - track this change."""
        self.add_pid(oldfilepath, pid)
        if oldfilepath.lower() in self.files:
            # Replace the entry with the new filepath.
            self.files[newfilepath.lower()] = self.files.pop(oldfilepath.lower(), [])

    def dump_files(self):
        """Dump all pending files."""
        while self.files:
            self.delete_file(list(self.files.keys())[0])


class ProcessList(object):
    def __init__(self):
        self.pids = []
        self.pids_notrack = []

    def add_pid(self, pid, track=True):
        """Add a process identifier to the process list.
        Track determines whether the analyzer should be monitoring this
        process, i.e., whether Cuckoo should wait for this process to finish.
        """
        if int(pid) not in self.pids and int(pid) not in self.pids_notrack:
            if track:
                self.pids.append(int(pid))
            else:
                self.pids_notrack.append(int(pid))

    def add_pids(self, pids):
        """Add one or more process identifiers to the process list."""
        if isinstance(pids, (tuple, list)):
            for pid in pids:
                self.add_pid(pid)
        else:
            self.add_pid(pids)

    def has_pid(self, pid, notrack=True):
        """Return whether or not this process identifier being tracked."""
        if int(pid) in self.pids:
            return True

        if notrack and int(pid) in self.pids_notrack:
            return True

        return False

    def remove_pid(self, pid):
        """Remove a process identifier from being tracked."""
        if pid in self.pids:
            self.pids.remove(pid)

        if pid in self.pids_notrack:
            self.pids_notrack.remove(pid)


class CommandPipeHandler(object):
    """Pipe Handler.
    This class handles the notifications received through the Pipe Server and
    decides what to do with them.
    """

    ignore_list = dict(pid=[])

    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.tracked = {}

    def _handle_debug(self, data):
        """Debug message from the monitor."""
        try:
            log.debug(data.decode("utf-8"))
        except:
            log.debug(data)

    def _handle_info(self, data):
        """Regular message from the monitor."""
        try:
            log.info(data.decode("utf-8"))
        except:
            log.debug(data)

    def _handle_warning(self, data):
        """Warning message from the monitor."""
        log.warning(data)

    def _handle_critical(self, data):
        """Critical message from the monitor."""
        log.critical(data)

    def _handle_loaded(self, data):
        """The monitor has loaded into a particular process."""
        if not data:
            log.warning("Received loaded command with incorrect parameters, " "skipping it.")
            return

        # pid, track = data.split(b",")
        # if not pid.isdigit() or not track.isdigit():
        #    log.warning("Received loaded command with incorrect parameters, "
        #                "skipping it.")
        #    return

        self.analyzer.process_lock.acquire()
        pid = int(data)
        if pid not in self.analyzer.process_list.pids:
            self.analyzer.process_list.add_pid(int(pid))  # , track=int(track))
        if pid in INJECT_LIST:
            INJECT_LIST.remove(pid)
        self.analyzer.process_lock.release()

        log.info("Loaded monitor into process with pid %s", pid)

    def _handle_getpids(self, data):
        """Return the process identifiers of the agent and its parent
        process."""
        # return struct.pack("II", self.analyzer.pid, self.analyzer.ppid)
        hidepids = set()
        hidepids.update(HIDE_PIDS)
        hidepids.update([self.analyzer.pid, self.analyzer.ppid])
        return struct.pack("%dI" % len(hidepids), *hidepids)

    # remove pid from process list because we received a notification
    # from kernel land
    def _handle_kterminate(self, data):
        process_id = int(data)
        if process_id and process_id in self.analyzer.process_list.pids:
            self.analyzer.process_list.remove_pid(process_id)

    # same than below but we don't want to inject any DLLs because
    # it's a kernel analysis
    def _handle_kprocess(self, data):
        self.analyzer.process_lock.acquire()
        process_id = int(data)
        thread_id = None
        if process_id and process_id not in (self.analyzer.pid, self.analyzer.ppid, self.analyzer.process_list.pids):
            proc = Process(options=self.analyzer.options, config=self.analyzer.config, pid=process_id, thread_id=thread_id)
            filepath = proc.get_filepath()
            filename = os.path.basename(filepath)
            if not in_protected_path(filename):
                self.analyzer.process_list.add_pid(process_id)
                log.info("Announce process name : %s", filename)
        self.analyzer.process_lock.release()

    def _handle_kerror(self, error_msg):
        log.error("Error : %s", str(error_msg))

    # if a new driver has been loaded, we stop the analysis
    def _handle_ksubvert(self, data):
        for pid in self.analyzer.process_list.pids:
            log.info("Process with pid %s has terminated", pid)
            self.analyzer.process_list.remove_pid(pid)

    def _handle_interop(self, data):
        if not self.analyzer.MONITORED_DCOM:
            self.analyzer.MONITORED_DCOM = True
            dcom_pid = pid_from_service_name("DcomLaunch")
            if dcom_pid:
                servproc = Process(options=self.analyzer.options, config=self.analyzer.config, pid=dcom_pid, suspended=False)
                self.analyzer.CRITICAL_PROCESS_LIST.append(int(dcom_pid))
                filepath = servproc.get_filepath()
                servproc.inject(injectmode=INJECT_QUEUEUSERAPC, interest=filepath, nosleepskip=True)
                self.analyzer.LASTINJECT_TIME = datetime.now()
                servproc.close()
                KERNEL32.Sleep(2000)

    def _handle_wmi(self, data):
        if not self.analyzer.MONITORED_WMI and ANALYSIS_TIMED_OUT is False:
            self.analyzer.MONITORED_WMI = True
            if not self.analyzer.MONITORED_DCOM:
                self.analyzer.MONITORED_DCOM = True
                dcom_pid = pid_from_service_name("DcomLaunch")
                if dcom_pid:
                    servproc = Process(options=self.analyzer.options, config=self.analyzer.config, pid=dcom_pid, suspended=False)
                    self.analyzer.CRITICAL_PROCESS_LIST.append(int(dcom_pid))
                    filepath = servproc.get_filepath()
                    servproc.inject(injectmode=INJECT_QUEUEUSERAPC, interest=filepath, nosleepskip=True)
                    self.analyzer.LASTINJECT_TIME = datetime.now()
                    servproc.close()
                    KERNEL32.Sleep(2000)

            wmi_pid = pid_from_service_name("winmgmt")
            if wmi_pid:
                servproc = Process(options=self.analyzer.options, config=self.analyzer.config, pid=wmi_pid, suspended=False)
                self.analyzer.CRITICAL_PROCESS_LIST.append(int(wmi_pid))
                filepath = servproc.get_filepath()
                servproc.inject(injectmode=INJECT_QUEUEUSERAPC, interest=filepath, nosleepskip=True)
                self.analyzer.LASTINJECT_TIME = datetime.now()
                servproc.close()
                KERNEL32.Sleep(2000)

    def _handle_tasksched(self, data):
        if not self.analyzer.MONITORED_TASKSCHED and ANALYSIS_TIMED_OUT is False:
            self.analyzer.MONITORED_TASKSCHED = True
            si = subprocess.STARTUPINFO()
            # STARTF_USESHOWWINDOW
            si.dwFlags = 1
            # SW_HIDE
            si.wShowWindow = 0
            log.info("Stopping Task Scheduler Service")
            subprocess.call(["net", "stop", "schedule", "/y"], startupinfo=si)
            log.info("Stopped Task Scheduler Service")
            subprocess.call("sc config schedule type= own", startupinfo=si)
            log.info("Starting Task Scheduler Service")

            subprocess.call("net start schedule", startupinfo=si)
            log.info("Started Task Scheduler Service")

            sched_pid = pid_from_service_name("schedule")
            if sched_pid:
                servproc = Process(options=self.analyzer.options, config=self.analyzer.config, pid=sched_pid, suspended=False)
                self.analyzer.CRITICAL_PROCESS_LIST.append(int(sched_pid))
                filepath = servproc.get_filepath()
                servproc.inject(injectmode=INJECT_QUEUEUSERAPC, interest=filepath, nosleepskip=True)
                self.analyzer.LASTINJECT_TIME = datetime.now()
                servproc.close()
                KERNEL32.Sleep(2000)

    def _handle_bits(self, data):
        if not self.analyzer.MONITORED_BITS and ANALYSIS_TIMED_OUT is False:
            self.analyzer.MONITORED_BITS = True
            si = subprocess.STARTUPINFO()
            # STARTF_USESHOWWINDOW
            si.dwFlags = 1
            # SW_HIDE
            si.wShowWindow = 0

            log.info("Stopping BITS Service")
            subprocess.call(["net", "stop", "BITS", "/y"], startupinfo=si)
            log.info("Stopped BITS Service")
            subprocess.call("sc config BITS type= own", startupinfo=si)

            if not self.analyzer.MONITORED_DCOM:
                self.analyzer.MONITORED_DCOM = True
                dcom_pid = pid_from_service_name("DcomLaunch")
                if dcom_pid:
                    servproc = Process(options=self.analyzer.options, config=self.analyzer.config, pid=dcom_pid, suspended=False)

                    self.analyzer.CRITICAL_PROCESS_LIST.append(int(dcom_pid))
                    filepath = servproc.get_filepath()
                    servproc.inject(injectmode=INJECT_QUEUEUSERAPC, interest=filepath, nosleepskip=True)
                    self.analyzer.LASTINJECT_TIME = datetime.now()
                    servproc.close()
                    KERNEL32.Sleep(2000)

            log.info("Starting BITS Service")
            subprocess.call("net start BITS", startupinfo=si)
            log.info("Started BITS Service")
            bits_pid = pid_from_service_name("BITS")
            if bits_pid:
                servproc = Process(options=self.analyzer.options, config=self.analyzer.config, pid=bits_pid, suspended=False)
                self.analyzer.CRITICAL_PROCESS_LIST.append(int(bits_pid))
                filepath = servproc.get_filepath()
                servproc.inject(injectmode=INJECT_QUEUEUSERAPC, interest=filepath, nosleepskip=True)
                self.analyzer.LASTINJECT_TIME = datetime.now()
                servproc.close()
                KERNEL32.Sleep(2000)

    # Handle case of a service being started by a monitored process
    # Switch the service type to own process behind its back so we
    # can monitor the service more easily with less noise
    def _handle_service(self, servname):
        if ANALYSIS_TIMED_OUT is False:
            si = subprocess.STARTUPINFO()
            # STARTF_USESHOWWINDOW
            si.dwFlags = 1
            # SW_HIDE
            si.wShowWindow = 0
            subprocess.call("sc config " + servname.decode("utf-8") + " type= own", startupinfo=si)
            log.info('Announced starting service "%s"', servname)
            if not self.analyzer.MONITORED_SERVICES:
                # Inject into services.exe so we can monitor service creation
                # if tasklist previously failed to get the services.exe PID we'll be
                # unable to inject
                if self.analyzer.SERVICES_PID:
                    servproc = Process(
                        options=self.analyzer.options, config=self.analyzer.config, pid=self.analyzer.SERVICES_PID, suspended=False
                    )
                    self.analyzer.CRITICAL_PROCESS_LIST.append(int(self.analyzer.SERVICES_PID))
                    filepath = servproc.get_filepath()
                    servproc.inject(injectmode=INJECT_QUEUEUSERAPC, interest=filepath, nosleepskip=True)
                    self.analyzer.LASTINJECT_TIME = datetime.now()
                    servproc.close()
                    KERNEL32.Sleep(1000)
                    self.analyzer.MONITORED_SERVICES = True
                else:
                    log.error("Unable to monitor service %s" % (servname))

    def _handle_resume(self, data):
        # RESUME:2560,3728'
        self.analyzer.LASTINJECT_TIME = datetime.now()
        if self.analyzer.options.get("unpack", "").lower() in ("yes", "true", "enabled", "on", "y"):
            data = list(map(int, data.split(b",")))
            if len(data) == 1:
                pid, tid = data[0], 0
            elif len(data) == 2:
                pid, tid = data
            log.debug("Resume: %s, %s", str(pid), str(tid))

    # Handle attempted shutdowns/restarts -- flush logs for all monitored processes
    # additional handling can be added later
    def _handle_shutdown(self, data):
        log.info("Received shutdown request")
        self.analyzer.process_lock.acquire()
        for process_id in self.analyzer.process_list.pids:
            event_name = TERMINATE_EVENT + str(process_id)
            event_handle = KERNEL32.OpenEventA(EVENT_MODIFY_STATE, False, event_name)
            if event_handle:
                KERNEL32.SetEvent(event_handle)
                KERNEL32.CloseHandle(event_handle)
                if self.analyzer.options.get("procmemdump"):
                    p = Process(pid=process_id)
                    p.dump_memory()
                self.files.dump_files()
        self.analyzer.process_lock.release()

    # Handle case of malware terminating a process -- notify the target
    # ahead of time so that it can flush its log buffer
    def _handle_kill(self, data):
        self.analyzer.process_lock.acquire()

        process_id = int(data)
        log.info("Process with pid %s has terminated", process_id)
        if process_id not in (self.analyzer.pid, self.analyzer.ppid) and process_id in self.analyzer.process_list.pids:
            self.analyzer.process_list.remove_pid(process_id)
        self.analyzer.process_lock.release()

    def _inject_process(self, process_id, thread_id, mode):
        """Helper function for injecting the monitor into a process."""
        # We acquire the process lock in order to prevent the analyzer to
        # terminate the analysis while we are operating on the new process.
        self.analyzer.process_lock.acquire()

        # Set the current DLL to the default one provided at submission.
        dll = self.analyzer.default_dll

        if process_id in (self.analyzer.pid, self.analyzer.ppid):
            if process_id not in self.ignore_list["pid"]:
                log.warning("Received request to inject Cuckoo processes, " "skipping it.")
                self.ignore_list["pid"].append(process_id)
            self.analyzer.process_lock.release()
            return

        # We inject the process only if it's not being monitored already,
        # otherwise we would generated polluted logs (if it wouldn't crash
        # horribly to start with).
        if self.analyzer.process_list.has_pid(process_id):
            # This pid is already on the notrack list, move it to the
            # list of tracked pids.
            if not self.analyzer.process_list.has_pid(process_id, notrack=False):
                log.debug("Received request to inject pid=%d. It was already " "on our notrack list, moving it to the track list.")

                self.analyzer.process_list.remove_pid(process_id)
                self.analyzer.process_list.add_pid(process_id)
                self.ignore_list["pid"].append(process_id)
            # Spit out an error once and just ignore it further on.
            elif process_id not in self.ignore_list["pid"]:
                self.ignore_list["pid"].append(process_id)

            # We're done operating on the processes list, release the lock.
            self.analyzer.process_lock.release()
            return

        # Open the process and inject the DLL. Hope it enjoys it.
        proc = Process(pid=process_id, tid=thread_id)

        filepath = proc.get_filepath()
        filename = os.path.basename(filepath)

        if not self.analyzer.files.is_protected_filename(filename):
            # Add the new process ID to the list of monitored processes.
            self.analyzer.process_list.add_pid(process_id)

            # We're done operating on the processes list,
            # release the lock. Let the injection do its thing.
            self.analyzer.process_lock.release()

            # If we have both pid and tid, then we can use APC to inject.
            if process_id and thread_id:
                proc.inject(injectmode=INJECT_QUEUEUSERAPC, interest=filepath, nosleepskip=True)
            else:
                proc.inject(injectmode=INJECT_CREATEREMOTETHREAD, interest=filepath, nosleepskip=True)

            log.info("Injected into process with pid %s and name %r", proc.pid, filename)

    def _handle_process(self, data):
        """Request for injection into a process."""
        # Parse the process identifier.
        # PROCESS:1:1824,2856
        suspended = False
        process_id = thread_id = None
        # We parse the process ID.
        suspended, data = data.split(b":")
        if b"," not in data:
            if data.isdigit():
                process_id = int(data)
        elif data.count(b",") == 1:
            process_id, param = data.split(b",")
            thread_id = None
            if process_id.isdigit():
                process_id = int(process_id)
            else:
                process_id = None
            if param.isdigit():
                thread_id = int(param)
        if process_id and ANALYSIS_TIMED_OUT is False:
            if process_id not in (self.analyzer.pid, self.analyzer.ppid):
                # We inject the process only if it's not being
                # monitored already, otherwise we would generate
                # polluted logs.
                if process_id not in self.analyzer.process_list.pids:
                    if process_id not in INJECT_LIST:
                        INJECT_LIST.append(process_id)
                    # Open the process and inject the DLL.
                    proc = Process(
                        options=self.analyzer.options, config=self.analyzer.config, pid=process_id, thread_id=thread_id, suspended=suspended
                    )
                    filepath = proc.get_filepath()  # .encode('utf8', 'replace')
                    # if it's a URL analysis, provide the URL to all processes as
                    # the "interest" -- this will allow capemon to see in the
                    # child browser process that a URL analysis is occurring
                    if self.analyzer.config.category == "file" or self.analyzer.NUM_INJECTED > 1:
                        interest = filepath
                    else:
                        interest = self.analyzer.config.target
                    is_64bit = proc.is_64bit()
                    filename = os.path.basename(filepath)
                    if self.analyzer.SERVICES_PID and process_id == self.analyzer.SERVICES_PID:
                        self.analyzer.CRITICAL_PROCESS_LIST.append(int(self.analyzer.SERVICES_PID))
                    log.info("Announced %s process name: %s pid: %d", "64-bit" if is_64bit else "32-bit", filename, process_id)
                    # We want to prevent multiple injection attempts if one is already underway
                    if not in_protected_path(filename):
                        _ = proc.inject(INJECT_QUEUEUSERAPC, interest)
                        self.LASTINJECT_TIME = datetime.now()
                        self.analyzer.NUM_INJECTED += 1
                    proc.close()
            else:
                log.warning("Received request to inject process with pid %d, skipped", process_id)
        # return self._inject_process(int(data), None, 0)
        return

    def _handle_process2(self, data):
        """Request for injection into a process using APC."""
        # Parse the process and thread identifier.
        if not data or data.count(b",") != 2:
            log.warning("Received PROCESS2 command from monitor with an " "incorrect argument.")
            return

        pid, tid, mode = data.split(b",")
        if not pid.isdigit() or not tid.isdigit() or not mode.isdigit():
            log.warning("Received PROCESS2 command from monitor with an " "incorrect argument.")
            return

        return self._inject_process(int(pid), int(tid), int(mode))

    def _handle_file_new(self, file_path):
        """Notification of a new dropped file."""
        if os.path.exists(file_path):
            self.analyzer.files.add_file(file_path.decode("utf-8"), self.pid)

    def _handle_file_cape(self, data):
        """Notification of a new dropped file."""
        # Syntax -> PATH|PID|Metadata
        file_path, pid, metadata = data.split(b"|")
        if os.path.exists(file_path):
            self.analyzer.files.dump_file(file_path.decode("utf-8"), pids=[pid.decode("utf-8")], metadata=metadata, category="CAPE")

    # In case of FILE_DEL, the client is trying to notify an ongoing
    # deletion of an existing file, therefore we need to dump it
    # straight away.
    def _handle_file_del(self, data):
        """Notification of a file being removed (if it exists) - we have to
        dump it before it's being removed."""
        file_path = data.decode("utf8")
        if os.path.exists(file_path):
            self.analyzer.files.delete_file(file_path, self.pid)

    def _handle_file_dump(self, file_path):
        # We extract the file path.
        # We dump immediately.
        if b"\\CAPE\\" in file_path:
            # Syntax -> PATH|PID|Metadata
            file_path, pid, metadata = file_path.split(b"|")
            if os.path.exists(file_path):
                self.analyzer.files.dump_file(file_path.decode("utf-8"), pids=[pid.decode("utf-8")], metadata=metadata, category="procdump")

        else:
            if os.path.exists(file_path):
                if b"\\memory\\" in file_path:
                    self.analyzer.files.dump_file(file_path.decode("utf-8"), category="memory")
                else:
                    self.analyzer.files.add_file(file_path.decode("utf-8"), self.pid)
            else:
                log.info("File doesn't exist, %s", file_path)

    def _handle_dumpreqs(self, data):
        if not data.isdigit():
            log.warning("Received DUMPREQS command with an incorrect argument %r.", data)
            return
        pid = int(data)
        if pid not in self.tracked:
            log.warning("Received DUMPREQS command but there are no reqs for pid %d.", pid)
            return

        dumpreqs = self.tracked[pid].get("dumpreq", [])
        for addr, length in dumpreqs:
            log.debug("tracked dump req (%r, %r, %r)", pid, addr, length)

            if not addr or not length:
                continue

        pid, scope, params = data.split(b":", 2)
        pid = int(pid)

        paramtuple = params.split(b",")
        if pid not in self.tracked:
            self.tracked[pid] = {}
        if scope not in self.tracked[pid]:
            self.tracked[pid][scope] = []
        self.tracked[pid][scope].append(paramtuple)

    def _handle_file_move(self, data):
        """A file is being moved - track these changes."""
        # Syntax = "FILE_MOVE:old_file_path::new_file_path".
        if b"::" not in data:
            log.warning("Received FILE_MOVE command from monitor with an incorrect argument.")
            return

        old_filepath, new_filepath = data.split(b"::", 1)
        new_filepath = new_filepath.decode("utf8")
        self.analyzer.files.move_file(old_filepath.decode("utf8"), new_filepath, self.pid)

    def dispatch(self, data):
        response = "NOPE"
        if not data or b":" not in data:
            log.critical("Unknown command received from the monitor: %r", data.strip())
        else:
            # Backwards compatibility (old syntax is, e.g., "FILE_NEW:" vs the
            # new syntax, e.g., "1234:FILE_NEW:").
            # if data[0].isupper():
            command, arguments = data.strip().split(b":", 1)
            # Uncomment to debug monitor commands
            # if command not in (b"DEBUG", b"INFO"):
            #    log.info((command, arguments, "dispatch"))
            self.pid = None
            fn = getattr(self, "_handle_%s" % command.lower().decode("utf-8"), None)
            if not fn:
                log.critical("Unknown command received from the monitor: %r", data.strip())
            else:
                try:
                    response = fn(arguments)
                except Exception as e:
                    log.error(e, exc_info=True)
                    log.exception("Pipe command handler exception occurred (command " "%s args %r).", command, arguments)

        return response


if __name__ == "__main__":
    success = False
    error = ""
    completion_key = ""
    data = {}
    try:
        # Initialize the main analyzer class.
        analyzer = Analyzer()
        analyzer.prepare()
        completion_key = analyzer.get_completion_key()

        # Run it and wait for the response.
        success = analyzer.run()

        data = {
            "status": "complete",
            "description": success,
        }

    # When user set wrong package, Example: Emotet package when submit doc, package only is for EXE!
    except CuckooError:
        log.info("You probably submitted the job with wrong package")
        data["status"] = "exception"
        data["description"] = "You probably submitted the job with wrong package"
        try:
            urlopen("http://127.0.0.1:8000/status", urlencode(data).encode("utf-8")).read()
        except Exception as e:
            print(e)
        sys.exit()
    # This is not likely to happen.
    except KeyboardInterrupt:
        error = "Keyboard Interrupt"

    # If the analysis process encountered a critical error, it will raise a
    # CuckooError exception, which will force the termination of the analysis.
    # Notify the agent of the failure. Also catch unexpected exceptions.
    except Exception as e:
        # Store the error.
        error_exc = traceback.format_exc()
        error = str(e)

        # Just to be paranoid.
        if len(log.handlers):
            log.exception(error_exc)
        else:
            sys.stderr.write("{0}\n".format(error_exc))

    # Once the analysis is completed or terminated for any reason, we report
    # back to the agent, notifying that it can report back to the host.
    finally:
        try:
            # Let's invoke the completion procedure.
            analyzer.complete()
        except Exception as e:
            complete_excp = traceback.format_exc()
            data["status"] = "exception"
            if "description" in data:
                data["description"] += "%s\n%s" % (data["description"], complete_excp)
            else:
                data["description"] = complete_excp
        try:
            urlopen("http://127.0.0.1:8000/status", urlencode(data).encode("utf-8")).read()
        except Exception as e:
            print(e)
