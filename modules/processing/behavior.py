# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import logging
import datetime
import struct

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.netlog import BsonParser
from lib.cuckoo.common.compressor import CuckooBsonCompressor
from lib.cuckoo.common.utils import convert_to_printable, pretty_print_arg, pretty_print_retval, logtime, default_converter, bytes2str, get_options


log = logging.getLogger(__name__)
cfg = Config()
cfg_process = Config("processing")


def fix_key(key):
    """Fix a registry key to have it normalized.
    @param key: raw key
    @returns: normalized key
    """
    # all normalization is done on the cuckoomon end, so this is now a no-op
    return key


class ParseProcessLog(list):
    """Parses process log file."""

    def __init__(self, log_path):
        """@param log_path: log file path."""
        self._log_path = log_path
        self.fd = None
        self.parser = None

        self.reporting_mode = False
        self.process_id = None
        self.process_name = None
        self.parent_id = None
        self.module_path = None
        # Using an empty initializer here allows the assignment of current_log.threads in the Processes run()
        # method to get a reference to the threads list we eventually build up by fully parsing a log
        # via the behavior analysis that happens later.  By the time the results dict is used later
        # to extract this information, it will finally have valid info.
        self.threads = []
        self.first_seen = None
        self.calls = self
        self.lastcall = None
        self.environdict = {}
        self.api_count = 0
        self.call_id = 0
        self.conversion_cache = {}
        self.api_limit = cfg.processing.analysis_call_limit  # Limit of API calls per process

        if os.path.exists(log_path) and os.stat(log_path).st_size > 0:
            self.parse_first_and_reset()

        if cfg.processing.ram_boost:
            self.api_call_cache = []
            self.api_pointer = 0

            try:
                while True:
                    i = self.cacheless_next()
                    self.api_call_cache.append(i)
            except StopIteration:
                pass
            self.api_call_cache.append(None)

    def parse_first_and_reset(self):
        """ Open file and init Bson Parser. Read till first process
        """
        self.fd = open(self._log_path, "rb")

        if self._log_path.endswith(".bson"):
            self.parser = BsonParser(self)
        else:
            self.fd.close()
            self.fd = None
            return

        # Get the process information from file
        # Note that we have to read in all messages until we
        # get all the information we need, so the invariant below
        # should involve the last process-related bit of
        # information logged
        # Environment info will be filled in as the log is read
        # and will be stored by reference into the results dict
        while not self.process_id:
            self.parser.read_next_message()

        self.fd.seek(0)

    def read(self, length):
        """ Read data from log file

        @param length: Length in byte to read
        """
        if not length or length < 0:
            return b""
        buf = self.fd.read(length)
        if not buf or len(buf) != length:
            raise EOFError()
        return buf

    def __iter__(self):
        # import inspect
        # log.debug('iter called by this guy: {0}'.format(inspect.stack()[1]))
        # import code; code.interact(local=dict(locals(), **globals()))
        return self

    def __repr__(self):
        return "<ParseProcessLog log-path: %r>" % self._log_path

    def __nonzero__(self):
        return self.wait_for_lastcall()

    def reset(self):
        """ Reset fd
        """
        self.fd.seek(0)
        self.api_count = 0
        self.lastcall = None
        self.call_id = 0
        self.api_pointer = 0

    def compare_calls(self, a, b):
        """Compare two calls for equality. Same implementation as before netlog.
        @param a: call a
        @param b: call b
        @return: True if a == b else False
        """
        if a["api"] == b["api"] and a["status"] == b["status"] and a["arguments"] == b["arguments"] and a["return"] == b["return"]:
            return True
        return False

    def wait_for_lastcall(self):
        """ If there is no lastcall, iterate through messages till a call is found or EOF.
        To get the next call, set self.lastcall to None before calling this function

        @return: True if there is a call, False on EOF
        """
        while not self.lastcall:
            try:
                if not self.parser.read_next_message():
                    return False
            except EOFError:
                return False

        return True

    def cacheless_next(self):
        if not self.fd:
            raise StopIteration()

        if not self.wait_for_lastcall():
            self.reset()
            raise StopIteration()

        self.api_count += 1
        if self.api_limit and self.api_count > self.api_limit:
            self.reset()
            raise StopIteration()

        nextcall, self.lastcall = self.lastcall, None

        self.wait_for_lastcall()
        while self.lastcall and self.compare_calls(nextcall, self.lastcall):
            nextcall["repeated"] += self.lastcall["repeated"] + 1
            self.lastcall = None
            self.wait_for_lastcall()

        nextcall["id"] = self.call_id
        self.call_id += 1

        return nextcall

    def __next__(self):
        """ Just accessing the cache
        """

        if cfg.processing.ram_boost:
            res = self.api_call_cache[self.api_pointer]
            if res is None:
                self.reset()
                raise StopIteration()
            self.api_pointer += 1
            return res
        else:
            return self.cacheless_next()

    def log_process(self, context, timestring, pid, ppid, modulepath, procname):
        """ log process information parsed from data file

        @param context: ignored
        @param timestring: Process first seen time
        @param pid: PID
        @param ppid: Parent PID
        @param modulepath: ignored
        @param procname: Process name
        """
        self.process_id, self.parent_id, self.process_name = pid, ppid, procname
        self.module_path = modulepath
        self.first_seen = timestring

    def log_thread(self, context, pid):
        pass

    def log_environ(self, context, environdict):
        """ log user/process environment information for later use in behavioral signatures

        @param context: ignored
        @param environdict: dict of the various collected information, which will expand over time
        """
        self.environdict.update(bytes2str(environdict))

    def log_anomaly(self, subcategory, tid, funcname, msg):
        """ log an anomaly parsed from data file

        @param subcategory:
        @param tid: Thread ID
        @param funcname:
        @param msg:
        """
        self.lastcall = dict(thread_id=tid, category="anomaly", api="", subcategory=subcategory, funcname=funcname, msg=msg)

    def log_call(self, context, apiname, category, arguments):
        """ log an api call from data file
        @param context: containing additional api info
        @param apiname: name of the api
        @param category: win32 function category
        @param arguments: arguments to the api call
        """
        apiindex, repeated, status, returnval, tid, timediff, caller, parentcaller = context

        current_time = self.first_seen + datetime.timedelta(0, 0, timediff * 1000)
        timestring = logtime(current_time)

        self.lastcall = self._parse([timestring, tid, caller, parentcaller, category, apiname, repeated, status, returnval] + arguments)

    def log_error(self, emsg):
        """ Log an error
        """
        log.warning("ParseProcessLog error condition on log %s: %s", str(self._log_path), emsg)

    def begin_reporting(self):
        self.reporting_mode = True
        if cfg.processing.ram_boost:
            idx = 0
            while True:
                ent = self.api_call_cache[idx]
                if not ent:
                    break
                # remove the values we don't want to encode in reports
                for arg in ent["arguments"]:
                    del arg["raw_value"]
                idx += 1

    def _parse(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """
        call = {}
        arguments = []

        try:
            timestamp = row[0]  # Timestamp of current API call invocation.
            thread_id = row[1]  # Thread ID.
            caller = row[2]  # non-system DLL return address
            parentcaller = row[3]  # non-system DLL parent of non-system-DLL return address
            category = row[4]  # Win32 function category.
            api_name = row[5]  # Name of the Windows API.
            repeated = row[6]  # Times log repeated
            status_value = row[7]  # Success or Failure?
            return_value = row[8]  # Value returned by the function.
        except IndexError as e:
            log.debug("Unable to parse process log row: %s", e)
            return None

        # Now walk through the remaining columns, which will contain API
        # arguments.
        for index in range(9, len(row)):
            argument = {}

            # Split the argument name with its value based on the separator.
            try:
                arg_name, arg_value = row[index]
            except ValueError as e:
                log.debug("Unable to parse analysis row argument (row=%s): %s", row[index], e)
                continue

            argument["name"] = arg_name
            if isinstance(arg_value, bytes):
                arg_value = bytes2str(arg_value)
            argument["value"] = convert_to_printable(str(arg_value), self.conversion_cache)
            if not self.reporting_mode:
                argument["raw_value"] = arg_value
            pretty = pretty_print_arg(category, api_name, arg_name, argument["value"])
            if pretty:
                argument["pretty_value"] = pretty
            arguments.append(argument)

        call["timestamp"] = timestamp
        call["thread_id"] = str(thread_id)
        call["caller"] = "0x%.08x" % default_converter(caller)
        call["parentcaller"] = "0x%.08x" % default_converter(parentcaller)
        call["category"] = category
        call["api"] = api_name
        call["status"] = bool(int(status_value))

        if isinstance(return_value, int) or isinstance(return_value, int):
            call["return"] = "0x%.08x" % default_converter(return_value)
        else:
            call["return"] = convert_to_printable(str(return_value), self.conversion_cache)

        prettyret = pretty_print_retval(category, api_name, call["status"], call["return"])
        if prettyret:
            call["pretty_return"] = prettyret

        call["arguments"] = arguments
        call["repeated"] = repeated

        # add the thread id to our thread set
        if call["thread_id"] not in self.threads:
            self.threads.append(call["thread_id"])

        return call


class Processes:
    """Processes analyzer."""

    def __init__(self, logs_path, task):
        """@param  logs_path: logs path."""
        self.task = task
        self._logs_path = logs_path
        self.options = get_options(self.task["options"])

    def run(self):
        """Run analysis.
        @return: processes infomartion list.
        """
        results = []

        if not os.path.exists(self._logs_path):
            log.warning('Analysis results folder does not exist at path "%s".', self._logs_path)
            return results

        # TODO: this should check the current analysis configuration and raise a warning
        # if injection is enabled and there is no logs folder.
        if len(os.listdir(self._logs_path)) == 0:
            log.info("Analysis results folder does not contain any file or injection was disabled.")
            return results

        for file_name in os.listdir(self._logs_path):
            file_path = os.path.join(self._logs_path, file_name)

            # Check if Loop Detection is enabled globally or locally (as an option)
            if cfg_process.loop_detection.enabled or self.options.get("loop_detection"):
                self.compress_log_file(file_path)

            if os.path.isdir(file_path):
                continue

            # Skipping the current log file if it's too big.
            if os.stat(file_path).st_size > cfg.processing.analysis_size_limit:
                log.warning("Behavioral log {0} too big to be processed, skipped.".format(file_name))
                continue

            # Invoke parsing of current log file (if ram_boost is enabled, otherwise parsing is done on-demand)
            current_log = ParseProcessLog(file_path)
            if current_log.process_id is None:
                continue

            # If the current log actually contains any data, add its data to
            # the results list.
            results.append(
                {
                    "process_id": current_log.process_id,
                    "process_name": bytes2str(current_log.process_name),
                    "parent_id": current_log.parent_id,
                    "module_path": bytes2str(current_log.module_path),
                    "first_seen": logtime(current_log.first_seen),
                    "calls": current_log.calls,
                    "threads": current_log.threads,
                    "environ": current_log.environdict,
                }
            )

        # Sort the items in the results list chronologically. In this way we
        # can have a sequential order of spawned processes.
        results.sort(key=lambda process: process["first_seen"])

        return results

    def compress_log_file(self, file_path):
        if file_path.endswith(".bson") and os.stat(file_path).st_size:
            try:
                if not CuckooBsonCompressor().run(file_path):
                    log.debug("Could not execute loop detection analysis.")
                else:
                    log.debug("BSON was compressed successfully.")
                    return True
            except Exception as e:
                log.error("BSON compression failed on file {}: {}".format(file_path, e))
        else:
            log.debug("Nonexistent or empty BSON file {}".format(file_path))

        return False


class Summary:
    """Generates summary information."""

    key = "summary"

    def __init__(self):
        self.keys = []
        self.read_keys = []
        self.write_keys = []
        self.delete_keys = []
        self.mutexes = []
        self.files = []
        self.read_files = []
        self.write_files = []
        self.delete_files = []
        self.started_services = []
        self.created_services = []
        self.executed_commands = []
        self.resolved_apis = []

    def get_argument(self, call, argname, strip=False):
        for arg in call["arguments"]:
            if arg["name"] == argname:
                if strip:
                    return arg["value"].strip()
                else:
                    return arg["value"]
        return None

    def get_raw_argument(self, call, argname):
        for arg in call["arguments"]:
            if arg["name"] == argname:
                return arg["raw_value"]
        return None

    def event_apicall(self, call, process):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """

        if call["api"].startswith("RegOpenKeyEx"):
            name = self.get_argument(call, "FullName")
            if name and name not in self.keys:
                self.keys.append(name)
        elif call["api"].startswith("RegSetValue") or call["api"] == "NtSetValueKey":
            name = self.get_argument(call, "FullName")
            if name and name not in self.keys:
                self.keys.append(name)
            if name and name not in self.write_keys:
                self.write_keys.append(name)
        elif call["api"] == "NtDeleteValueKey" or call["api"] == "NtDeleteKey" or call["api"].startswith("RegDeleteValue"):
            name = self.get_argument(call, "FullName")
            if name and name not in self.keys:
                self.keys.append(name)
            if name and name not in self.delete_keys:
                self.delete_keys.append(name)
        elif call["api"].startswith("RegCreateKeyEx"):
            name = self.get_argument(call, "FullName")
            disposition = int(self.get_argument(call, "Disposition"), 10)
            if name and name not in self.keys:
                self.keys.append(name)
            # if disposition == 1 then we created a new key
            if name and disposition == 1 and name not in self.write_keys:
                self.write_keys.append(name)
        elif call["api"].startswith("NtOpenKey"):
            name = self.get_argument(call, "ObjectAttributes")
            if name and name not in self.keys:
                self.keys.append(name)
        elif call["api"] == "NtCreateKey":
            name = self.get_argument(call, "ObjectAttributes")
            disposition = int(self.get_argument(call, "Disposition"), 10)
            if name and name not in self.keys:
                self.keys.append(name)
            # if disposition == 1 then we created a new key
            if name and disposition == 1 and name not in self.write_keys:
                self.write_keys.append(name)
        elif call["api"].startswith("RegQueryValue") or call["api"] == "NtQueryValueKey" or call["api"] == "NtQueryMultipleValueKey":
            name = self.get_argument(call, "FullName")
            if name and name not in self.keys:
                self.keys.append(name)
            if name and name not in self.read_keys:
                self.read_keys.append(name)
        elif call["api"] == "SHGetFileInfoW":
            filename = self.get_argument(call, "Path")
            if filename and (len(filename) < 2 or filename[1] != ":"):
                filename = None
            if filename and filename not in self.files:
                self.files.append(filename)
        elif call["api"] == "ShellExecuteExW":
            filename = self.get_argument(call, "FilePath")
            if len(filename) < 2 or filename[1] != ":":
                filename = None
            if filename and filename not in self.files:
                self.files.append(filename)
            path = self.get_argument(call, "FilePath", strip=True)
            params = self.get_argument(call, "Parameters", strip=True)
            cmdline = None
            if path:
                cmdline = path + " " + params
            if cmdline and cmdline not in self.executed_commands:
                self.executed_commands.append(cmdline)
        elif call["api"] == "NtSetInformationFile":
            filename = self.get_argument(call, "HandleName")
            infoclass = int(self.get_argument(call, "FileInformationClass"), 10)
            fileinfo = self.get_raw_argument(call, "FileInformation")
            if filename and infoclass and infoclass == 13 and fileinfo and len(fileinfo) > 0:
                if not isinstance(fileinfo, bytes):
                    fileinfo = fileinfo.encode("utf-8")
                disp = struct.unpack_from("B", fileinfo)[0]
                if disp and filename not in self.delete_files:
                    self.delete_files.append(filename)

        elif call["api"].startswith("DeleteFile") or call["api"] == "NtDeleteFile" or call["api"].startswith("RemoveDirectory"):
            filename = self.get_argument(call, "FileName")
            if not filename:
                filename = self.get_argument(call, "DirectoryName")
            if filename:
                if filename not in self.files:
                    self.files.append(filename)
                if filename not in self.delete_files:
                    self.delete_files.append(filename)
        elif call["api"].startswith("StartService"):
            servicename = self.get_argument(call, "ServiceName", strip=True)
            if servicename and servicename not in self.started_services:
                self.started_services.append(servicename)

        elif call["api"].startswith("CreateService"):
            servicename = self.get_argument(call, "ServiceName", strip=True)
            if servicename and servicename not in self.created_services:
                self.created_services.append(servicename)

        elif call["api"] in ["CreateProcessInternalW", "NtCreateUserProcess", "CreateProcessWithTokenW", "CreateProcessWithLogonW"]:
            cmdline = self.get_argument(call, "CommandLine", strip=True)
            appname = self.get_argument(call, "ApplicationName", strip=True)
            if appname and cmdline:
                base = ".".join(appname.split("\\")[-1].split(".")[:-1])
                firstarg = ""
                if cmdline[0] == '"':
                    firstarg = cmdline[1:].split('"')[0]
                else:
                    firstarg = cmdline.split(" ")[0]
                if base not in firstarg:
                    cmdline = appname + " " + cmdline
            if cmdline and cmdline not in self.executed_commands:
                self.executed_commands.append(cmdline)

        elif call["api"] == "LdrGetProcedureAddress" and call["status"]:
            dllname = self.get_argument(call, "ModuleName").lower()
            funcname = self.get_argument(call, "FunctionName")
            if not funcname:
                funcname = "#" + str(self.get_argument(call, "Ordinal"))
            combined = dllname + "." + funcname
            if combined not in self.resolved_apis:
                self.resolved_apis.append(combined)

        elif call["api"].startswith("NtCreateProcess"):
            cmdline = self.get_argument(call, "FileName")
            if cmdline and cmdline not in self.executed_commands:
                self.executed_commands.append(cmdline)

        elif call["api"] == "MoveFileWithProgressW" or call["api"] == "MoveFileWithProgressTransactedW":
            origname = self.get_argument(call, "ExistingFileName")
            newname = self.get_argument(call, "NewFileName")
            if origname:
                if origname not in self.files:
                    self.files.append(origname)
                if origname not in self.delete_files:
                    self.delete_files.append(origname)
            if newname:
                if newname not in self.files:
                    self.files.append(newname)
                if newname not in self.write_files:
                    self.write_files.append(newname)

        elif call["category"] == "filesystem":
            filename = self.get_argument(call, "FileName")
            if not filename:
                filename = self.get_argument(call, "DirectoryName")
            srcfilename = self.get_argument(call, "ExistingFileName")
            dstfilename = self.get_argument(call, "NewFileName")
            access = None
            accessval = self.get_argument(call, "DesiredAccess")
            if accessval:
                access = int(accessval, 16)
            if filename:
                if (
                    access
                    and (access & 0x80000000 or access & 0x10000000 or access & 0x02000000 or access & 0x1)
                    and filename not in self.read_files
                ):
                    self.read_files.append(filename)
                if (
                    access
                    and (access & 0x40000000 or access & 0x10000000 or access & 0x02000000 or access & 0x6)
                    and filename not in self.write_files
                ):
                    self.write_files.append(filename)
                if filename not in self.files:
                    self.files.append(filename)
            if srcfilename:
                if srcfilename not in self.read_files:
                    self.read_files.append(srcfilename)
                if srcfilename not in self.files:
                    self.files.append(srcfilename)
            if dstfilename:
                if dstfilename not in self.write_files:
                    self.write_files.append(dstfilename)
                if dstfilename not in self.files:
                    self.files.append(dstfilename)

        elif call["category"] == "synchronization":
            value = self.get_argument(call, "MutexName")
            if value and value not in self.mutexes:
                self.mutexes.append(value)

    def run(self):
        """Get registry keys, mutexes and files.
        @return: Summary of keys, read keys, written keys, mutexes and files.
        """
        return {
            "files": self.files,
            "read_files": self.read_files,
            "write_files": self.write_files,
            "delete_files": self.delete_files,
            "keys": self.keys,
            "read_keys": self.read_keys,
            "write_keys": self.write_keys,
            "delete_keys": self.delete_keys,
            "executed_commands": self.executed_commands,
            "resolved_apis": self.resolved_apis,
            "mutexes": self.mutexes,
            "created_services": self.created_services,
            "started_services": self.started_services,
        }


class Enhanced(object):
    """Generates a more extensive high-level representation than Summary."""

    key = "enhanced"

    def __init__(self, details=False):
        """
        @param details: Also add some (not so relevant) Details to the log
        """
        self.eid = 0
        self.details = details
        self.modules = {}
        self.procedures = {}
        self.events = []

    def _add_procedure(self, mbase, name, base):
        """
        Add a procedure address
        """
        self.procedures[base] = "{0}:{1}".format(self._get_loaded_module(mbase), name)

    def _add_loaded_module(self, name, base):
        """
        Add a loaded module to the internal database
        """
        self.modules[base] = name

    def _get_loaded_module(self, base):
        """
        Get the name of a loaded module from the internal db
        """
        return self.modules.get(base, "")

    def _process_call(self, call):
        """ Gets files calls
        @return: information list
        """

        def _load_args(call):
            """
            Load arguments from call
            """
            res = {}
            for argument in call["arguments"]:
                res[argument["name"]] = argument["value"]

            return res

        def _generic_handle_details(self, call, item):
            """
            Generic handling of api calls
            @call: the call dict
            @item: Generic item to process
            """
            event = None
            if call["api"] in item["apis"]:
                args = _load_args(call)
                self.eid += 1

                event = {"event": item["event"], "object": item["object"], "timestamp": call["timestamp"], "eid": self.eid, "data": {}}

                for logname, dataname in item["args"]:
                    event["data"][logname] = args.get(dataname)
                return event

        def _generic_handle(self, data, call):
            """Generic handling of api calls."""
            for item in data:
                event = _generic_handle_details(self, call, item)
                if event:
                    return event

            return None

        def _get_service_action(control_code):
            """@see: http://msdn.microsoft.com/en-us/library/windows/desktop/ms682108%28v=vs.85%29.aspx"""
            codes = {1: "stop", 2: "pause", 3: "continue", 4: "info"}

            default = "user" if int(control_code) >= 128 else "notify"
            return codes.get(control_code, default)

        event = None

        gendat = [
            {
                "event": "move",
                "object": "file",
                "apis": ["MoveFileWithProgressW", "MoveFileWithProgressTransactedW",],
                "args": [("from", "ExistingFileName"), ("to", "NewFileName")],
            },
            {
                "event": "copy",
                "object": "file",
                "apis": ["CopyFileA", "CopyFileW", "CopyFileExW", "CopyFileExA"],
                "args": [("from", "ExistingFileName"), ("to", "NewFileName")],
            },
            {"event": "delete", "object": "file", "apis": ["DeleteFileA", "DeleteFileW", "NtDeleteFile"], "args": [("file", "FileName")]},
            {"event": "delete", "object": "dir", "apis": ["RemoveDirectoryA", "RemoveDirectoryW"], "args": [("file", "DirectoryName")]},
            {"event": "create", "object": "dir", "apis": ["CreateDirectoryW", "CreateDirectoryExW"], "args": [("file", "DirectoryName")]},
            {"event": "write", "object": "file", "apis": ["URLDownloadToFileW", "URLDownloadToFileA"], "args": [("file", "FileName")]},
            {"event": "read", "object": "file", "apis": ["NtReadFile",], "args": [("file", "HandleName")]},
            {"event": "write", "object": "file", "apis": ["NtWriteFile",], "args": [("file", "HandleName")]},
            {
                "event": "execute",
                "object": "file",
                "apis": [
                    "CreateProcessAsUserA",
                    "CreateProcessAsUserW",
                    "CreateProcessA",
                    "CreateProcessW",
                    "NtCreateProcess",
                    "NtCreateProcessEx",
                ],
                "args": [("file", "FileName")],
            },
            {
                "event": "execute",
                "object": "file",
                "apis": ["CreateProcessInternalW", "CreateProcessWithLogonW", "CreateProcessWithTokenW",],
                "args": [("file", "CommandLine")],
            },
            {"event": "execute", "object": "file", "apis": ["ShellExecuteExA", "ShellExecuteExW",], "args": [("file", "FilePath")]},
            {
                "event": "load",
                "object": "library",
                "apis": ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrLoadDll", "LdrGetDllHandle"],
                "args": [("file", "FileName"), ("pathtofile", "PathToFile"), ("moduleaddress", "BaseAddress")],
            },
            {
                "event": "findwindow",
                "object": "windowname",
                "apis": ["FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW"],
                "args": [("classname", "ClassName"), ("windowname", "WindowName")],
            },
            {
                "event": "write",
                "object": "registry",
                "apis": ["RegSetValueExA", "RegSetValueExW"],
                "args": [("regkey", "FullName"), ("content", "Buffer")],
            },
            {"event": "write", "object": "registry", "apis": ["RegCreateKeyExA", "RegCreateKeyExW"], "args": [("regkey", "FullName")]},
            {
                "event": "read",
                "object": "registry",
                "apis": ["RegQueryValueExA", "RegQueryValueExW",],
                "args": [("regkey", "FullName"), ("content", "Data")],
            },
            {"event": "read", "object": "registry", "apis": ["NtQueryValueKey"], "args": [("regkey", "FullName"), ("content", "Information")]},
            {
                "event": "delete",
                "object": "registry",
                "apis": ["RegDeleteKeyA", "RegDeleteKeyW", "RegDeleteValueA", "RegDeleteValueW", "NtDeleteValueKey"],
                "args": [("regkey", "FullName")],
            },
            {
                "event": "create",
                "object": "windowshook",
                "apis": ["SetWindowsHookExA"],
                "args": [("id", "HookIdentifier"), ("moduleaddress", "ModuleAddress"), ("procedureaddress", "ProcedureAddress")],
            },
            {"event": "start", "object": "service", "apis": ["StartServiceA", "StartServiceW"], "args": [("service", "ServiceName")]},
            {
                "event": "modify",
                "object": "service",
                "apis": ["ControlService"],
                "args": [("service", "ServiceName"), ("controlcode", "ControlCode")],
            },
            {"event": "delete", "object": "service", "apis": ["DeleteService"], "args": [("service", "ServiceName")]},
        ]

        # Not sure I really want this, way too noisy anyway and doesn't bring
        # much value.
        # if self.details:
        #    gendata = gendata + [{"event" : "get",
        #           "object" : "procedure",
        #           "apis" : ["LdrGetProcedureAddress"],
        #           "args": [("name", "FunctionName"), ("ordinal", "Ordinal")]
        #          },]

        event = _generic_handle(self, gendat, call)
        args = _load_args(call)

        if event:
            if call["api"] in ["LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrGetDllHandle"] and call["status"]:
                self._add_loaded_module(args.get("FileName", ""), args.get("ModuleHandle", ""))

            elif call["api"] in ["LdrLoadDll"] and call["status"]:
                self._add_loaded_module(args.get("FileName", ""), args.get("BaseAddress", ""))

            elif call["api"] in ["LdrGetProcedureAddress"] and call["status"]:
                self._add_procedure(args.get("ModuleHandle", ""), args.get("FunctionName", ""), args.get("FunctionAddress", ""))
                event["data"]["module"] = self._get_loaded_module(args.get("ModuleHandle", ""))

            elif call["api"] in ["SetWindowsHookExA"]:
                event["data"]["module"] = self._get_loaded_module(args.get("ModuleAddress", ""))

            if call["api"] in ["ControlService"]:
                event["data"]["action"] = _get_service_action(args["ControlCode"])

            return event

        return event

    def event_apicall(self, call, process):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """
        event = self._process_call(call)
        if event:
            self.events.append(event)

    def run(self):
        """Get registry keys, mutexes and files.
        @return: Summary of keys, mutexes and files.
        """
        return self.events


class Anomaly(object):

    """Anomaly detected during analysis.
    For example: a malware tried to remove Cuckoo's hooks.
    """

    key = "anomaly"

    def __init__(self):
        self.anomalies = []

    def event_apicall(self, call, process):
        """Process API calls.
        @param call: API call object
        @param process: process object
        """
        if call["category"] != "anomaly":
            return

        category, funcname, message = None, None, None
        for row in call["arguments"]:
            if row["name"] == "Subcategory":
                category = row["value"]
            if row["name"] == "FunctionName":
                funcname = row["value"]
            if row["name"] == "Message":
                message = row["value"]

        self.anomalies.append(
            dict(name=process["process_name"], pid=process["process_id"], category=category, funcname=funcname, message=message,)
        )

    def run(self):
        """Fetch all anomalies."""
        return self.anomalies


class ProcessTree:
    """Generates process tree."""

    key = "processtree"

    def __init__(self):
        self.processes = []
        self.tree = []

    def add_node(self, node, tree):
        """Add a node to a process tree.
        @param node: node to add.
        @param tree: processes tree.
        @return: boolean with operation success status.
        """
        # Walk through the existing tree.
        ret = False
        for process in tree:
            # If the current process has the same ID of the parent process of
            # the provided one, append it the children.
            if process["pid"] == node["parent_id"]:
                process["children"].append(node)
                ret = True
                break
            # Otherwise try with the children of the current process.
            else:
                if self.add_node(node, process["children"]):
                    ret = True
                    break
        return ret

    def event_apicall(self, call, process):
        for entry in self.processes:
            if entry["pid"] == process["process_id"]:
                return

        self.processes.append(
            dict(
                name=process["process_name"],
                pid=process["process_id"],
                parent_id=process["parent_id"],
                module_path=process["module_path"],
                children=[],
                threads=process["threads"],
                environ=process["environ"],
            )
        )

    def run(self):
        children = []

        # Walk through the generated list of processes.
        for process in self.processes:
            has_parent = False
            # Walk through the list again.
            for process_again in self.processes:
                if process_again == process:
                    continue
                # If we find a parent for the first process, we mark it as
                # as a child.
                if process_again["pid"] == process["parent_id"]:
                    has_parent = True
                    break

            # If the process has a parent, add it to the children list.
            if has_parent:
                children.append(process)
            # Otherwise it's an orphan and we add it to the tree root.
            else:
                self.tree.append(process)

        # Now we loop over the remaining child processes.
        for process in children:
            if not self.add_node(process, self.tree):
                self.tree.append(process)

        return self.tree


class EncryptedBuffers:
    """Generates summary information."""

    key = "encryptedbuffers"

    def __init__(self):
        self.bufs = []

    def get_argument(self, call, argname, strip=False):
        for arg in call["arguments"]:
            if arg["name"] == argname:
                if strip:
                    return arg["value"].strip()
                else:
                    return arg["value"]
        return None

    def get_raw_argument(self, call, argname):
        for arg in call["arguments"]:
            if arg["name"] == argname:
                return arg["raw_value"]
        return None

    def event_apicall(self, call, process):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """

        if call["api"].startswith("SslEncryptPacket"):
            buf = self.get_argument(call, "Buffer", strip=True)
            bufsize = self.get_argument(call, "BufferSize")
            if buf and buf not in self.bufs:
                self.bufs.append(
                    dict(
                        process_name=process["process_name"],
                        pid=process["process_id"],
                        api_call="SslEncryptPacket",
                        buffer=buf,
                        buffer_size=bufsize,
                    )
                )

        if call["api"].startswith("CryptEncrypt"):
            key = self.get_argument(call, "CryptKey")
            buf = self.get_argument(call, "Buffer", strip=True)
            if buf and buf not in self.bufs:
                self.bufs.append(
                    dict(process_name=process["process_name"], pid=process["process_id"], api_call="CryptEncrypt", buffer=buf, crypt_key=key,)
                )

        if call["api"].startswith("CryptEncryptMessage"):
            buf = self.get_argument(call, "Buffer", strip=True)
            if buf and buf not in self.bufs:
                self.bufs.append(
                    dict(process_name=process["process_name"], pid=process["process_id"], api_call="CryptEncryptMessage", buffer=buf,)
                )

    def run(self):
        """Get registry keys, mutexes and files.
        @return: Summary of keys, read keys, written keys, mutexes and files.
        """
        return self.bufs


class BehaviorAnalysis(Processing):
    """Behavior Analyzer."""

    key = "behavior"

    def run(self):
        """Run analysis.
        @return: results dict.
        """
        behavior = {}
        behavior["processes"] = Processes(self.logs_path, self.task).run()

        instances = [
            Anomaly(),
            ProcessTree(),
            Summary(),
            Enhanced(),
            EncryptedBuffers(),
        ]
        # Iterate calls and tell interested signatures about them
        for process in behavior["processes"]:
            for call in process["calls"]:
                for instance in instances:
                    try:
                        instance.event_apicall(call, process)
                    except:
                        log.exception('Failure in partial behavior "%s"', instance.key)

        for instance in instances:
            try:
                behavior[instance.key] = instance.run()
            except:
                log.exception('Failed to run partial behavior class "%s"', instance.key)

        return behavior
