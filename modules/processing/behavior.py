# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import json
import logging
import os
import struct
from contextlib import suppress

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.compressor import CuckooBsonCompressor
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.netlog import BsonParser
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.replace_patterns_utils import _clean_path, check_deny_pattern
from lib.cuckoo.common.utils import (
    bytes2str,
    convert_to_printable,
    default_converter,
    logtime,
    pretty_print_arg,
    pretty_print_retval,
)

log = logging.getLogger(__name__)
cfg = Config()
integrations_conf = Config("integrations")

HAVE_FLARE_CAPA = False
# required to not load not enabled dependencies
if integrations_conf.flare_capa.enabled and integrations_conf.flare_capa.behavior:
    from lib.cuckoo.common.integrations.capa import HAVE_FLARE_CAPA, flare_capa_details


class ParseProcessLog(list):
    """Parses process log file."""

    def __init__(self, log_path, options):
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
        self.options = options
        # Limit of API calls per process
        self.api_limit = self.options.analysis_call_limit

        if path_exists(log_path) and os.stat(log_path).st_size > 0:
            self.parse_first_and_reset()

        if self.options.ram_boost:
            self.api_call_cache = []
            self.api_pointer = 0

            with suppress(StopIteration):
                while True:
                    i = self.cacheless_next()
                    self.api_call_cache.append(i)
            self.api_call_cache.append(None)

    def parse_first_and_reset(self):
        """Open file and init Bson Parser. Read till first process"""
        if not self._log_path.endswith(".bson"):
            return

        self.fd = open(self._log_path, "rb")
        self.parser = BsonParser(self)

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
        """Read data from log file

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
        # log.debug("iter called by: %s", inspect.stack()[1])
        # import code; code.interact(local=dict(locals(), **globals()))
        return self

    def __repr__(self):
        return f"<ParseProcessLog log-path: {self._log_path}>"

    def __nonzero__(self):
        return self.wait_for_lastcall()

    def reset(self):
        """Reset fd"""
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
        return (
            a["api"] == b["api"] and a["status"] == b["status"] and a["arguments"] == b["arguments"] and a["return"] == b["return"]
        )

    def wait_for_lastcall(self):
        """If there is no lastcall, iterate through messages till a call is found or EOF.
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
        """Just accessing the cache"""

        if not self.options.ram_boost:
            return self.cacheless_next()
        res = self.api_call_cache[self.api_pointer]
        if res is None:
            self.reset()
            raise StopIteration()
        self.api_pointer += 1
        return res

    def log_process(self, context, timestring, pid, ppid, modulepath, procname):
        """log process information parsed from data file

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
        """log user/process environment information for later use in behavioral signatures

        @param context: ignored
        @param environdict: dict of the various collected information, which will expand over time
        """
        environdict = bytes2str(environdict)
        if self.options.replace_patterns:
            for key in ("UserName", "ComputerName", "TempPath", "CommandLine"):
                environdict[key] = _clean_path(environdict[key], self.options.replace_patterns)
        self.environdict.update(environdict)

    def log_anomaly(self, subcategory, tid, funcname, msg):
        """log an anomaly parsed from data file

        @param subcategory:
        @param tid: Thread ID
        @param funcname:
        @param msg:
        """
        self.lastcall = {
            "thread_id": tid,
            "category": "anomaly",
            "api": "",
            "subcategory": subcategory,
            "funcname": funcname,
            "msg": msg,
        }

    def log_call(self, context, apiname, category, arguments):
        """log an api call from data file
        @param context: containing additional api info
        @param apiname: name of the api
        @param category: win32 function category
        @param arguments: arguments to the api call
        """
        apiindex, repeated, status, returnval, tid, timediff, caller, parentcaller = context

        current_time = self.first_seen + datetime.timedelta(0, 0, timediff * 1000)
        timestring = logtime(current_time)

        self.lastcall = self._parse(
            [timestring, tid, caller, parentcaller, category, apiname, repeated, status, returnval] + arguments
        )

    def log_error(self, emsg):
        """Log an error"""
        log.warning("ParseProcessLog error condition on log %s: %s", self._log_path, emsg)

    def begin_reporting(self):
        self.reporting_mode = True
        if self.options.ram_boost:
            idx = 0
            ent = self.api_call_cache[idx]
            while ent:
                # remove the values we don't want to encode in reports
                for arg in ent["arguments"]:
                    with suppress(KeyError):
                        if "raw_value" in arg:
                            del arg["raw_value"]
                        elif "raw_value_string" in arg:
                            del arg["raw_value_string"]
                idx += 1
                ent = self.api_call_cache[idx]

    def _parse(self, row):
        """Parse log row.
        @param row: row data.
        @return: parsed information dict.
        """
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

        # Now walk through the remaining columns, which will contain API arguments.

        for api_arg in row[9:]:
            # Split the argument name with its value based on the separator.
            try:
                arg_name, arg_value = api_arg
            except ValueError as e:
                log.debug("Unable to parse analysis row argument (row=%s): %s", api_arg, e)
                continue

            argument = {"name": arg_name}
            arg_value_raw = arg_value
            if isinstance(arg_value, bytes):
                arg_value = bytes2str(arg_value)

            if arg_value and isinstance(arg_value, list) and len(arg_value) >= 1 and isinstance(arg_value[0], bytes):
                arg_value = " ".join(bytes2str(arg_value))

            try:
                argument["value"] = convert_to_printable(arg_value, self.conversion_cache)
            except Exception:
                log.exception(arg_value)
                continue
            if not self.reporting_mode:
                if isinstance(arg_value_raw, bytes):
                    argument["raw_value"] = bytes.hex(arg_value_raw)
                elif isinstance(arg_value_raw, int) and arg_value_raw > 0x7FFFFFFFFFFFFFFF:
                    # Mongo can't support ints larger than this.
                    argument["raw_value_string"] = str(arg_value_raw)
                else:
                    argument["raw_value"] = arg_value

            pretty = pretty_print_arg(category, api_name, arg_name, argument["value"])
            if pretty:
                argument["pretty_value"] = pretty

            arguments.append(argument)

        call = {
            "timestamp": timestamp,
            "thread_id": str(thread_id),
            "caller": f"0x{default_converter(caller):08x}",
            "parentcaller": f"0x{default_converter(parentcaller):08x}",
            "category": category,
            "api": api_name,
            "status": bool(int(status_value)),
        }

        if isinstance(return_value, int):
            call["return"] = f"0x{default_converter(return_value):08x}"
        else:
            call["return"] = convert_to_printable(str(return_value), self.conversion_cache)

        prettyret = pretty_print_retval(call["status"], call["return"])
        if prettyret:
            call["pretty_return"] = prettyret

        call["arguments"] = arguments
        call["repeated"] = repeated

        # add the thread id to our thread set
        if call["thread_id"] not in self.threads:
            self.threads.append(call["thread_id"])

        if (
            api_name == "DllLoadNotification"
            and len(arguments) == 3
            and arguments[-1].get("name", "") == "DllBase"
            and arguments[0].get("value", "") == "load"
            and "DllBase" not in self.environdict
            and _clean_path(arguments[1]["value"], self.options.replace_patterns) in self.environdict.get("CommandLine", "")
        ):
            self.environdict.setdefault("DllBase", arguments[-1]["value"])

        return call


class Processes:
    """Processes analyzer."""

    def __init__(self, logs_path, task, options):
        """@param  logs_path: logs path."""
        self.task = task
        self._logs_path = logs_path
        self.options = options

    def run(self):
        """Run analysis.
        @return: processes infomartion list.
        """
        results = []

        if not path_exists(self._logs_path):
            log.warning('Analysis results folder does not exist at path "%s"', self._logs_path)
            return results

        # TODO: this should check the current analysis configuration and raise a warning
        # if injection is enabled and there is no logs folder.
        if len(os.listdir(self._logs_path)) == 0:
            log.debug("Analysis results folder does not contain any file or injection was disabled")
            return results

        for file_name in os.listdir(self._logs_path):
            file_path = os.path.join(self._logs_path, file_name)

            if self.options.loop_detection:
                self.compress_log_file(file_path)

            if os.path.isdir(file_path):
                continue

            # Skipping the current log file if it's too big
            if os.stat(file_path).st_size > cfg.processing.analysis_size_limit:
                log.warning("Behavioral log %s too big to be processed, skipped", file_name)
                continue

            # Invoke parsing of current log file (if ram_boost is enabled, otherwise parsing is done on-demand)
            current_log = ParseProcessLog(file_path, self.options)
            if current_log.process_id is None:
                continue

            # If the current log actually contains any data, add its data to the results list.
            results.append(
                {
                    "process_id": current_log.process_id,
                    "process_name": bytes2str(current_log.process_name),
                    "parent_id": current_log.parent_id,
                    "module_path": _clean_path(bytes2str(current_log.module_path), self.options.replace_patterns),
                    "first_seen": logtime(current_log.first_seen),
                    "calls": current_log.calls,
                    "threads": current_log.threads,
                    "environ": current_log.environdict,
                    "file_activities": {"read_files": [], "write_files": [], "delete_files": []},
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
                    log.debug("Could not execute loop detection analysis")
                else:
                    log.debug("BSON was compressed successfully")
                    return True
            except Exception as e:
                log.error("BSON compression failed on file %s: %s", file_path, e)
        else:
            log.debug("Nonexistent or empty BSON file %s", file_path)

        return False


class Summary:
    """Generates summary information."""

    key = "summary"

    def __init__(self, options):
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
        self.options = options

    def get_argument(self, call, argname, strip=False):
        return next(
            (arg["value"].strip() if strip else arg["value"] for arg in call["arguments"] if arg["name"] == argname),
            None,
        )

    def get_raw_argument(self, call, argname):
        return next(
            (arg["raw_value"] for arg in call["arguments"] if arg["name"] == argname),
            None,
        )

    def _filtering_helper(self, source_list, pattern):
        if not pattern:
            return
        if self.options.replace_patterns:
            check_deny_pattern(source_list, pattern)
        else:
            source_list.append(pattern)

    def _add_file_activity(self, process, key, filename):
        if not filename:
            return
        if self.options.file_activities:
            process["file_activities"][key].append(filename)

    def event_apicall(self, call, process):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """
        if call["api"].startswith("RegOpenKeyEx"):
            name = self.get_argument(call, "FullName")
            if name and name not in self.keys:
                self._filtering_helper(self.keys, name)
        elif call["api"].startswith("RegSetValue") or call["api"] == "NtSetValueKey":
            name = self.get_argument(call, "FullName")
            if name and name not in self.keys:
                self._filtering_helper(self.keys, name)
            if name and name not in self.write_keys:
                self._filtering_helper(self.write_keys, name)
        elif call["api"] == "NtCreateKey" or call["api"].startswith("RegCreateKeyEx"):
            name = self.get_argument(call, "ObjectAttributes" if call["api"] == "NtCreateKey" else "FullName")
            disposition = int(self.get_argument(call, "Disposition"))
            if name and name not in self.keys:
                self._filtering_helper(self.keys, name)
            # if disposition == 1 then we created a new key
            if name and disposition == 1 and name not in self.write_keys:
                self.write_keys.append(name)

        elif call["api"] in ("NtDeleteValueKey", "NtDeleteKey") or call["api"].startswith("RegDeleteValue"):
            name = self.get_argument(call, "FullName")
            if name and name not in self.keys:
                self._filtering_helper(self.keys, name)
            if name and name not in self.delete_keys:
                self.delete_keys.append(name)
        elif call["api"].startswith("NtOpenKey"):
            name = self.get_argument(call, "ObjectAttributes")
            if name and name not in self.keys:
                self._filtering_helper(self.keys, name)
        elif call["api"] in ("NtQueryValueKey", "NtQueryMultipleValueKey") or call["api"].startswith("RegQueryValue"):
            name = self.get_argument(call, "FullName")
            if name and name not in self.keys:
                self._filtering_helper(self.keys, name)
            if name and name not in self.read_keys:
                self._filtering_helper(self.read_keys, name)
        elif call["api"] == "SHGetFileInfoW":
            filename = self.get_argument(call, "Path")
            if filename and (len(filename) < 2 or filename[1] != ":"):
                filename = None
            if filename and filename not in self.files:
                self._filtering_helper(self.files, filename)
        elif call["api"] == "ShellExecuteExW":
            filename = self.get_argument(call, "FilePath")
            if len(filename) < 2 or filename[1] != ":":
                filename = None
            if filename and filename not in self.files:
                self._filtering_helper(self.files, filename)
            path = self.get_argument(call, "FilePath", strip=True)
            params = self.get_argument(call, "Parameters", strip=True)
            cmdline = f"{path} {params}" if path else None
            if cmdline and cmdline not in self.executed_commands:
                self._filtering_helper(self.executed_commands, cmdline)
        elif call["api"] == "NtSetInformationFile":
            filename = self.get_argument(call, "HandleName")
            infoclass = int(self.get_argument(call, "FileInformationClass"))
            fileinfo = self.get_raw_argument(call, "FileInformation")
            if filename and infoclass and infoclass == 13 and fileinfo and len(fileinfo) > 0:
                if not isinstance(fileinfo, bytes):
                    fileinfo = fileinfo.encode()
                disp = struct.unpack_from("B", fileinfo)[0]
                if disp and filename not in self.delete_files:
                    self._filtering_helper(self.delete_files, filename)
                    self._add_file_activity(process, "delete_files", filename)
        elif call["api"].startswith("DeleteFile") or call["api"] == "NtDeleteFile" or call["api"].startswith("RemoveDirectory"):
            filename = self.get_argument(call, "FileName")
            if not filename:
                filename = self.get_argument(call, "DirectoryName")
            if filename:
                if filename not in self.files:
                    self._filtering_helper(self.files, filename)
                if filename not in self.delete_files:
                    self._filtering_helper(self.delete_files, filename)
                    self._add_file_activity(process, "delete_files", filename)
        elif call["api"].startswith("StartService"):
            servicename = self.get_argument(call, "ServiceName", strip=True)
            if servicename and servicename not in self.started_services:
                self._filtering_helper(self.started_services, servicename)
        elif call["api"].startswith("CreateService"):
            servicename = self.get_argument(call, "ServiceName", strip=True)
            if servicename and servicename not in self.created_services:
                self._filtering_helper(self.created_services, servicename)
        elif call["api"] in ("CreateProcessInternalW", "NtCreateUserProcess", "CreateProcessWithTokenW", "CreateProcessWithLogonW"):
            cmdline = self.get_argument(call, "CommandLine", strip=True)
            appname = self.get_argument(call, "ApplicationName", strip=True)
            if appname and cmdline:
                base = appname.rsplit("\\", 1)[-1].rsplit(".", 1)[0]
                firstarg = ""
                if cmdline[0] == '"':
                    firstarg = cmdline[1:].split('"', 1)[0]
                else:
                    firstarg = cmdline.split(" ", 1)[0]
                if base not in firstarg:
                    cmdline = f"{appname} {cmdline}"
            if cmdline and cmdline not in self.executed_commands:
                self._filtering_helper(self.executed_commands, cmdline)

        elif call["api"] == "LdrGetProcedureAddress" and call["status"]:
            dllname = self.get_argument(call, "ModuleName").lower()
            funcname = self.get_argument(call, "FunctionName")
            if not funcname:
                funcname = f"#{self.get_argument(call, 'Ordinal')}"
            combined = f"{dllname}.{funcname}"
            if combined not in self.resolved_apis:
                self.resolved_apis.append(combined)

        elif call["api"].startswith("NtCreateProcess"):
            cmdline = self.get_argument(call, "FileName")
            if cmdline and cmdline not in self.executed_commands:
                self._filtering_helper(self.executed_commands, cmdline)

        elif call["api"] in ("MoveFileWithProgressW", "MoveFileWithProgressTransactedW"):
            origname = self.get_argument(call, "ExistingFileName")
            newname = self.get_argument(call, "NewFileName")
            if origname:
                if origname not in self.files:
                    self._filtering_helper(self.files, origname)
                if origname not in self.delete_files:
                    self._filtering_helper(self.delete_files, origname)
                    self._add_file_activity(process, "delete_files", origname)
            if newname:
                if newname not in self.files:
                    self._filtering_helper(self.files, newname)
                if newname not in self.write_files:
                    self._filtering_helper(self.write_files, newname)
                    self._add_file_activity(process, "write_files", newname)

        elif call["category"] == "filesystem":
            filename = self.get_argument(call, "FileName")
            if not filename:
                filename = self.get_argument(call, "DirectoryName")
            srcfilename = self.get_argument(call, "ExistingFileName")
            dstfilename = self.get_argument(call, "NewFileName")
            accessval = self.get_argument(call, "DesiredAccess")
            access = int(accessval, 16) if accessval else None
            if filename:
                if (
                    access
                    and (access & 0x80000000 or access & 0x10000000 or access & 0x02000000 or access & 0x1)
                    and filename not in self.read_files
                ):
                    # self.read_files.append(filename)
                    self._filtering_helper(self.read_files, srcfilename)
                    self._add_file_activity(process, "read_files", srcfilename)
                if (
                    access
                    and (access & 0x40000000 or access & 0x10000000 or access & 0x02000000 or access & 0x6)
                    and filename not in self.write_files
                ):
                    self._filtering_helper(self.write_files, srcfilename or filename)
                    self._add_file_activity(process, "write_files", srcfilename or filename)
                if filename not in self.files:
                    self._filtering_helper(self.files, filename)
            if srcfilename:
                if srcfilename not in self.read_files:
                    self._filtering_helper(self.read_files, srcfilename)
                    self._add_file_activity(process, "read_files", srcfilename)
                if srcfilename not in self.files:
                    self._filtering_helper(self.files, srcfilename)
            if dstfilename:
                if dstfilename not in self.write_files:
                    self._filtering_helper(self.write_files, dstfilename)
                    self._add_file_activity(process, "write_files", dstfilename)
                if dstfilename not in self.files:
                    self._filtering_helper(self.files, dstfilename)

        elif call["category"] == "synchronization":
            value = self.get_argument(call, "MutexName")
            if value and value not in self.mutexes:
                self._filtering_helper(self.mutexes, value)

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


class Enhanced:
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
        self.procedures[base] = f"{self._get_loaded_module(mbase)}:{name}"

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
        """Gets files calls
        @return: information list
        """

        def _load_args(call):
            """
            Load arguments from call
            """
            return {argument["name"]: argument["value"] for argument in call["arguments"]}

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

                event = {
                    "event": item["event"],
                    "object": item["object"],
                    "timestamp": call["timestamp"],
                    "eid": self.eid,
                    "data": {},
                }

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
                "apis": [
                    "MoveFileWithProgressW",
                    "MoveFileWithProgressTransactedW",
                ],
                "args": [("from", "ExistingFileName"), ("to", "NewFileName")],
            },
            {
                "event": "copy",
                "object": "file",
                "apis": ["CopyFileA", "CopyFileW", "CopyFileExW", "CopyFileExA"],
                "args": [("from", "ExistingFileName"), ("to", "NewFileName")],
            },
            {
                "event": "delete",
                "object": "file",
                "apis": ["DeleteFileA", "DeleteFileW", "NtDeleteFile"],
                "args": [("file", "FileName")],
            },
            {
                "event": "delete",
                "object": "dir",
                "apis": ["RemoveDirectoryA", "RemoveDirectoryW"],
                "args": [("file", "DirectoryName")],
            },
            {
                "event": "create",
                "object": "dir",
                "apis": ["CreateDirectoryW", "CreateDirectoryExW"],
                "args": [("file", "DirectoryName")],
            },
            {
                "event": "write",
                "object": "file",
                "apis": ["URLDownloadToFileW", "URLDownloadToFileA"],
                "args": [("file", "FileName")],
            },
            {
                "event": "read",
                "object": "file",
                "apis": [
                    "NtReadFile",
                ],
                "args": [("file", "HandleName")],
            },
            {
                "event": "write",
                "object": "file",
                "apis": [
                    "NtWriteFile",
                ],
                "args": [("file", "HandleName")],
            },
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
                "apis": [
                    "CreateProcessInternalW",
                    "CreateProcessWithLogonW",
                    "CreateProcessWithTokenW",
                ],
                "args": [("file", "CommandLine")],
            },
            {
                "event": "execute",
                "object": "file",
                "apis": [
                    "ShellExecuteExA",
                    "ShellExecuteExW",
                ],
                "args": [("file", "FilePath")],
            },
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
            {
                "event": "write",
                "object": "registry",
                "apis": ["RegCreateKeyExA", "RegCreateKeyExW"],
                "args": [("regkey", "FullName")],
            },
            {
                "event": "read",
                "object": "registry",
                "apis": [
                    "RegQueryValueExA",
                    "RegQueryValueExW",
                ],
                "args": [("regkey", "FullName"), ("content", "Data")],
            },
            {
                "event": "read",
                "object": "registry",
                "apis": ["NtQueryValueKey"],
                "args": [("regkey", "FullName"), ("content", "Information")],
            },
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
            {
                "event": "start",
                "object": "service",
                "apis": ["StartServiceA", "StartServiceW"],
                "args": [("service", "ServiceName")],
            },
            {
                "event": "modify",
                "object": "service",
                "apis": ["ControlService"],
                "args": [("service", "ServiceName"), ("controlcode", "ControlCode")],
            },
            {"event": "delete", "object": "service", "apis": ["DeleteService"], "args": [("service", "ServiceName")]},
        ]

        # Not sure I really want this, way too noisy anyway and doesn't bring much value.
        # if self.details:
        #    gendata += [{"event" : "get",
        #           "object" : "procedure",
        #           "apis" : ["LdrGetProcedureAddress"],
        #           "args": [("name", "FunctionName"), ("ordinal", "Ordinal")]
        #          },]

        event = _generic_handle(self, gendat, call)
        args = _load_args(call)

        if event:
            if (
                call["api"] in ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "LdrGetDllHandle")
                and call["status"]
            ):
                self._add_loaded_module(args.get("FileName", ""), args.get("ModuleHandle", ""))

            elif call["api"] == "LdrLoadDll" and call["status"]:
                self._add_loaded_module(args.get("FileName", ""), args.get("BaseAddress", ""))

            elif call["api"] == "LdrGetProcedureAddress" and call["status"]:
                self._add_procedure(args.get("ModuleHandle", ""), args.get("FunctionName", ""), args.get("FunctionAddress", ""))
                event["data"]["module"] = self._get_loaded_module(args.get("ModuleHandle", ""))

            elif call["api"] == "SetWindowsHookExA":
                event["data"]["module"] = self._get_loaded_module(args.get("ModuleAddress", ""))

            elif call["api"] == "ControlService":
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


class Anomaly:
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
            elif row["name"] == "FunctionName":
                funcname = row["value"]
            elif row["name"] == "Message":
                message = row["value"]

        self.anomalies.append(
            {
                "name": process["process_name"],
                "pid": process["process_id"],
                "category": category,
                "funcname": funcname,
                "message": message,
            }
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
            {
                "name": process["process_name"],
                "pid": process["process_id"],
                "parent_id": process["parent_id"],
                "module_path": process["module_path"],
                "children": [],
                "threads": process["threads"],
                "environ": process["environ"],
            }
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
        return next(
            (arg["value"].strip() if strip else arg["value"] for arg in call["arguments"] if arg["name"] == argname),
            None,
        )

    def get_raw_argument(self, call, argname):
        return next(
            (arg["raw_value"] for arg in call["arguments"] if arg["name"] == argname),
            None,
        )

    def event_apicall(self, call, process):
        """Generate processes list from streamed calls/processes.
        @return: None.
        """

        if call["api"].startswith("SslEncryptPacket"):
            buf = self.get_argument(call, "Buffer", strip=True)
            bufsize = self.get_argument(call, "BufferSize")
            if buf and buf not in self.bufs:
                self.bufs.append(
                    {
                        "process_name": process["process_name"],
                        "pid": process["process_id"],
                        "api_call": "SslEncryptPacket",
                        "buffer": buf,
                        "buffer_size": bufsize,
                    }
                )

        if call["api"].startswith("CryptEncrypt"):
            key = self.get_argument(call, "CryptKey")
            buf = self.get_argument(call, "Buffer", strip=True)
            if buf and buf not in self.bufs:
                self.bufs.append(
                    {
                        "process_name": process["process_name"],
                        "pid": process["process_id"],
                        "api_call": "CryptEncrypt",
                        "buffer": buf,
                        "crypt_key": key,
                    }
                )

        if call["api"].startswith("CryptEncryptMessage"):
            buf = self.get_argument(call, "Buffer", strip=True)
            if buf and buf not in self.bufs:
                self.bufs.append(
                    {
                        "process_name": process["process_name"],
                        "pid": process["process_id"],
                        "api_call": "CryptEncryptMessage",
                        "buffer": buf,
                    }
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

        behavior = {"processes": []}
        if path_exists(self.logs_path) and len(os.listdir(self.logs_path)) != 0:
            behavior = {"processes": Processes(self.logs_path, self.task, self.options).run()}

            instances = [
                Anomaly(),
                ProcessTree(),
                Summary(self.options),
                Enhanced(),
                EncryptedBuffers(),
            ]
            enabled_instances = [instance for instance in instances if getattr(self.options, instance.key, True)]

            if enabled_instances:
                # Iterate calls and tell interested signatures about them
                for process in behavior["processes"]:
                    for call in process["calls"]:
                        for instance in enabled_instances:
                            try:
                                instance.event_apicall(call, process)
                            except Exception:
                                log.exception('Failure in partial behavior "%s"', instance.key)

            for instance in instances:
                try:
                    behavior[instance.key] = instance.run()
                except Exception as e:
                    log.exception('Failed to run partial behavior class "%s" due to "%s"', instance.key, e)
        else:
            log.warning('Analysis results folder does not exist at path "%s"', self.logs_path)
            # load behavior from json if exist or env CAPE_REPORT variable
            json_path = False
            if os.environ.get("CAPE_REPORT") and path_exists(os.environ["CAPE_REPORT"]):
                json_path = os.environ["CAPE_REPORT"]
            elif os.path.exists(os.path.join(self.reports_path, "report.json")):
                json_path = os.path.join(self.reports_path, "report.json")

            if not json_path:
                return behavior

            with open(json_path) as f:
                try:
                    behavior = json.load(f).get("behavior", [])
                except Exception as e:
                    log.error("Behavior. Can't load json: %s", str(e))

        # https://github.com/mandiant/capa/issues/2620
        if (
            HAVE_FLARE_CAPA
            and self.results.get("info", {}).get("category", "") == "file"
            and "PE" in self.results.get("target", {}).get("file", "").get("type", "")
        ):
            try:
                self.results["capa_summary"] = flare_capa_details(
                    file_path=self.results["target"]["file"]["path"],
                    category="behavior",
                    backend="cape",
                    results={"behavior": behavior, **self.results},
                )
            except Exception as e:
                log.error("Can't generate CAPA summary: %s", str(e))
        return behavior
