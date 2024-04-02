import json
import logging
import os
import re

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.path_utils import path_exists

log = logging.getLogger(__name__)

__author__ = "@winson0123"
__version__ = "1.0.0"

fd_syscalls = [
    "read",
    "write",
    "close",
    "newfstat",
    "lseek",
    "ioctl",
    "pread64",
    "pwrite64",
    "readv",
    "writev",
    "fcntl",
    "flock",
    "fsync",
    "fdatasync",
    "ftruncate",
    "getdents",
    "fchdir",
    "fchmod",
    "fchown",
    "fstatfs",
    "readahead",
    "fsetxattr",
    "fgetxattr",
    "flistxattr",
    "fremovexattr",
    "getdents64",
    "newfstatat",
    "sync_file_range",
    "vmsplice",
    "fallocate",
    "preadv",
    "pwritev",
    "syncfs",
    "preadv2",
    "pwritev2",
    "fsconfig",
    "quotactl_fd",
]


class ParseProcessLog(list):
    """Parses the process log file"""

    def __init__(self, log_path, syscalls_info, options):
        """@param log_path: log file path."""
        self._log_path = log_path
        self.process_id = int(log_path.split(".")[-1])
        self.children_ids = []
        self.first_seen = None
        self.process_name = None
        self.calls = self
        self.file_descriptors = []
        self.options = options
        # Limit of API calls per process
        # self.api_limit = self.options.analysis_call_limit

        if path_exists(log_path) and os.stat(log_path).st_size > 0:
            self.fetch_calls(syscalls_info)

    def __iter__(self):
        return iter(super().__iter__())

    def __repr__(self):
        return f"<ParseProcessLog log-path: {self._log_path}>"

    def begin_reporting(self):
        pass

    def log_concat(self, unfinished, resumed):
        """
        Concatenates all the respective unfinished and resumed strace logs into a string,
        matching '<unfinished ...>' and '<... {syscall} resumed>' strings accordingly,
        returns the `resumed` time as that is the completed syscall time.
        """
        data = ""
        for head in unfinished:
            for tail in resumed:
                if head["syscall"] != tail["syscall"]:
                    continue
                data += " ".join([tail["time"], head["unfinished"] + tail["resumed"] + "\n"])
                resumed.remove(tail)
                break
        return data

    def extract_logs(self, raw_logs, pattern):
        return [match.groupdict() for match in pattern.finditer(raw_logs)]

    def normalize_logs(self):
        """
        Normalize the logs into a standard format to process the syscall information.
        Returns a list of dictionaries containing syscall information.
        """
        log_pattern = re.compile(
            r"(?P<time>\d+:\d+:\d+\.\d+)\s+\[\s+\d+\]\s+(?P<syscall>\w+)\((?P<args>.*)\)\s+=\s(?P<retval>.+)\n"
        )
        unfinished_pattern = re.compile(r"\d+:\d+:\d+\.\d+\s+(?P<unfinished>\[\s+\d+\]\s+(?P<syscall>\w+)\(.*)<unfinished\s...>\n")
        resumed_pattern = re.compile(
            r"(?P<time>\d+:\d+:\d+\.\d+)\s+\[\s+\d+\]\s+<\.\.\.\s(?P<syscall>\w+)\sresumed>(?P<resumed>.*)\n"
        )
        with open(self._log_path, "r") as log_file:
            raw_logs = log_file.read()

        normal_logs = self.extract_logs(raw_logs, log_pattern)
        unfinished_logs = self.extract_logs(raw_logs, unfinished_pattern)
        resumed_logs = self.extract_logs(raw_logs, resumed_pattern)

        concat_logs = self.log_concat(unfinished_logs, resumed_logs)
        normal_logs.extend(self.extract_logs(concat_logs, log_pattern))

        normal_logs.sort(key=lambda d: d["time"])
        return normal_logs

    def split_arguments(self, args_str):
        args = []
        current = ""
        brace_level = 0
        for char in args_str:
            if char == "," and brace_level == 0:
                args.append(current)
                current = ""
            else:
                current += char
                if char in ["{", "["]:
                    brace_level += 1
                elif char in ["}", "]"]:
                    brace_level = max(brace_level - 1, 0)
        args.append(current)

        return [x.strip() for x in args if x.strip() != ""]

    def fetch_calls(self, syscalls_info):
        for event in self.normalize_logs():
            time = event["time"]
            category = "misc"
            syscall = event["syscall"]
            arguments = []
            args = self.split_arguments(event["args"])
            if syscall_info := syscalls_info.get(syscall, None):
                category = syscall_info.get("category", "misc")
                arg_names = syscall_info.get("signature", None)
                for arg_name, arg in zip(arg_names, args):
                    arguments.append(
                        {
                            "name": arg_name,
                            "value": arg,
                        }
                    )
            else:
                arguments.append(event["args"])
            retval = event["retval"]

            if len(self.calls) == 0:
                self.first_seen = time
                self.process_name = syscall + "(" + event["args"] + ")"

            if syscall in ["fork", "vfork", "clone", "clone3"]:
                self.children_ids.append((int(retval), syscall + "(" + event["args"] + ")"))

            self.calls.append(
                {
                    "timestamp": time,
                    "category": category,
                    "api": syscall,
                    "return": retval,
                    "arguments": arguments,
                }
            )

            # Consider open/openat/dup syscalls for tracking opened file descriptors
            if retval > "0":
                match syscall:
                    case call if call in ["open", "creat"]:
                        self.file_descriptors.append(
                            {
                                "time": time,
                                "syscall": syscall,
                                "fd": retval,
                                "filename": eval(args[0]),
                            }
                        )
                    case call if call in ["openat", "openat2"]:
                        self.file_descriptors.append(
                            {
                                "time": time,
                                "syscall": syscall,
                                "fd": retval,
                                "filename": eval(args[1]),
                            }
                        )
                    case call if call in ["dup", "dup2", "dup3"]:
                        self.file_descriptors.append(
                            {
                                "time": time,
                                "syscall": syscall,
                                "oldfd": args[0],
                                "fd": retval,
                            }
                        )
                continue

            # Consider close syscalls for tracking closed file descriptors
            if retval == "0" and syscall == "close":
                self.file_descriptors.append(
                    {
                        "time": time,
                        "syscall": syscall,
                        "fd": args[0],
                    }
                )


class Processes:
    """Processes analyzer."""

    key = "processes"

    def __init__(self, logs_path, options):
        """
        @param _logs_path: path of the strace logs
        @param syscalls_info: information of indexed syscalls
        """
        self._logs_path = logs_path
        self.syscalls_info = self.load_syscalls_args()
        self.options = options

    def load_syscalls_args(self):
        """
        Returns dictionary with syscall information indexed by syscall index.
        The values include the signature of the syscall and the category
        extracted from the definition location.
        """
        syscalls_json = open("/opt/CAPEv2/data/linux/linux-syscalls.json", "r")
        syscalls_dict = json.load(syscalls_json)
        return {
            syscall["name"]: {
                "signature": syscall["signature"],
                "category": "kernel" if "kernel" in syscall["file"] else syscall["file"].split("/")[0],
            }
            for syscall in syscalls_dict["syscalls"]
        }

    def update_file_descriptors(self, process_list, fd_calls):
        """
        Returns an updated process list where file-access related calls have
        the matching file descriptor at the time of it being opened.
        """
        # Default file descriptors
        file_descriptors = [
            {
                "fd": "0",
                "filename": "STDIN",
                "time_opened": "00:00:00.000000",
                "time_closed": None,
            },
            {
                "fd": "1",
                "filename": "STDOUT",
                "time_opened": "00:00:00.000000",
                "time_closed": None,
            },
            {
                "fd": "2",
                "filename": "STDERR",
                "time_opened": "00:00:00.000000",
                "time_closed": None,
            },
        ]
        sorted_fd_calls = sorted(fd_calls, key=lambda x: x["time"])

        for fd_call in sorted_fd_calls:
            # Retrieve the relevant informaton from syscalls that open/duplicate/close file descriptors
            match fd_call["syscall"]:
                case syscall if syscall in ["open", "creat", "openat", "openat2"]:
                    file_descriptors.append(
                        {
                            "fd": fd_call["fd"],
                            "filename": fd_call["filename"],
                            "time_opened": fd_call["time"],
                            "time_closed": None,
                        }
                    )
                case syscall if syscall in ["dup", "dup2", "dup3"]:
                    for fd in reversed(file_descriptors):
                        if fd["time_closed"] is None and fd_call["oldfd"] == fd["fd"]:
                            file_descriptors.append(
                                {
                                    "fd": fd_call["fd"],
                                    "filename": fd["filename"],
                                    "time_opened": fd_call["time"],
                                    "time_closed": None,
                                }
                            )
                case "close":
                    for fd in reversed(file_descriptors):
                        if fd["time_closed"] is None and fd_call["fd"] == fd["fd"]:
                            fd["time_closed"] = fd_call["time"]

        for process in process_list:
            for call in process["calls"]:
                if call["api"] in fd_syscalls:
                    # append filename to file descriptor according to relevant time that fd is opened
                    # if any unclosed file descriptor, assume that it is closed after process is finished
                    for fd in file_descriptors:
                        if (
                            call["arguments"][0]["value"] == fd["fd"]
                            and fd["time_opened"] < call["timestamp"]
                            and (fd["time_closed"] is None or call["timestamp"] <= fd["time_closed"])
                        ):
                            call["arguments"][0]["value"] += f' ({fd["filename"]})'

        return process_list

    def update_parent_ids(self, process_list, relations):
        """
        Returns an updated process list with the matched parent IDs
        """
        # Create a dictionary to map process IDs to their respective entries
        process_dict = {entry["process_id"]: entry for entry in process_list}

        # Iterate through the parent_relations dictionary
        for parent_id, children in relations.items():
            # Check if the parent_id exists in the process_dict
            if parent_id in process_dict:
                # Update the parent_id for each child
                for child_id, name in children:
                    if child_id in process_dict:
                        process_dict[child_id]["parent_id"] = parent_id
                        process_dict[child_id]["process_name"] = name

        # Convert the dictionary back to a list of entries
        updated_process_list = list(process_dict.values())

        return updated_process_list

    def run(self):
        results = []
        parent_child_relation = {}
        fd = []

        if not path_exists(self._logs_path):
            log.warning('Analysis results folder does not exist at path "%s"', self._logs_path)
            return results

        if len(os.listdir(self._logs_path)) == 0:
            log.info("Analysis results folder does not contain any file or injection was disabled")
            return results

        for file_name in os.listdir(self._logs_path):
            file_path = os.path.join(self._logs_path, file_name)

            if os.path.isdir(file_path):
                continue

            current_log = ParseProcessLog(file_path, self.syscalls_info, self.options)
            if current_log.process_id is None:
                continue

            parent_child_relation[current_log.process_id] = current_log.children_ids

            results.append(
                {
                    "process_id": current_log.process_id,
                    "process_name": current_log.process_name,
                    "parent_id": None,
                    "first_seen": current_log.first_seen,
                    "calls": current_log.calls,
                }
            )

            fd += current_log.file_descriptors

        results = self.update_parent_ids(results, parent_child_relation)
        results = self.update_file_descriptors(results, fd)

        # Sort the items in the results list chronologically. In this way we
        # can have a sequential order of spawned processes.
        results.sort(key=lambda process: process["first_seen"])

        return results


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
                "children": [],
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


class StraceAnalysis(Processing):
    """Strace Analyzer."""

    key = "behavior"
    os = "linux"

    def run(self):
        """
        Run analysis on strace logs
        @return: results dict.
        """
        strace = {"processes": Processes(self.logs_path, self.options).run()}

        instances = [
            ProcessTree(),
        ]
        enabled_instances = [instance for instance in instances if getattr(self.options, instance.key, True)]

        if enabled_instances:
            # Iterate calls and tell interested signatures about them
            for process in strace["processes"]:
                for call in process["calls"]:
                    for instance in enabled_instances:
                        try:
                            instance.event_apicall(call, process)
                        except Exception:
                            log.exception('Failure in partial behavior "%s"', instance.key)

        for instance in instances:
            try:
                strace[instance.key] = instance.run()
            except Exception as e:
                log.exception('Failed to run partial behavior class "%s" due to "%s"', instance.key, e)

        return strace
