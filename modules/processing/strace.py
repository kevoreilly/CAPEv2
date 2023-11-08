import logging
import re
import json
import os
import tempfile
from contextlib import suppress
import strace_process_tree as stp

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.path_utils import path_exists
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

__author__ = "@winson0123"
__version__ = "1.0.0"

class ParseProcessLog(list):
    """Parses the process log file"""

    def __init__(self, log_path, syscalls_info, options):
        """@param log_path: log file path."""
        self._log_path = log_path
        self.process_id = int(log_path.split(".")[-1])
        self.children_ids = []
        self.first_seen = None
        self.calls = list()

        self.options = options
        # Limit of API calls per process
        # self.api_limit = self.options.analysis_call_limit

        if path_exists(log_path) and os.stat(log_path).st_size > 0:
            self.fetch_calls(syscalls_info)

    def __iter__(self):
        for item in self.calls:
            yield item
    
    def __repr__(self):
        return f"<ParseProcessLog log-path: {self._log_path}>"

    def time_key(self, event):
        return event.group("time")
    
    def log_concat(self, unfinished, resumed):
        """
        Concatenates all the respective unfinished and resumed strace logs into a string,
        matching '<unfinished ...>' and '<... {syscall} resumed>' strings accordingly,
        returns the `resumed` time as that is the completed syscall time.
        """
        data = ""
        for head in unfinished:
            for tail in resumed:
                if head.group("pid") != tail.group("pid") or head.group("syscall_number") != tail.group("syscall_number"):
                    continue
                data += " ".join([tail.group("pid"), tail.group("time"), head.group("unfinished") + tail.group("resumed") + "\n"])
                resumed.remove(tail)
                break
        return data

    def normalize_logs(self):
        raw_strace_logs = open(self._log_path, "r").read()

        log_pattern = re.compile(r'(?P<time>\d+:\d+:\d+\.\d+)\s+\[\s+(?P<syscall_number>\d+)\]\s+(?P<syscall>\w+)\((?P<args>.*)\)\s+=\s(?P<retval>.+)\n')
        unfinished_pattern = re.compile(r'\d+:\d+:\d+\.\d+\s+(?P<unfinished>\[\s+(?P<syscall_number>\d+)\]\s+(?P<syscall>\w+)\(.*)<unfinished\s...>\n')
        resumed_pattern = re.compile(r'(?P<time>\d+:\d+:\d+\.\d+)\s+\[\s+(?P<syscall_number>\d+)\]\s+<\.\.\.\s(?P<syscall>\w+)\sresumed>(?P<resumed>.*)\n')
        # exited_pattern = re.compile(r'(?P<pid>\d+)\s+(?P<time>\d+:\d+:\d+\.\d+)\s+\+\+\+ exited with 0 \+\+\+')

        unfinished_logs = [x for x in unfinished_pattern.finditer(raw_strace_logs)]
        resumed_logs = [x for x in resumed_pattern.finditer(raw_strace_logs)]
        concat_logs = self.log_concat(unfinished_logs, resumed_logs)

        normal_logs = [x for x in log_pattern.finditer(raw_strace_logs)]
        normal_logs.extend([x for x in log_pattern.finditer(concat_logs)])
        normal_logs = sorted(normal_logs, key=self.time_key)

        return normal_logs
    
    def split_arguments(self, args_str):
        args = []
        current = ''
        brace_level = 0
        for char in args_str:
            if char == ',' and brace_level == 0:
                args.append(current)
                current = ''
            else:
                current += char
                if char in ['{', '[']:
                    brace_level += 1
                elif char in ['}', ']']:
                    brace_level = max(brace_level - 1, 0)
        args.append(current)

        return [x.strip() for x in args if x.strip() != '']
    
    def fetch_calls(self, syscalls_info):
        for event in self.normalize_logs():
            time = event.group("time")
            category = None
            syscall = event.group("syscall")
            arguments = []
            args = self.split_arguments(event.group("args"))
            if syscall_info := syscalls_info.get(int(event.group("syscall_number")), None):
                category = syscall_info.get("category", None)
                arg_names = syscall_info.get("signature", None)
                for arg_name, arg in zip(arg_names, args):
                    arguments.append({
                        "name": arg_name,
                        "value": arg,
                    })
            else:
                arguments.append(event.group("args"))
            retval = event.group("retval")

            if len(self) == 0:
                    self.first_seen = time

            if syscall in ["vfork", "clone", "clone3"]:
                self.children_ids.append(int(retval))

            self.calls.append({
                "timestamp": time,
                "category": category,
                "syscall": syscall,
                "return": retval,
                "arguments": arguments
            })

class Processes():
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
        return { syscall["index"]: {
                    "signature": syscall["signature"],
                    "category": syscall["file"].split("/")[0]
                    } for syscall in syscalls_dict["syscalls"]
                }

    def update_parent_ids(self, process_list, relations):
        # Create a dictionary to map process IDs to their respective entries
        process_dict = {entry['process_id']: entry for entry in process_list}

        # Iterate through the parent_relations dictionary
        for parent_id, children in relations.items():
            # Check if the parent_id exists in the process_dict
            if parent_id in process_dict:
                # Update the parent_id for each child
                for child_id in children:
                    if child_id in process_dict:
                        process_dict[child_id]['parent_id'] = parent_id

        # Convert the dictionary back to a list of entries
        updated_process_list = list(process_dict.values())

        return updated_process_list

    def run(self):
        results = []
        parent_child_relation = {}

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

            results.append({
                "process_id": current_log.process_id,
                "parent_id": None,
                "first_seen": current_log.first_seen,
                "calls": current_log.calls,
            })

        results = self.update_parent_ids(results, parent_child_relation)

        # Sort the items in the results list chronologically. In this way we
        # can have a sequential order of spawned processes.
        results.sort(key=lambda process: process["first_seen"])
        print(results)

        return results

class ProcessTree():
    """ Generates process tree. """
    
    key = "processtree"
    
    def __init__(self, path):
        self.tree = []
        self.path = path

    def add_node(self, node, tree):
        ret = False
        for process in tree:
            if process["pid"] == node.parent.pid:
                process["children"].append({
                    "name": node.name,
                    "pid": node.pid,
                    "parent_id": node.parent.pid,
                    "children": [],
                })
                ret = True
                break
            else:
                if self.add_node(node, process["children"]):
                    ret = True
                    break
        return ret

    def run(self):
        children = []
        stptree = None

        t = tempfile.NamedTemporaryFile(mode="r+")
        with open(self.path, "r") as f:
            t.write(re.sub(r"\s\[\s+\d+\]", "", "".join(f.readlines())))
            t.seek(0)
            stptree = stp.parse_stream(stp.events(t), stp.simplify_syscall)
            t.close()
        
        for _, process in stptree.processes.items():
            if process.parent is None:
                self.tree.append({
                    "name": process.name,
                    "pid": process.pid,
                    "parent_id": None,
                    "children": [],
                })
            else:
                children.append(process)
        
        for process in children:
            if not self.add_node(process, self.tree):
                self.tree.append({
                    "name": process.name,
                    "pid": process.pid,
                    "parent_id": process.parent.pid,
                    "children": []
                })
        return self.tree

class StraceAnalysis(Processing):
    """ Strace Analyzer. """

    os = "linux"

    def run(self):
        self.key = "strace"
        log.info("Processing strace logs")
        
        strace_behavior = {}

        strace_dir = os.path.join(self.analysis_path, "strace")
        strace_data_path = os.path.join(strace_dir, "strace.log")

        #strace_logs = open(strace_data_path, "r").read()

        strace_behavior["processes"] = Processes(strace_dir, self.options).run()
        #trace_behavior["processtree"] = ProcessTree(strace_data_path).run()

        return strace_behavior
    