import logging
import re
import json
import os
import tempfile
import strace_process_tree as stp

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

__author__ = "@winson0123"
__version__ = "1.0.0"

class Processes():
    """Processes analyzer."""

    key = "processes"

    def __init__(self, raw_strace_logs):
        """
        @param  _raw_strace_logs: path of the strace logs
        @param syscalls_info: information of indexed syscalls
        """
        self._raw_strace_logs = raw_strace_logs
        self.syscalls_info = self.load_syscalls_args()
        

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
        log_pattern = re.compile(r'(?P<pid>\d+)\s+(?P<time>\d+:\d+:\d+\.\d+)\s+\[\s+(?P<syscall_number>\d+)\]\s+(?P<syscall>\w+)\((?P<args>.*)\)\s+=\s(?P<retval>.+)\n')
        unfinished_pattern = re.compile(r'(?P<pid>\d+)\s+\d+:\d+:\d+\.\d+\s+(?P<unfinished>\[\s+(?P<syscall_number>\d+)\]\s+(?P<syscall>\w+)\(.*)<unfinished\s...>\n')
        resumed_pattern = re.compile(r'(?P<pid>\d+)\s+(?P<time>\d+:\d+:\d+\.\d+)\s+\[\s+(?P<syscall_number>\d+)\]\s+<\.\.\.\s(?P<syscall>\w+)\sresumed>(?P<resumed>.*)\n')
        # exited_pattern = re.compile(r'(?P<pid>\d+)\s+(?P<time>\d+:\d+:\d+\.\d+)\s+\+\+\+ exited with 0 \+\+\+')

        unfinished_logs = [x for x in unfinished_pattern.finditer(self._raw_strace_logs)]
        resumed_logs = [x for x in resumed_pattern.finditer(self._raw_strace_logs)]
        concat_logs = self.log_concat(unfinished_logs, resumed_logs)

        normal_logs = [x for x in log_pattern.finditer(self._raw_strace_logs)]
        normal_logs.extend([x for x in log_pattern.finditer(concat_logs)])

        return normal_logs
    
    def parse_events(self):
        logs = self.normalize_logs()
        processes = {}
        parent_relations = []

        for event in logs:
            pid = event.group("pid")
            time = event.group("time")
            category = None
            syscall = event.group("syscall")
            arguments = []
            args = self.split_string_by_commas_ignore_braces(event.group("args"))
            if syscall_info := self.syscalls_info.get(int(event.group("syscall_number")), None):
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

            if pid not in processes:
                processes[pid] = {
                    "process_id": pid,
                    "parent_id": None,
                    "first_seen": time,
                    "calls": [],
                }

            if syscall in ["vfork", "clone", "clone3"]:
                parent_relations.append((processes[retval]["parent_id"], pid))

            processes[pid]["calls"].append({
                "timestamp": time,
                "category": category,
                "syscall": syscall,
                "return": retval,
                "arguments": arguments
            })

        # Update the parent_id after the loop
        for pid, ppid in parent_relations:
            processes[pid]["parent_id"] = ppid

        return list(processes.values())
    
    def split_string_by_commas_ignore_braces(self, args_str):
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
    
    def run(self):
        return self.parse_events()

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

        strace_logs = open(strace_data_path, "r").read()

        strace_behavior["processes"] = Processes(strace_logs).run()
        strace_behavior["processtree"] = ProcessTree(strace_data_path).run()

        return strace_behavior
    