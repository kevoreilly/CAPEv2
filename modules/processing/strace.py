import logging
import re
import os
import strace_process_tree as stp

from lib.cuckoo.common.abstracts import Processing
from lib.cuckoo.common.exceptions import CuckooProcessingError

log = logging.getLogger(__name__)

__author__ = "@winson0123"
__version__ = "1.0.0"

def log_concat(unfinished, resumed):
    """
    Concatenates all the respective unfinished and resumed strace logs into a string,
    matching '<unfinished ...>' and '<... {syscall} resumed>' strings accordingly,
    returns the `resumed` time as that is the completed syscall time.
    """
    data = ""
    for head in unfinished:
        for tail in resumed:
            if head.group("pid") != tail.group("pid") or head.group("syscall") != tail.group("syscall"):
                continue
            data += tail.group("pid") + ' ' + tail.group("time") + ' ' + head.group("unfinished") + tail.group("resumed") + '\n'
            resumed.remove(tail)
            unfinished.remove(head)
            break
    return data

def parse_log(strace_logs):
    results = []
    log_pattern = re.compile(r'(?P<pid>\d+)\s+(?P<time>\d+:\d+:\d+\.\d+)\s+(?P<syscall>\w+)\((?P<args>.*)\)\s+=\s(?P<retval>.+)\n')
    unfinished_pattern = re.compile(r'(?P<pid>\d+)\s+\d+:\d+:\d+\.\d+\s+(?P<unfinished>(?P<syscall>\w+)\(.*)<unfinished\s...>\n')
    resumed_pattern = re.compile(r'(?P<pid>\d+)\s+(?P<time>\d+:\d+:\d+\.\d+)\s+<\.\.\.\s(?P<syscall>\w+)\sresumed>(?P<resumed>.*)\n')
    # exited_pattern = re.compile(r'(?P<pid>\d+)\s+(?P<time>\d+:\d+:\d+\.\d+)\s+\+\+\+ exited with 0 \+\+\+')

    unfinished_logs = [x for x in unfinished_pattern.finditer(strace_logs)]
    resumed_logs = [x for x in resumed_pattern.finditer(strace_logs)]
    concat_logs = log_concat(unfinished_logs, resumed_logs)

    normal_logs = [x for x in log_pattern.finditer(strace_logs)]
    normal_logs.extend([x for x in log_pattern.finditer(concat_logs)])

    for event in normal_logs:
        pid = event.group("pid")
        time = event.group("time")
        syscall = event.group("syscall")
        args = event.group("args")
        retval = event.group("retval")
        results.append({
            "pid":pid,
            "time": time,
            "syscall": syscall,
            "args": args,
            "retval": retval
                    })
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

        stptree = stp.parse_stream(stp.events(open(self.path,"r")), stp.simplify_syscall)
        
        for pid, process in stptree.processes.items():
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

    def run(self):
        self.key = "strace"
        log.info("Processing strace logs")
        
        strace_behavior = {}

        strace_dir = os.path.join(self.analysis_path, "strace")
        strace_data_path = os.path.join(strace_dir, "strace.log")

        strace_logs = open(strace_data_path, "r").read()

        strace_behavior["processes"] = parse_log(strace_logs)
        strace_behavior["processtree"] = ProcessTree(strace_data_path).run()

        return strace_behavior
    