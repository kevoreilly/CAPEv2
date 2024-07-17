import base64
import json
import logging
import os
import subprocess
import zlib

from lib.cuckoo.common.abstracts import Processing

log = logging.getLogger(__name__)

__author__ = "@theoleecj2"
__version__ = "1.0.0"

sec_events = [
    "sched_process_exec",
    "stdio_over_socket",
    "k8s_api_connection",
    "aslr_inspection",
    "proc_mem_code_injection",
    "docker_abuse",
    "scheduled_task_mod",
    "ld_preload",
    "cgroup_notify_on_release",
    "default_loader_mod",
    "sudoers_modification",
    "sched_debug_recon",
    "system_request_key_mod",
    "cgroup_release_agent",
    "rcd_modification",
    "core_pattern_modification",
    "proc_kcore_read",
    "proc_mem_access",
    "hidden_file_created",
    "anti_debugging",
    "ptrace_code_injection",
    "process_vm_write_inject",
    "disk_mount",
    "dynamic_code_loading",
    "fileless_execution",
    "illegitimate_shell",
    "kernel_module_loading",
    "k8s_cert_theft",
    "proc_fops_hooking",
    "syscall_hooking",
    "dropped_executable",
]


def load_syscalls_args():
    # Source: strace.py
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


class ProcTree:
    def __init__(self, pid, details):
        self.children = {}
        self.pid = pid
        self.details = details

    def add_child(self, pid, details):
        self.children[pid] = ProcTree(pid, details)

    def update_details(self, details):
        self.details = details

    def get_child(self, pid):
        if pid == self.pid:
            return self
        else:
            for child in self.children:
                result = self.children[child].get_child(pid)
                if result:
                    return result
        return None

    def to_dict(self):
        output = {"pid": self.pid, "details": dict(self.details), "children": {}}
        for child in self.children:
            output["children"][child] = self.children[child].to_dict()
        return output


class TraceeAnalysis(Processing):
    """Tracee Analyzer v1."""

    order = 2
    os = "linux"

    def run(self):
        """
        Run analysis on tracee logs and files
        @return: results dict.
        """

        self.key = "tracee"

        log.info("Tracee Processor Running.")

        syscall_catalog = load_syscalls_args()
        tree = ProcTree(0, {"desc": "(ABSTRACTION) root process"})

        logpath = os.path.join(self.analysis_path, "logs", "tracee.log")
        subprocess.run(
            r"""grep -v '\\"processName\\":\\"strace\\"' """ + logpath + " > " + logpath + ".cleaner",
            shell=True,
            capture_output=True,
            text=True,
        )

        f = open(logpath + ".cleaner", "r")
        ln = f.readline()

        output = {"metadata": {"security_events": []}, "syscalls": []}  # trace security events and store process tree
        all_syscalls = output["syscalls"]
        output_metadata = output["metadata"]
        ev_idx = -1

        while ln:
            ln = f.readline()
            if len(ln) == 0:
                continue
            lg = None

            try:
                lg = json.loads(json.loads(ln)["log"])
            except Exception as e:
                log.info("Could not process Tracee line: %s - %s", str(lg), e)
                continue

            if lg.get("syscall", None):
                ev_idx += 1
                lg["idx"] = ev_idx
                lg["cat"] = syscall_catalog.get(lg["syscall"], {"category": "misc"})["category"]
                # outfile.write(json.dumps(lg) + "\n")
                all_syscalls.append(lg)

                if lg["syscall"] == "execve":
                    for arg in lg["args"]:
                        if arg["name"] == "argv":
                            if not tree.get_child(lg["parentProcessId"]):
                                tree.add_child(lg["parentProcessId"], {"desc": "PARENT"})

                            arg2 = []
                            for a in lg["args"]:
                                if "env" in a["name"]:
                                    arg2 = a["value"]

                            tree.get_child(lg["parentProcessId"]).add_child(
                                lg["processId"],
                                {
                                    "desc": arg["value"],
                                    "cmdline": arg["value"],  # "full": lg,
                                    "env": arg2,
                                },
                            )
            elif lg.get("eventName", None) in sec_events:
                ev_idx += 1
                lg["idx"] = ev_idx
                all_syscalls.append(lg)

            if lg.get("eventName", None) in sec_events:
                lg["idx"] = ev_idx
                output_metadata["security_events"].append(lg)

        f.close()

        output_metadata["proctree"] = tree.to_dict()

        return str(base64.b64encode(zlib.compress(bytearray(json.dumps(output), "utf-8"))), "ascii")
