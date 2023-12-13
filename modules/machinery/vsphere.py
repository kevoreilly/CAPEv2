# Copyright (C) 2015 eSentire, Inc (jacob.gajek@esentire.com).
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import random
import re
import sys
import time
from datetime import datetime, timedelta

import requests

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooDependencyError, CuckooMachineError

try:
    from pyVim.connect import SmartConnection

    HAVE_PYVMOMI = True
except ImportError:
    HAVE_PYVMOMI = False
    sys.exit("Missed library: poetry run pip install pyvmomi")

log = logging.getLogger(__name__)
logging.getLogger("requests").setLevel(logging.WARNING)
cfg = Config()


class vSphere(Machinery):
    """vSphere/ESXi machinery class based on pyVmomi Python SDK."""

    # VM states
    RUNNING = "poweredOn"
    POWEROFF = "poweredOff"
    SUSPENDED = "suspended"
    ABORTED = "aborted"

    def __init__(self):
        if not HAVE_PYVMOMI:
            raise CuckooDependencyError("Couldn't import pyVmomi. Please install using 'pip3 install --upgrade pyvmomi'")

        super(vSphere, self).__init__()

    def _initialize(self, module_name):
        """Read configuration.
        @param module_name: module name.
        """
        super(vSphere, self)._initialize(module_name)

        # Initialize random number generator
        random.seed()

    def _initialize_check(self):
        """Runs checks against virtualization software when a machine manager
        is initialized.
        @raise CuckooCriticalError: if a misconfiguration or unsupported state
                                    is found.
        """
        self.connect_opts = {}

        if self.options.vsphere.host:
            self.connect_opts["host"] = self.options.vsphere.host
        else:
            raise CuckooCriticalError("vSphere host address setting not found, please add it to the config file")

        if self.options.vsphere.port:
            self.connect_opts["port"] = self.options.vsphere.port
        else:
            raise CuckooCriticalError("vSphere port setting not found, please add it to the config file")

        if self.options.vsphere.user:
            self.connect_opts["user"] = self.options.vsphere.user
        else:
            raise CuckooCriticalError("vSphere username setting not found, please add it to the config file")

        if self.options.vsphere.pwd:
            self.connect_opts["pwd"] = self.options.vsphere.pwd
        else:
            raise CuckooCriticalError("vSphere password setting not found, please add it to the config file")

        # Workaround for PEP-0476 issues in recent Python versions
        if self.options.vsphere.unverified_ssl:
            import ssl

            sslContext = ssl._create_unverified_context()
            self.connect_opts["sslContext"] = sslContext
            log.warn("Turning off SSL certificate verification!")

        # Check that a snapshot is configured for each machine
        # and that it was taken in a powered-on state
        try:
            with SmartConnection(**self.connect_opts) as conn:
                for machine in self.machines():
                    if not machine.snapshot:
                        raise CuckooCriticalError(
                            f"Snapshot name not specified for machine {machine.label}, please add it to the config file"
                        )
                    vm = self._get_virtual_machine_by_label(conn, machine.label)
                    if not vm:
                        raise CuckooCriticalError(
                            f"Unable to find machine {machine.label} on vSphere host, please update your configuration"
                        )
                    state = self._get_snapshot_power_state(vm, machine.snapshot)
                    if not state:
                        raise CuckooCriticalError(
                            f"Unable to find snapshot {machine.snapshot} for machine {machine.label}, please update your configuration"
                        )
                    if state != self.RUNNING:
                        raise CuckooCriticalError(
                            f"Snapshot for machine {machine.label} not in powered-on state, please create one"
                        )
        except Exception:
            raise CuckooCriticalError("Couldn't connect to vSphere host")

        super(vSphere, self)._initialize_check()

    def start(self, label):
        """Start a machine.
        @param label: machine name.
        @raise CuckooMachineError: if unable to start machine.
        """
        name = self.db.view_machine_by_label(label).snapshot
        with SmartConnection(**self.connect_opts) as conn:
            vm = self._get_virtual_machine_by_label(conn, label)
            if vm:
                self._revert_snapshot(vm, name)
            else:
                raise CuckooMachineError(f"Machine {label} not found on host")

    def stop(self, label):
        """Stop a machine.
        @param label: machine name.
        @raise CuckooMachineError: if unable to stop machine
        """
        with SmartConnection(**self.connect_opts) as conn:
            vm = self._get_virtual_machine_by_label(conn, label)
            if vm:
                self._stop_virtual_machine(vm)
            else:
                raise CuckooMachineError(f"Machine {label} not found on host")

    def dump_memory(self, label, path):
        """Take a memory dump of a machine.
        @param path: path to where to store the memory dump
        @raise CuckooMachineError: if error taking the memory dump
        """
        name = f"cuckoo_memdump_{random.randint(100000, 999999)}"
        with SmartConnection(**self.connect_opts) as conn:
            vm = self._get_virtual_machine_by_label(conn, label)
            if vm:
                self._create_snapshot(vm, name)
                self._download_snapshot(conn, vm, name, path)
                self._delete_snapshot(vm, name)
            else:
                raise CuckooMachineError(f"Machine {label} not found on host")

    def _list(self):
        """List virtual machines on vSphere host"""
        with SmartConnection(**self.connect_opts) as conn:
            vmlist = [vm.summary.config.name for vm in self._get_virtual_machines(conn)]

        return vmlist

    def _status(self, label):
        """Get power state of vm from vSphere host.
        @param label: virtual machine name
        @raise CuckooMachineError: if error getting status or machine not found
        """
        with SmartConnection(**self.connect_opts) as conn:
            vm = self._get_virtual_machine_by_label(conn, label)
            if not vm:
                raise CuckooMachineError(f"Machine {label} not found on server")

            status = vm.runtime.powerState
            self.set_status(label, status)
            return status

    def _get_virtual_machines(self, conn):
        """Iterate over all VirtualMachine managed objects on vSphere host"""

        def traverseDCFolders(conn, nodes, path=""):
            for node in nodes:
                if hasattr(node, "childEntity"):
                    yield from traverseDCFolders(conn, node.childEntity, f"{path}{node.name}/")
                else:
                    yield node, path + node.name

        def traverseVMFolders(conn, nodes):
            for node in nodes:
                if hasattr(node, "childEntity"):
                    yield from traverseVMFolders(conn, node.childEntity)
                else:
                    yield node

        self.VMtoDC = {}

        for dc, dcpath in traverseDCFolders(conn, conn.content.rootFolder.childEntity):
            for vm in traverseVMFolders(conn, dc.vmFolder.childEntity):
                if hasattr(vm.summary.config, "name"):
                    self.VMtoDC[vm.summary.config.name] = dcpath
                    yield vm

    def _get_virtual_machine_by_label(self, conn, label):
        """Return the named VirtualMachine managed object"""
        vg = (vm for vm in self._get_virtual_machines(conn) if vm.summary.config.name == label)
        return next(vg, None)

    def _get_snapshot_by_name(self, vm, name):
        """Return the named VirtualMachineSnapshot managed object for
        a virtual machine"""
        root = vm.snapshot.rootSnapshotList
        sg = (ss.snapshot for ss in self._traverseSnapshots(root) if ss.name == name)
        return next(sg, None)

    def _get_snapshot_power_state(self, vm, name):
        """Return the power state for a named VirtualMachineSnapshot object"""
        root = vm.snapshot.rootSnapshotList
        sg = (ss.state for ss in self._traverseSnapshots(root) if ss.name == name)
        return next(sg, None)

    def _create_snapshot(self, vm, name):
        """Create named snapshot of virtual machine"""
        log.info("Creating snapshot %s for machine %s", name, vm.summary.config.name)
        task = vm.CreateSnapshot_Task(name=name, description="Created by Cuckoo sandbox", memory=True, quiesce=False)
        try:
            self._wait_task(task)
        except CuckooMachineError as e:
            raise CuckooMachineError(f"CreateSnapshot: {e}")

    def _delete_snapshot(self, vm, name):
        """Remove named snapshot of virtual machine"""
        snapshot = self._get_snapshot_by_name(vm, name)
        if not snapshot:
            raise CuckooMachineError(f"Snapshot {name} for machine {vm.summary.config.name} not found")
        log.info("Removing snapshot %s for machine %s", name, vm.summary.config.name)
        task = snapshot.RemoveSnapshot_Task(removeChildren=True)
        try:
            self._wait_task(task)
        except CuckooMachineError as e:
            log.error("RemoveSnapshot: %s", e)

    def _revert_snapshot(self, vm, name):
        """Revert virtual machine to named snapshot"""
        snapshot = self._get_snapshot_by_name(vm, name)
        if not snapshot:
            raise CuckooMachineError(f"Snapshot {name} for machine {vm.summary.config.name} not found")
        log.info("Reverting machine %s to snapshot %s", vm.summary.config.name, name)
        task = snapshot.RevertToSnapshot_Task()
        try:
            self._wait_task(task)
        except CuckooMachineError as e:
            raise CuckooMachineError(f"RevertToSnapshot: {e}")

    def _download_snapshot(self, conn, vm, name, path):
        """Download snapshot file from host to local path"""

        # Get filespec to .vmsn file of named snapshot
        snapshot = self._get_snapshot_by_name(vm, name)
        if not snapshot:
            raise CuckooMachineError(f"Snapshot {name} for machine {vm.summary.config.name} not found")

        memorykey = datakey = filespec = None
        for s in vm.layoutEx.snapshot:
            if s.key == snapshot:
                memorykey = s.memoryKey
                datakey = s.dataKey
                break

        for f in vm.layoutEx.file:
            if f.key == memorykey and f.type in ("snapshotMemory", "suspendMemory"):
                filespec = f.name
                break

        if not filespec:
            for f in vm.layoutEx.file:
                if f.key == datakey and f.type == "snapshotData":
                    filespec = f.name
                    break

        if not filespec:
            raise CuckooMachineError("Could not find memory snapshot file")

        log.info("Downloading memory dump %s to %s", filespec, path)

        # Parse filespec to get datastore and file path
        datastore, filepath = re.match(r"\[([^\]]*)\] (.*)", filespec).groups()

        # Construct URL request
        params = {"dsName": datastore, "dcPath": self.VMtoDC.get(vm.summary.config.name, "ha-datacenter")}
        headers = {"Cookie": conn._stub.cookie}
        url = f"https://{self.connect_opts['host']}:{self.connect_opts['port']}/folder/{filepath}"

        # Stream download to specified local path
        try:
            response = requests.get(url, params=params, headers=headers, verify=False, stream=True)

            response.raise_for_status()

            with open(path, "wb") as localfile:
                for chunk in response.iter_content(16 * 1024):
                    localfile.write(chunk)

        except Exception as e:
            raise CuckooMachineError(f"Error downloading memory dump {filespec}: {e}")

    def _stop_virtual_machine(self, vm):
        """Power off a virtual machine"""
        log.info("Powering off virtual machine %s", vm.summary.config.name)
        task = vm.PowerOffVM_Task()
        try:
            self._wait_task(task)
        except CuckooMachineError as e:
            log.error("PowerOffVM: %s", e)

    def _wait_task(self, task):
        """Wait for a task to complete with timeout"""
        limit = timedelta(seconds=int(cfg.timeouts.vm_state))
        start = datetime.utcnow()

        while True:
            if task.info.state == "error":
                raise CuckooMachineError("Task error")

            if task.info.state == "success":
                break

            if datetime.utcnow() - start > limit:
                raise CuckooMachineError("Task timed out")

            time.sleep(1)

    def _traverseSnapshots(self, root):
        """Recursive depth-first traversal of snapshot tree"""
        for node in root:
            if len(node.childSnapshotList) > 0:
                yield from self._traverseSnapshots(node.childSnapshotList)
            yield node
