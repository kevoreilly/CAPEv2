# Copyright (C) 2017 Menlo Security
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import sys
import time

from requests.exceptions import RequestException

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError

try:
    from proxmoxer import ProxmoxAPI, ResourceException
except ImportError:
    sys.exit("Install by yourself. Missed dependency: pip3 install proxmoxer -U")

READ_RETRY_EXCEPTIONS = (ResourceException, RequestException)

# silence overly verbose INFO level logging default of proxmoxer module
logging.getLogger("proxmoxer").setLevel(logging.WARNING)

log = logging.getLogger(__name__)
cfg = Config()


class Proxmox(Machinery):
    """Manage Proxmox sandboxes."""

    module_name = "proxmox"

    def __init__(self):
        super().__init__()
        self.timeout = int(cfg.timeouts.vm_state)

    def _initialize_check(self):
        """Ensures that credentials have been entered into the config file.
        @raise CuckooCriticalError: if no credentials were provided
        """
        if not self.options.proxmox.username or not self.options.proxmox.password:
            raise CuckooCriticalError(
                "Proxmox credentials are missing, please add them to the Proxmox machinery configuration file"
            )
        if not self.options.proxmox.hostname:
            raise CuckooCriticalError("Proxmox hostname not set")

        super(Proxmox, self)._initialize_check()

    def _get_with_retry(self, resource, *, deadline, description, **kwargs):
        """Retry a Proxmox GET operation until the supplied deadline."""
        while True:
            try:
                return resource.get(**kwargs)
            except READ_RETRY_EXCEPTIONS as e:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CuckooMachineError(f"{description}: {e}") from e

                delay = min(1, remaining)
                log.warning("%s: %s; retrying in %.1f seconds", description, e, delay)
                time.sleep(delay)

                if time.monotonic() >= deadline:
                    raise CuckooMachineError(f"{description}: {e}") from e

    def find_vm(self, label):
        """Find a VM in the Proxmox cluster and return its node and vm proxy
        objects for extraction of additional data by other methods.

        @param label: the label of the VM to be compared to the VM's name in
                      Proxmox.
        @raise CuckooMachineError: if the VM cannot be found."""
        proxmox = ProxmoxAPI(
            self.options.proxmox.hostname,
            user=self.options.proxmox.username,
            password=self.options.proxmox.password,
            verify_ssl=False,
        )

        # /cluster/resources[type=vm] will give us all VMs no matter which node they reside on
        deadline = time.monotonic() + self.timeout
        vms = self._get_with_retry(
            proxmox.cluster.resources,
            deadline=deadline,
            description=f"{label}: Error enumerating VMs",
            type="vm",
        )

        for vm in vms:
            if vm["name"] == label:
                # dynamically address /nodes/<node>/{qemu,lxc,openvz,...}/<vmid> to get handle on VM
                node = proxmox.nodes(vm["node"])
                hv = node.__getattr__(vm["type"])
                vm = hv.__getattr__(str(vm["vmid"]))

                # remember various request proxies for subsequent actions
                return vm, node

        raise CuckooMachineError("Not found")

    def wait_for_task(self, taskid, label, vm, node):
        """Wait for long-running Proxmox task to finish.

        @param taskid: id of Proxmox task to wait for
        @return: task status, or None if the timeout expires."""
        deadline = time.monotonic() + self.timeout

        while time.monotonic() < deadline:
            try:
                task = self._get_with_retry(
                    node.tasks(taskid).status,
                    deadline=deadline,
                    description=f"{label}: Error getting status of task {taskid}",
                )
            except CuckooMachineError:
                return None

            # extract operation name from task status for display
            operation = task["type"]
            if operation.startswith("qm"):
                operation = operation[2:]

            if task["status"] != "stopped":
                log.debug("%s: Waiting for operation %s (%s) to finish", label, operation, taskid)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                time.sleep(min(1, remaining))
                continue

            # VMs sometimes remain locked for some seconds after a task
            # completed. They will get stuck in that state if another operation
            # is attempted. So query the current VM status to extract the lock
            # status.
            try:
                status = self._get_with_retry(
                    vm.status.current,
                    deadline=deadline,
                    description=f"{label}: Couldn't get VM status after task {taskid}",
                )
            except CuckooMachineError:
                return None

            if "lock" in status:
                log.debug("%s: Task finished but VM still locked", label)
                if status["lock"] != operation:
                    log.warning("%s: Task finished but VM locked by different operation: %s", label, operation)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                time.sleep(min(1, remaining))
                continue

            # task is really, really done
            return task

        # timeout expired
        return None

    def find_snapshot(self, label, vm):
        """Find a specific or the most current snapshot of a VM.

        @param label: VM label for additional parameter retrieval
        @raise CuckooMachineError: if snapshots cannot be enumerated."""
        # use a statically configured snapshot name if configured without any
        # additional checks. User has to make sure it exists then.
        snapshot = self.db.view_machine_by_label(label).snapshot
        if snapshot:
            return snapshot

        # heuristically determine the most recent snapshot if no snapshot name
        # is explicitly configured.
        log.debug("%s: No snapshot configured, determining most recent one", label)
        deadline = time.monotonic() + self.timeout
        snapshots = self._get_with_retry(
            vm.snapshot,
            deadline=deadline,
            description=f"{label}: Error enumerating snapshots",
        )

        snaptime = 0
        snapshot = None
        for snap in snapshots:
            # ignore "meta-snapshot" current which is the current state
            if snap["name"] == "current":
                continue

            if snap["snaptime"] > snaptime:
                snaptime = snap["snaptime"]
                snapshot = snap["name"]

        return snapshot

    def rollback(self, label, vm, node, retry=5, retry_index=0):
        """Roll back a VM's status to a statically configured or the most recent
        snapshot.

        @param label: VM label for lookup in Proxmox and additional parameter
                      retrieval.
        @raise CuckooMachineError: if snapshot cannot be found, reverting the
                                   machine to the snapshot cannot be triggered
                                   or times out or fails for another reason."""
        snapshot = self.find_snapshot(label, vm)
        if not snapshot:
            raise CuckooMachineError("No snapshot found - check config")

        try:
            log.debug("%s: Reverting to snapshot %s", label, snapshot)
            taskid = vm.snapshot(snapshot).rollback.post()
        except ResourceException as e:
            raise CuckooMachineError(f"Couldn't trigger rollback to snapshot {snapshot}: {e}")

        task = self.wait_for_task(taskid, label, vm, node)
        if not task:
            raise CuckooMachineError(f"Timeout expired while rolling back to snapshot {snapshot}")
        if task["exitstatus"] != "OK":
            if task["exitstatus"] == "timeout waiting on systemd":
                if retry > retry_index:
                    time.sleep(5)
                    self.rollback(label, vm, node, retry, retry_index + 1)
                else:
                    raise CuckooMachineError(
                        f"Rollback to snapshot {snapshot} failed: {task['exitstatus']} - Proxmox may be overwhelmed"
                    )
            else:
                raise CuckooMachineError(f"Rollback to snapshot {snapshot} failed: {task['exitstatus']}")

    def start(self, label):
        """Roll back VM to known-pristine snapshot and optionally start it if
        not already running after reverting to the snapshot.

        @param label: VM label for lookup by name in Proxmox additional
                      parameter retrieval.
        @raise CuckooMachineError: if snapshot cannot be found, reverting the
                                   machine to the snapshot or starting the VM
                                   cannot be triggered or times out or fails
                                   for another reason."""
        vm, node = self.find_vm(label)
        self.rollback(label, vm, node)

        deadline = time.monotonic() + self.timeout
        status = self._get_with_retry(
            vm.status.current,
            deadline=deadline,
            description=f"{label}: Couldn't get VM status",
        )

        if status["status"] == "running":
            log.debug("%s: Already running after rollback, no need to start it", label)
            return

        try:
            log.debug("%s: Starting VM", label)
            taskid = vm.status.start.post()
        except ResourceException as e:
            raise CuckooMachineError(f"Couldn't trigger start: {e}")

        task = self.wait_for_task(taskid, label, vm, node)
        if not task:
            raise CuckooMachineError("Timeout expired while starting")
        if task["exitstatus"] != "OK":
            raise CuckooMachineError(f"Start failed: {task['exitstatus']}")

    def stop(self, label):
        """Do a hard shutdown of the VM.

        @param label: VM label for lookup by name in Proxmox.
        @raise CuckooMachineError: if VM cannot be found or stopping it cannot
                                   be triggered or times out or fails for
                                   another reason."""
        vm, node = self.find_vm(label)

        try:
            log.debug("%s: Stopping VM", label)
            taskid = vm.status.stop.post()
        except ResourceException as e:
            raise CuckooMachineError(f"Couldn't trigger stop: {e}")

        task = self.wait_for_task(taskid, label, vm, node)
        if not task:
            raise CuckooMachineError("Timeout expired while stopping")
        if task["exitstatus"] != "OK":
            raise CuckooMachineError(f"Stop failed: {task['exitstatus']}")
