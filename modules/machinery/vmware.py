# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file was originally produced by Mike Tu.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import glob
import logging
import os.path
import shutil
import subprocess
import time

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.path_utils import path_exists

log = logging.getLogger(__name__)


class VMware(Machinery):
    """Virtualization layer for VMware Workstation using vmrun utility."""

    LABEL = "vmx_path"

    def _initialize_check(self):
        """Check for configuration file and vmware setup.
        @raise CuckooMachineError: if configuration is missing or wrong.
        """
        if not self.options.vmware.path:
            raise CuckooMachineError("VMware vmrun path missing, please add it to vmware.conf")

        if not path_exists(self.options.vmware.path):
            raise CuckooMachineError(f"VMware vmrun not found in specified path {self.options.vmware.path}")
        # Consistency checks.
        for machine in self.machines():
            vmx_path = machine.label

            snapshot = self._snapshot_from_vmx(vmx_path)
            self._check_vmx(vmx_path)
            self._check_snapshot(vmx_path, snapshot)

        # Base checks.
        super(VMware, self)._initialize_check()

    def _check_vmx(self, vmx_path):
        """Checks whether a vmx file exists and is valid.
        @param vmx_path: path to vmx file
        @raise CuckooMachineError: if file not found or not ending with .vmx
        """
        # b".vms"? someone can test?
        if not vmx_path.endswith(".vmx"):
            raise CuckooMachineError(f"Wrong configuration: vm path not ending with .vmx: {vmx_path}")

        if not path_exists(vmx_path):
            raise CuckooMachineError(f"Vm file {vmx_path} not found")

    def _check_snapshot(self, vmx_path, snapshot):
        """Checks snapshot existance.
        @param vmx_path: path to vmx file
        @param snapshot: snapshot name
        @raise CuckooMachineError: if snapshot not found
        """
        try:
            p = subprocess.Popen(
                [self.options.vmware.path, "listSnapshots", vmx_path],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            output, _ = p.communicate()
        except OSError as e:
            raise CuckooMachineError(f"Unable to get snapshot list for {vmx_path}: {e}")
        else:
            if output:
                return snapshot in output
            else:
                raise CuckooMachineError(f"Unable to get snapshot list for {vmx_path}, no output from `vmrun listSnapshots`")

    def start(self, vmx_path):
        """Start a virtual machine.
        @param vmx_path: path to vmx file.
        @raise CuckooMachineError: if unable to start.
        """
        snapshot = self._snapshot_from_vmx(vmx_path)

        # Preventive check
        if self._is_running(vmx_path):
            raise CuckooMachineError(f"Machine {vmx_path} is already running")

        self._revert(vmx_path, snapshot)

        time.sleep(3)

        log.debug("Starting vm %s", vmx_path)
        try:
            p = subprocess.Popen(
                [self.options.vmware.path, "start", vmx_path, self.options.vmware.mode],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if self.options.vmware.mode.lower() == "gui":
                output, _ = p.communicate()
                if output:
                    raise CuckooMachineError(f"Unable to start machine {vmx_path}: {output}")
        except OSError as e:
            mode = self.options.vmware.mode.upper()
            raise CuckooMachineError(f"Unable to start machine {vmx_path} in {mode} mode: {e}")

    def stop(self, vmx_path):
        """Stops a virtual machine.
        @param vmx_path: path to vmx file
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s", vmx_path)
        if self._is_running(vmx_path):
            try:
                if subprocess.call(
                    [self.options.vmware.path, "stop", vmx_path, "hard"],
                    universal_newlines=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                ):
                    raise CuckooMachineError(f"Error shutting down machine {vmx_path}")
            except OSError as e:
                raise CuckooMachineError(f"Error shutting down machine {vmx_path}: {e}")
        else:
            log.warning("Trying to stop an already stopped machine: %s", vmx_path)

    def _revert(self, vmx_path, snapshot):
        """Revets machine to snapshot.
        @param vmx_path: path to vmx file
        @param snapshot: snapshot name
        @raise CuckooMachineError: if unable to revert
        """
        log.debug("Revert snapshot for vm %s", vmx_path)
        try:
            if subprocess.call(
                [self.options.vmware.path, "revertToSnapshot", vmx_path, snapshot],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ):
                raise CuckooMachineError(f"Unable to revert snapshot for machine {vmx_path}: vmrun exited with error")
        except OSError as e:
            raise CuckooMachineError(f"Unable to revert snapshot for machine {vmx_path}: {e}")

    def _is_running(self, vmx_path):
        """Checks if virtual machine is running.
        @param vmx_path: path to vmx file
        @return: running status
        """
        try:
            p = subprocess.Popen(
                [self.options.vmware.path, "list"], universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            output, error = p.communicate()
        except OSError as e:
            raise CuckooMachineError(f"Unable to check running status for {vmx_path}: {e}")
        else:
            if output:
                return vmx_path in output
            else:
                raise CuckooMachineError(f"Unable to check running status for {vmx_path}, no output from `vmrun list`")

    def _snapshot_from_vmx(self, vmx_path):
        """Get snapshot for a given vmx file.
        @param vmx_path: configuration option from config file
        """
        vm_info = self.db.view_machine_by_label(vmx_path)
        return vm_info.snapshot

    def dump_memory(self, vmx_path, path):
        """Take a memory dump of the machine."""
        if not path_exists(vmx_path):
            raise CuckooMachineError(
                f"Can't find .vmx file {vmx_path}. Ensure to configure a fully qualified path in vmware.conf (key = vmx_path)"
            )

        try:
            subprocess.call(
                [self.options.vmware.path, "snapshot", vmx_path, "memdump"],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as e:
            raise CuckooMachineError(f"vmrun failed to take a memory dump of the machine with label {vmx_path}: {e}")

        vmwarepath, _ = os.path.split(vmx_path)
        latestvmem = max(glob.iglob(os.path.join(vmwarepath, "*.vmem")), key=os.path.getctime)

        # We need to move the snapshot to the current analysis directory as
        # vmware doesn't support an option for the destination path :-/
        shutil.move(latestvmem, path)

        # Old snapshot can be deleted, as it isn't needed any longer.
        try:
            subprocess.call(
                [self.options.vmware.path, "deleteSnapshot", vmx_path, "memdump"],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as e:
            raise CuckooMachineError(f"vmrun failed to delete the temporary snapshot in {vmx_path}: {e}")

        log.info("Successfully generated memory dump for virtual machine with label %s", vmx_path)
