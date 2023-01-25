# Copyright (C) 2010-2015 Cuckoo Foundation, Context Information Security. (kevin.oreilly@contextis.co.uk)
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import subprocess
import time

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError
from lib.cuckoo.common.path_utils import path_exists

log = logging.getLogger(__name__)


class VMwareServer(Machinery):
    """Virtualization layer for remote VMware Workstation Server using vmrun utility."""

    LABEL = "vmx_path"

    def _initialize_check(self):
        """Check for configuration file and vmware setup.
        @raise CuckooMachineError: if configuration is missing or wrong.
        """
        if not self.options.vmwareserver.path:
            raise CuckooMachineError("VMware vmrun path missing, please add it to vmwareserver.conf")

        # Base checks.
        super(VMwareServer, self)._initialize_check()

    def _check_vmx(self, vmx_path):
        """Checks whether a vmx file exists and is valid.
        @param vmx_path: path to vmx file
        @raise CuckooMachineError: if file not found or not ending with .vmx
        """
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

        check_string = (
            f"{self.options.vmwareserver.path} -T ws-shared -h {self.options.vmwareserver.vmware_url} -u {self.options.vmwareserver.username} "
            f'-p {self.options.vmwareserver.password} listSnapshots "{vmx_path}"'
        )

        try:
            p = subprocess.Popen(check_string, universal_newlines=True, shell=True)
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
        self._check_snapshot(vmx_path, snapshot)

        # Check if the machine is already running, stop if so.
        if self._is_running(vmx_path):
            log.debug("Machine %s is already running, attempting to stop...", vmx_path)
            self.stop(vmx_path)
            time.sleep(3)

        self._revert(vmx_path, snapshot)

        time.sleep(3)

        start_string = (
            f"{self.options.vmwareserver.path} -T ws-shared -h {self.options.vmwareserver.vmware_url} -u {self.options.vmwareserver.username} "
            f'-p {self.options.vmwareserver.password} start "{vmx_path}"'
        )

        log.debug("Starting vm %s", vmx_path)

        try:
            p = subprocess.Popen(start_string, universal_newlines=True, shell=True)
            if self.options.vmwareserver.mode.lower() == "gui":
                output, _ = p.communicate()
                if output:
                    raise CuckooMachineError(f"Unable to start machine {vmx_path}: {output}")
        except OSError as e:
            mode = self.options.vmwareserver.mode.upper()
            raise CuckooMachineError(f"Unable to start machine {vmx_path} in {mode} mode: {e}")

    def stop(self, vmx_path):
        """Stops a virtual machine.
        @param vmx_path: path to vmx file
        @raise CuckooMachineError: if unable to stop.
        """

        stop_string = (
            f"{self.options.vmwareserver.path} -T ws-shared -h {self.options.vmwareserver.vmware_url} -u {self.options.vmwareserver.username} "
            f'-p {self.options.vmwareserver.password} stop "{vmx_path}" hard'
        )

        log.debug("Stopping vm %s", vmx_path)
        # log.debug("Stop string: %s", stop_string)

        if self._is_running(vmx_path):
            try:
                if subprocess.call(stop_string, universal_newlines=True, shell=True):
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
        log.debug("Revert snapshot for vm %s: %s", vmx_path, snapshot)

        revert_string = (
            f"{self.options.vmwareserver.path} -T ws-shared -h {self.options.vmwareserver.vmware_url} -u {self.options.vmwareserver.username} "
            f'-p {self.options.vmwareserver.password} revertToSnapshot "{vmx_path}" snapshot'
        )
        # log.debug("Revert string: %s", revert_string)

        try:
            if subprocess.call(revert_string, universal_newlines=True, shell=True):
                raise CuckooMachineError(f"Unable to revert snapshot for machine {vmx_path}: vmrun exited with error")

        except OSError as e:
            raise CuckooMachineError(f"Unable to revert snapshot for machine {vmx_path}: {e}")

    def _is_running(self, vmx_path):
        """Checks if virtual machine is running.
        @param vmx_path: path to vmx file
        @return: running status
        """
        list_string = (
            f"{self.options.vmwareserver.path} -T ws-shared -h {self.options.vmwareserver.vmware_url} -u {self.options.vmwareserver.username} "
            f'-p {self.options.vmwareserver.password} list "{vmx_path}"'
        )
        # log.debug("List string: %s", list_string)

        try:
            p = subprocess.Popen(list_string, universal_newlines=True, stdout=subprocess.PIPE, shell=True)
            output, error = p.communicate()
        except OSError as e:
            raise CuckooMachineError(f"Unable to check running status for {vmx_path}: {e}")
        else:
            if output:
                return vmx_path in output
            else:
                raise CuckooMachineError(f"Unable to check running status for {vmx_path}. No output from `vmrun list`")

    def _snapshot_from_vmx(self, vmx_path):
        """Get snapshot for a given vmx file.
        @param vmx_path: configuration option from config file
        """
        vm_info = self.db.view_machine_by_label(vmx_path)
        return vm_info.snapshot
