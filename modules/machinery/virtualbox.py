# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import subprocess
import time

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError
from lib.cuckoo.common.path_utils import path_exists

try:
    import re2 as re
except ImportError:
    import re

log = logging.getLogger(__name__)
cfg = Config()


class VirtualBox(Machinery):
    """Virtualization layer for VirtualBox."""

    # VM states.
    SAVED = "saved"
    RUNNING = "running"
    POWEROFF = "poweroff"
    ABORTED = "aborted"
    ERROR = "machete"

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if VBoxManage is not found.
        """
        # VirtualBox specific checks.
        if not self.options.virtualbox.path:
            raise CuckooCriticalError("VirtualBox VBoxManage path missing, please add it to the config file")
        if not path_exists(self.options.virtualbox.path):
            raise CuckooCriticalError(f'VirtualBox VBoxManage not found at specified path "{self.options.virtualbox.path}"')

        # Base checks.
        super(VirtualBox, self)._initialize_check()

    def start(self, label):
        """Start a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start.
        """
        log.debug("Starting vm %s", label)

        if self._status(label) == self.RUNNING:
            raise CuckooMachineError(f"Trying to start an already started vm {label}")

        vm_info = self.db.view_machine_by_label(label)
        virtualbox_args = [self.options.virtualbox.path, "snapshot", label]
        if vm_info.snapshot:
            log.debug("Using snapshot %s for virtual machine %s", vm_info.snapshot, label)
            virtualbox_args.extend(["restore", vm_info.snapshot])
        else:
            log.debug("Using current snapshot for virtual machine %s", label)
            virtualbox_args.extend(["restorecurrent"])

        try:
            if subprocess.call(
                virtualbox_args, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True
            ):
                raise CuckooMachineError("VBoxManage exited with error restoring the machine's snapshot")
        except OSError as e:
            raise CuckooMachineError(f"VBoxManage failed restoring the machine: {e}")

        self._wait_status(label, self.SAVED)

        try:
            proc = subprocess.Popen(
                [self.options.virtualbox.path, "startvm", label, "--type", self.options.virtualbox.mode],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            output, err = proc.communicate()
            if err:
                raise OSError(err)
        except OSError as e:
            raise CuckooMachineError(f"VBoxManage failed starting the machine in {self.options.virtualbox.mode.upper()} mode: {e}")
        self._wait_status(label, self.RUNNING)

    def stop(self, label):
        """Stops a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop.
        """
        log.debug("Stopping vm %s", label)

        if self._status(label) in (self.POWEROFF, self.ABORTED):
            raise CuckooMachineError(f"Trying to stop an already stopped vm {label}")

        try:
            proc = subprocess.Popen(
                [self.options.virtualbox.path, "controlvm", label, "poweroff"],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            # Sometimes VBoxManage stucks when stopping vm so we needed
            # to add a timeout and kill it after that.
            stop_me = 0
            while proc.poll() is None:
                if stop_me < int(cfg.timeouts.vm_state):
                    time.sleep(1)
                    stop_me += 1
                else:
                    log.debug("Stopping vm %s timed out, killing", label)
                    proc.terminate()

            if proc.returncode != 0 and stop_me < int(cfg.timeouts.vm_state):
                log.debug("VBoxManage exited with error powering off the machine")
        except OSError as e:
            raise CuckooMachineError(f"VBoxManage failed powering off the machine: {e}")
        self._wait_status(label, [self.POWEROFF, self.ABORTED, self.SAVED])

    def _list(self):
        """Lists virtual machines installed.
        @return: virtual machine names list.
        """
        try:
            proc = subprocess.Popen(
                [self.options.virtualbox.path, "list", "vms"],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            output, _ = proc.communicate()
        except OSError as e:
            raise CuckooMachineError(f"VBoxManage error listing installed machines: {e}")

        machines = []
        for line in output.split("\n"):
            try:
                label = line.split('"', 2)[1]
                if label == "<inaccessible>":
                    log.warning("Found an inaccessible virtual machine, please check its state")
                else:
                    machines.append(label)
            except IndexError:
                continue

        return machines

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        log.debug("Getting status for %s", label)
        status = None
        try:
            proc = subprocess.Popen(
                [self.options.virtualbox.path, "showvminfo", label, "--machinereadable"],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            output, err = proc.communicate()

            if proc.returncode != 0:
                # It's quite common for virtualbox crap utility to exit with:
                # VBoxManage: error: Details: code E_ACCESSDENIED (0x80070005)
                # So we just log to debug this.
                log.debug("VBoxManage returns error checking status for machine %s: %s", label, err)
                status = self.ERROR
        except OSError as e:
            log.warning("VBoxManage failed to check status for machine %s: %s", label, e)
            status = self.ERROR
        if not status:
            for line in output.split("\n"):
                state = re.match(r"VMState=\"(\w+)\"", line, re.M | re.I)
                if state:
                    status = state.group(1)
                    log.debug("Machine %s status %s", label, status)
                    status = status.lower()
        # Report back status.
        if status:
            self.set_status(label, status)
            return status
        else:
            raise CuckooMachineError(f"Unable to get status for {label}")

    def dump_memory(self, label, path):
        """Takes a memory dump.
        @param path: path to where to store the memory dump.
        """

        try:
            subprocess.call(
                [self.options.virtualbox.path, "debugvm", label, "dumpvmcore", "--filename", path],
                universal_newlines=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                close_fds=True,
            )
            log.info("Successfully generated memory dump for virtual machine with label %s to path %s", label, path)
        except OSError as e:
            raise CuckooMachineError(f"VBoxManage failed to take a memory dump of the machine with label {label}: {e}")
