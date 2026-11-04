# Copyright (C) 2026 CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

import hashlib
import logging
import os
import subprocess
import tempfile
import time

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


stop_vm = """Stop-VM {vm} -TurnOff -Force"""
start_vm = """Start-VM -Name {vm}"""
restore_vm = """Restore-VMSnapshot -Name {sn} -VMName {vm} -Confirm:$false"""
suspend_vm = """Suspend-VM-VMSnapshot -VMName UbuntuSQL -Confirm:$false"""
check_vm = """Get-VM -Name {vm} ^| Select -ExpandProperty State"""


class HyperV(Machinery):
    """Virtualization layer for Hyper-V."""

    module_name = "hyperv"

    # Deadline for a single remote powershell call.
    CMD_TIMEOUT = 120
    # How long the multiplexed ssh connection is kept open after the last command.
    CONTROL_PERSIST = "60s"
    # Bounds on waiting for a machine to report Running.
    START_TIMEOUT = 300
    START_POLL_INTERVAL = 2

    def _initialize_check(self):
        """Check for configuration file and remote powershell setup.
        @raise CuckooMachineError: if configuration is missing or wrong.
        """
        if not self.options.hyperv.host:
            raise CuckooMachineError("Hyper-V Host missing from hyperv.conf")

        self.host = self.options.hyperv.host
        if not self.options.hyperv.username:
            raise CuckooMachineError(
                "Hyper-V SSH username missing from hyperv.conf (needs permissions to manage both Hyper-V and SSH)"
            )

        self.username = self.options.hyperv.username
        if not self.options.hyperv.ssh_key:
            raise CuckooMachineError("Hyper-V ssh private key path missing from hyperv.conf")
        self.ssh_key = self.options.hyperv.ssh_key

        # One control socket per user@host. The path is hashed because a unix socket path
        # is limited to ~108 bytes and the hostname is attacker-independent config data.
        digest = hashlib.sha256(f"{self.username}@{self.host}".encode()).hexdigest()[:16]
        self._control_path = os.path.join(tempfile.gettempdir(), f"cape-hyperv-{os.getuid()}-{digest}")

        super(HyperV, self)._initialize_check()

        log.info("Hyper-V machinery module initialised (%s).", self.host)

    def run_cmd(self, cmd):
        # Every call used to open a new ssh connection: a TCP connect, key exchange and
        # auth per command. start() alone issues four of them. ControlMaster keeps one
        # connection alive and multiplexes the rest onto it.
        argv = [
            "ssh",
            "-i",
            self.ssh_key,
            "-o",
            "BatchMode=yes",
            "-o",
            "ControlMaster=auto",
            "-o",
            f"ControlPath={self._control_path}",
            "-o",
            f"ControlPersist={self.CONTROL_PERSIST}",
            f"{self.username}@{self.host}",
            f"powershell.exe {cmd}",
        ]
        try:
            r = subprocess.run(
                argv,
                capture_output=True,
                timeout=self.CMD_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired as e:
            raise CuckooMachineError(f"Hyper-V command timed out after {self.CMD_TIMEOUT}s: {cmd}") from e
        return r.stdout.decode(errors="replace").strip()

    def power_off(self, id):
        self.run_cmd(stop_vm.format(vm=id))

    def get_vm_status(self, id):
        return self.run_cmd(check_vm.format(vm=id))

    def _is_running(self, id):
        power_state = self.get_vm_status(id)
        if power_state and power_state == "Running":
            return id

    def stop(self, id):
        if self._is_running(id):
            self.power_off(id)

    def start(self, id):
        vm_info = self.db.view_machine_by_label(id)
        self.stop(id)
        self.run_cmd(restore_vm.format(sn=vm_info.snapshot, vm=id))
        self.run_cmd(start_vm.format(vm=id))
        # This used to be `while not self._is_running(id): continue`, which issued
        # back-to-back remote status queries as fast as the host could spawn them, with
        # no upper bound.
        deadline = time.monotonic() + self.START_TIMEOUT
        while not self._is_running(id):
            if time.monotonic() >= deadline:
                raise CuckooMachineError(f"Hyper-V machine {id} did not reach the Running state within {self.START_TIMEOUT}s")
            time.sleep(self.START_POLL_INTERVAL)
