# Copyright (C) 2026 CAPE Sandbox authors
# This file is part of CAPE Sandbox - https://github.com/kevoreilly/CAPEv2
# See the file 'docs/LICENSE' for copying permission.

import logging
import subprocess

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


stop_vm = '''Stop-VM {vm} -TurnOff -Force'''
start_vm = '''Start-VM -Name {vm}'''
restore_vm = '''Restore-VMSnapshot -Name {sn} -VMName {vm} -Confirm:$false'''
suspend_vm = '''Suspend-VM-VMSnapshot -VMName UbuntuSQL -Confirm:$false'''
check_vm = '''Get-VM -Name {vm} ^| Select -ExpandProperty State'''


class HyperV(Machinery):
    """Virtualization layer for Hyper-V."""

    module_name = "hyperv"

    def _initialize_check(self):
        """Check for configuration file and remote powershell setup.
        @raise CuckooMachineError: if configuration is missing or wrong.
        """
        if not self.options.hyperv.host:
            raise CuckooMachineError("Hyper-V Host missing from hyperv.conf")

        self.host = self.options.hyperv.host
        if not self.options.hyperv.username:
            raise CuckooMachineError("Hyper-V SSH username missing from hyperv.conf (needs permissions to manage both Hyper-V and SSH)")

        self.username = self.options.hyperv.username
        if not self.options.hyperv.ssh_key:
            raise CuckooMachineError("Hyper-V ssh private key path missing from hyperv.conf")
        self.ssh_key = self.options.hyperv.ssh_key

        super(HyperV, self)._initialize_check()

        log.info("Hyper-V machinery module initialised (%s).", self.host)

    def run_cmd(self, cmd):
        r = subprocess.Popen("ssh -i {key} {user}@{host} '{cmd}'".format(key=self.ssh_key, user=self.username, host=self.host, cmd="powershell.exe " + cmd),
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
        return(r[0].decode().strip())

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
        self.run_cmd(restore_vm.format(sn=vm_info.snapshot,vm=id))
        self.run_cmd(start_vm.format(vm=id))
        while not self._is_running(id):
            continue


