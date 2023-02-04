# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import subprocess
import xml.etree.ElementTree as ET

import libvirt
from lib.cuckoo.common.abstracts import LibVirtMachinery
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError

log = logging.getLogger(__name__)


class KVMRemote(LibVirtMachinery):
    """Virtualization layer for KVM based on python-libvirt."""

    dsn = None

    def _list(self):
        """Overriden: we can't list having DSN per machine"""
        raise NotImplementedError

    def _connect(self, label=None):
        """Connects to libvirt subsystem.
        @raise CuckooMachineError: when unable to connect to libvirt.
        """
        # Check if a connection string is available.

        dsn = self.options.get(label).get("dsn", None)

        if not dsn:
            raise CuckooMachineError(f"You must provide a proper connection string for {label}")

        try:
            return libvirt.open(dsn)
        except libvirt.libvirtError as e:
            raise CuckooMachineError("Cannot connect to libvirt") from e

    def _initialize(self, module_name):
        """Read configuration.
        @param module_name: module name.
        """
        super()._initialize(module_name)

        hypervs_labels = self.options.get("kvmremote")["hypervisors"]
        hypervs_labels = ("".join(hypervs_labels.split())).split(",")

        for machine in self.machines():
            machine_cfg = self.options.get(machine.label)

            if machine_cfg.hypervisor:
                if machine_cfg.hypervisor not in hypervs_labels:
                    raise CuckooCriticalError(f"Unknown hypervisor {machine_cfg.hypervisor} for {machine.label}")

                hyperv_cfg = self.options.get(machine_cfg.hypervisor)

                machine_cfg.dsn = hyperv_cfg.dsn
                machine_cfg.interface = hyperv_cfg.interface

    def _get_interface(self, label):
        if_cfg = self.options.get(label).get("interface")

        if if_cfg:
            return if_cfg

        xml = ET.fromstring(self._lookup(label).XMLDesc())
        elem = xml.find("./devices/interface[@type='network']")
        if elem is None:
            return elem
        elem = elem.find("target")
        if elem is None:
            return None

        return elem.attrib["dev"]

    def start(self, label):
        super().start(label)
        if not self.db.view_machine_by_label(label).interface:
            self.db.set_machine_interface(label, self._get_interface(label))

    def dump_memory(self, label, path):
        """Takes a memory dump.
        @param path: path to where to store the memory dump.
        """

        # ssh and create save file then copy to path
        try:
            # create the memory dump file ourselves first so it doesn't end up root/root 0600
            # it'll still be owned by root, so we can't delete it, but at least we can read it
            with open(path, "w"):
                pass

            # this triggers local dump
            # self.vms[label].coreDump(path, flags=libvirt.VIR_DUMP_MEMORY_ONLY)

            # use first
            for machine in self.machines():
                machine_cfg = self.options.get(machine.label)
                hyperv_cfg = self.options.get(machine_cfg.hypervisor)
                break

            remote_host = hyperv_cfg["remote_host"]

            log.info("Dumping volatile memory remotely @ %s (%s)", remote_host, label)
            subprocess.run(
                ("ssh", remote_host, "virsh", "dump", "--memory-only", label, f"/data/memory/{label}.memory.dump"),
                stderr=subprocess.DEVNULL,
            )

            log.debug("Copying memory from remote host")
            subprocess.run(("scp", "-q", f"{remote_host}:/data/memory/{label}.memory.dump", path), stderr=subprocess.DEVNULL)

            log.debug("Removing memory from remote host")
            subprocess.run(["ssh", remote_host, "rm", "-f", f"/data/memory/{label}.memory.dump"], stderr=subprocess.DEVNULL)

            if not os.path.isfile(path):
                raise CuckooMachineError(f"Error dumping memory virtual machine {label}: file not found")

        except libvirt.libvirtError as e:
            raise CuckooMachineError(f"Error dumping memory virtual machine {label}: {e}") from e
