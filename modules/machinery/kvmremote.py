# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import subprocess
import xml.etree.ElementTree as ET
import libvirt
import logging
import os

from lib.cuckoo.common.abstracts import LibVirtMachinery
from lib.cuckoo.common.exceptions import CuckooMachineError, CuckooCriticalError

log = logging.getLogger(__name__)

class KVMRemote(LibVirtMachinery):
    """Virtualization layer for KVM based on python-libvirt."""

    dsn = None

    def _list(self):
        """Overriden: we can't list having DSN per machine
            """
        raise NotImplementedError

    def _connect(self, label=None):
        """Connects to libvirt subsystem.
            @raise CuckooMachineError: when unable to connect to libvirt.
            """
        # Check if a connection string is available.

        dsn = self.options.get(label).get("dsn", None)

        if not dsn:
            raise CuckooMachineError("You must provide a proper "
                                     "connection string for "+label)

        try:
            return libvirt.open(dsn)
        except libvirt.libvirtError:
            raise CuckooMachineError("Cannot connect to libvirt")

    def _initialize(self, module_name):
        """Read configuration.
            @param module_name: module name.
        """
        super(KVMRemote, self)._initialize(module_name)

        hypervs_labels = self.options.get("kvmremote")["hypervisors"]
        hypervs_labels = ("".join(hypervs_labels.split())).split(",")

        for machine in self.machines():
            machine_cfg = self.options.get(machine.label)

            if machine_cfg.hypervisor:
                if machine_cfg.hypervisor not in hypervs_labels:
                    raise CuckooCriticalError(
                        "Unknown hypervisor %s for %s" % (machine_cfg.hypervisor, machine.label))

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
        super(KVMRemote, self).start(label)
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
            fd = open(path, "w")
            fd.close()
            try:
                from subprocess import DEVNULL  # py3k
            except ImportError:
                DEVNULL = open(os.devnull, 'wb')

            # this triggers local dump

                #self.vms[label].coreDump(path, flags=libvirt.VIR_DUMP_MEMORY_ONLY)

            machine_label = None
            hypverv_cfg = None
            # use first
            for machine in self.machines():
                machine_cfg = self.options.get(machine.label)
                hyperv_cfg = self.options.get(machine_cfg.hypervisor)
                break

            remote_host = hyperv_cfg['remote_host']

            log.info("Dumping volatile memory remotely @ %s (%s)" %
                     (remote_host, label))

            remote_output = subprocess.check_output(
                ['ssh', remote_host, "virsh", "dump", "--memory-only", label, "/data/memory/%s.memory.dump" % (label)], stderr=DEVNULL)
            log.debug("Copying memory from remote host")
            remote_output = subprocess.check_output(
                ['scp', '-q', remote_host + ":/data/memory/%s.memory.dump" % label, path], stderr=DEVNULL)
            log.debug("Removing memory from remote host")
            remote_output = subprocess.check_output(
                ['ssh', remote_host, "rm", "-f", "/data/memory/%s.memory.dump" % (label)], stderr=DEVNULL)

            if not os.path.isfile(path):
                raise CuckooMachineError("Error dumping memory virtual machine "
                                         "{0}: {1}".format(label, "file not found"))

        except libvirt.libvirtError as e:
            raise CuckooMachineError("Error dumping memory virtual machine "
                                     "{0}: {1}".format(label, e))
