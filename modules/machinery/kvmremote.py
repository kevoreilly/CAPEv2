# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import xml.etree.ElementTree as ET

from lib.cuckoo.common.abstracts import LibVirtMachinery
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


class KVMRemote(LibVirtMachinery):
    """Virtualization layer for KVM Remote."""

    module_name = "kvmremote"

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if configuration is invalid
        """
        try:
            self.dsn = self.options.kvmremote.dsn
            self.interface = self.options.kvmremote.interface
        except AttributeError:
            raise CuckooMachineError("KVMRemote: DSN or Interface missing in global config section")

        for machine in self.machines():
            machine.dsn = self.dsn
            machine.interface = self.interface

        super(KVMRemote, self)._initialize_check()

    def _get_interface(self, label):
        xml = ET.fromstring(self._lookup(label).XMLDesc())
        elem = xml.find("./devices/interface[@type='network']")
        if elem is None:
            return None
        elem = elem.find("target")
        if elem is None:
            return None

        return elem.attrib["dev"]

    def start(self, label):
        super(KVMRemote, self).start(label)
        machine = self.db.view_machine_by_label(label)
        if machine:
            iface = getattr(machine, "interface", self._get_interface(label))
            if iface:
                self.db.set_machine_interface(label, iface)
            else:
                log.warning("Can't get iface for %s", label)
