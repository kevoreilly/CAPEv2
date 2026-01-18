# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import xml.etree.ElementTree as ET

from lib.cuckoo.common.abstracts import LibVirtMachinery
from lib.cuckoo.common.exceptions import CuckooMachineError

log = logging.getLogger(__name__)


class KVM(LibVirtMachinery):
    """Virtualization layer for KVM based on python-libvirt."""

    module_name = "kvm"

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if configuration is invalid
        """
        if not self.options.kvm.dsn:
            raise CuckooMachineError("KVM DSN is missing, please add it to the config file")
        self.dsn = self.options.kvm.dsn
        super(KVM, self)._initialize_check()

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
        super(KVM, self).start(label)
        machine = self.db.view_machine_by_label(label)
        if machine:
            iface = getattr(machine, "interface", self._get_interface(label))
            if iface:
                self.db.set_machine_interface(label, iface)
            else:
                log.warning("Can't get iface for %s", label)

    def store_vnc_port(self, label: str, task_id: int):
        xml = ET.fromstring(self._lookup(label).XMLDesc())
        graphics = xml.find("./devices/graphics")
        if graphics is not None:
            port = int(graphics.get("port", -1))
            if port > 0:
                self.db.set_vnc_port(task_id, port)
                return

        log.warning("Can't get VNC port for %s", label)
