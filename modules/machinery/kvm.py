# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import xml.etree.ElementTree as ET

from lib.cuckoo.common.abstracts import LibVirtMachinery


class KVM(LibVirtMachinery):
    """Virtualization layer for KVM based on python-libvirt."""

    # Set KVM connection string.
    dsn = "qemu:///system"

    def _get_interface(self, label):
        xml = ET.fromstring(self._lookup(label).XMLDesc())
        elem = xml.find("./devices/interface[@type='network']")
        if elem is None:
            return elem
        elem = elem.find("target")
        if elem is None:
            return None

        return elem.attrib["dev"]

    def start(self, label):
        super(KVM, self).start(label)
        machine = self.db.view_machine_by_label(label)
        if machine and not hasattr(machine, "interface"):
            self.db.set_machine_interface(label, self._get_interface(label))
