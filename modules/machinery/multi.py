# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2019-2019 Christophe Vandeplas.
# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

"""
Pseudo-machinery for using multiple machinery.
"""

from __future__ import absolute_import
import inspect
import types

from lib.cuckoo.common.abstracts import LibVirtMachinery, Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooCriticalError


def import_plugin(name):
    try:
        module = __import__(name, globals(), locals(), ["dummy"], 0)
    except ImportError as e:
        raise CuckooCriticalError("Unable to import plugin " '"{0}": {1}'.format(name, e))

    for name, value in inspect.getmembers(module):
        if inspect.isclass(value):
            if issubclass(value, Machinery) and value is not Machinery and value is not LibVirtMachinery:
                return value


class MultiMachinery(Machinery):
    LABEL = "mm_label"

    _machineries = dict()
    _machines = dict()
    _machine_labels = dict()

    def set_options(self, options):
        if getattr(self, "options", None) is None:
            # First time being called, gather the configs of our sub-machineries
            for machinery_name in options.get("multi").get("machinery").split(","):
                machinery = {"config": Config(machinery_name), "module": import_plugin("modules.machinery." + machinery_name)()}
                machinery_label = machinery["module"].LABEL
                machinery["module"].set_options(machinery["config"])
                machinery_machines = machinery["config"].get(machinery_name)["machines"]

                orig_list_machines = machinery["module"].machines

                def list_machines(s):
                    machines = list()
                    for machine in orig_list_machines():
                        machine_name = self._machine_labels[machine.label]
                        machinery_name = self._machines[machine_name]["machinery"]
                        if self._machineries[machinery_name]["module"] == s:
                            machines.append(machine)
                    return machines

                machinery["module"].machines = types.MethodType(list_machines, machinery["module"])

                for machine_name in [machine.strip() for machine in machinery_machines.split(",")]:
                    machine = machinery["config"].get(machine_name)
                    machine["machinery"] = machinery_name

                    if "interface" not in machine:
                        machine["interface"] = machinery["config"].get(machinery_name)["interface"]

                    machine_label = machine[machinery_label]
                    machine["mm_label"] = machine_label
                    self._machine_labels[machine_label] = machine_name

                    self._machines[machine_name] = machine
                    setattr(options, machine_name, machine)

                self._machineries[machinery_name] = machinery
            setattr(options, "sections", dict())
            for mk, mv in self._machines.items():
                options.sections[mk] = mv
            options.multi["machines"] = list(self._machines.keys())
        super(MultiMachinery, self).set_options(options)

    def _initialize_check(self):
        for machinery in self._machineries.values():
            machinery["module"]._initialize_check()

    def start(self, label):
        machine_name = self._machine_labels.get(label)
        machine = self._machines.get(machine_name, None)
        machinery = self._machineries.get(machine["machinery"])
        machinery["module"].start(label)

    def stop(self, label=None):
        if label:
            machine_name = self._machine_labels.get(label)
            machine = self._machines.get(machine_name, None)
            machinery = self._machineries.get(machine["machinery"])
            machinery["module"].stop(label)

    def _status(self, label):
        machine_name = self._machine_labels.get(label)
        machine = self._machines.get(machine_name, None)
        machinery = self._machineries.get(machine["machinery"])
        return machinery["module"]._status(label)
