# encoding: utf-8
# Copyright (C) 2010-2015 Cuckoo Foundation, Optiv, Inc. (brad.spengler@optiv.com).
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import datetime
import inspect
import io
import logging
import os
import socket
import threading
import time
import timeit
import xml.etree.ElementTree as ET
from builtins import NotImplementedError
from pathlib import Path
from typing import Dict, List

try:
    import dns.resolver
except ImportError:
    print("Missed dependency -> pip3 install dnspython")
import PIL
import requests

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.dictionary import Dictionary
from lib.cuckoo.common.exceptions import (
    CuckooCriticalError,
    CuckooDependencyError,
    CuckooMachineError,
    CuckooOperationalError,
    CuckooReportError,
)
from lib.cuckoo.common.integrations.mitre import mitre_load
from lib.cuckoo.common.path_utils import path_exists, path_mkdir
from lib.cuckoo.common.url_validate import url as url_validator
from lib.cuckoo.common.utils import create_folder, get_memdump_path, load_categories
from lib.cuckoo.core.database import Database

try:
    import re2 as re
except ImportError:
    import re

try:
    import libvirt

    HAVE_LIBVIRT = True
except ImportError:
    HAVE_LIBVIRT = False

try:
    from tldextract import TLDExtract

    HAVE_TLDEXTRACT = True
    logging.getLogger("filelock").setLevel("WARNING")
except ImportError:
    HAVE_TLDEXTRACT = False

repconf = Config("reporting")
_, categories_need_VM = load_categories()

mitre, HAVE_MITRE, _ = mitre_load(repconf.mitre.enabled)

log = logging.getLogger(__name__)
cfg = Config()
machinery_conf = Config(cfg.cuckoo.machinery)

myresolver = dns.resolver.Resolver()
myresolver.timeout = 5.0
myresolver.lifetime = 5.0
myresolver.domain = dns.name.Name("google-public-dns-a.google.com")
myresolver.nameserver = ["8.8.8.8"]


class Auxiliary:
    """Base abstract class for auxiliary modules."""

    def __init__(self):
        self.task = None
        self.machine = None
        self.options = None
        self.db = Database()

    def set_task(self, task):
        self.task = task

    def set_machine(self, machine):
        self.machine = machine

    def set_options(self, options):
        self.options = options

    def start(self):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError


class Machinery:
    """Base abstract class for machinery modules."""

    # Default label used in machinery configuration file to supply virtual
    # machine name/label/vmx path. Override it if you dubbed it in another
    # way.
    LABEL = "label"

    def __init__(self):
        self.module_name = ""
        self.options = None
        # Database pointer.
        self.db = Database()
        # Machine table is cleaned to be filled from configuration file
        # at each start.
        self.db.clean_machines()

    def set_options(self, options: dict):
        """Set machine manager options.
        @param options: machine manager options dict.
        """
        self.options = options

    def initialize(self, module_name):
        """Read, load, and verify machines configuration.
        @param module_name: module name.
        """
        # Load.
        self._initialize(module_name)

        # Run initialization checks.
        self._initialize_check()

    def _initialize(self, module_name):
        """Read configuration.
        @param module_name: module name.
        """
        self.module_name = module_name
        mmanager_opts = self.options.get(module_name)
        if not isinstance(mmanager_opts["machines"], list):
            mmanager_opts["machines"] = str(mmanager_opts["machines"]).strip().split(",")

        for machine_id in mmanager_opts["machines"]:
            try:
                machine_opts = self.options.get(machine_id.strip())
                machine = Dictionary()
                machine.id = machine_id.strip()
                machine.label = machine_opts[self.LABEL]
                machine.platform = machine_opts["platform"]
                machine.tags = machine_opts.get("tags")
                machine.ip = machine_opts["ip"]
                machine.arch = machine_opts["arch"]
                machine.reserved = machine_opts.get("reserved", False)

                # If configured, use specific network interface for this
                # machine, else use the default value.
                if machine_opts.get("interface"):
                    machine.interface = machine_opts["interface"]
                else:
                    machine.interface = mmanager_opts.get("interface")

                # If configured, use specific snapshot name, else leave it
                # empty and use default behaviour.
                machine.snapshot = machine_opts.get("snapshot")

                machine.resultserver_ip = machine_opts.get("resultserver_ip", cfg.resultserver.ip)
                machine.resultserver_port = machine_opts.get("resultserver_port")
                if machine.resultserver_port is None:
                    # The ResultServer port might have been dynamically changed,
                    # get it from the ResultServer singleton. Also avoid import
                    # recursion issues by importing ResultServer here.
                    from lib.cuckoo.core.resultserver import ResultServer

                    machine.resultserver_port = ResultServer().port

                # Strip parameters.
                for key, value in machine.items():
                    if value and isinstance(value, str):
                        machine[key] = value.strip()

                self.db.add_machine(
                    name=machine.id,
                    label=machine.label,
                    arch=machine.arch,
                    ip=machine.ip,
                    platform=machine.platform,
                    tags=machine.tags,
                    interface=machine.interface,
                    snapshot=machine.snapshot,
                    resultserver_ip=machine.resultserver_ip,
                    resultserver_port=machine.resultserver_port,
                    reserved=machine.reserved,
                )
            except (AttributeError, CuckooOperationalError) as e:
                log.warning("Configuration details about machine %s are missing: %s", machine_id.strip(), e)
                continue

    def _initialize_check(self):
        """Runs checks against virtualization software when a machine manager is initialized.
        @note: in machine manager modules you may override or superclass his method.
        @raise CuckooMachineError: if a misconfiguration or a unkown vm state is found.
        """
        try:
            configured_vms = self._list()
        except NotImplementedError:
            return

        # If machinery_screenshots are enabled, check the machinery supports it.
        if cfg.cuckoo.machinery_screenshots:
            # inspect function members available on the machinery class
            cls_members = inspect.getmembers(self.__class__, predicate=inspect.isfunction)
            for name, function in cls_members:
                if name != Machinery.screenshot.__name__:
                    continue
                if Machinery.screenshot == function:
                    msg = f"machinery {self.module_name} does not support machinery screenshots"
                    raise CuckooCriticalError(msg)
                break
            else:
                raise NotImplementedError(f"missing machinery method: {Machinery.screenshot.__name__}")

        for machine in self.machines():
            # If this machine is already in the "correct" state, then we
            # go on to the next machine.
            if machine.label in configured_vms and self._status(machine.label) in (self.POWEROFF, self.ABORTED):
                continue

            # This machine is currently not in its correct state, we're going
            # to try to shut it down. If that works, then the machine is fine.
            try:
                self.stop(machine.label)
            except CuckooMachineError as e:
                msg = f"Please update your configuration. Unable to shut '{machine.label}' down or find the machine in its proper state: {e}"
                raise CuckooCriticalError(msg) from e

        if not cfg.timeouts.vm_state:
            raise CuckooCriticalError("Virtual machine state change timeout setting not found, please add it to the config file")

    def machines(self):
        """List virtual machines.
        @return: virtual machines list
        """
        return self.db.list_machines(include_reserved=True)

    def availables(self, label=None, platform=None, tags=None, arch=None, include_reserved=False, os_version=[]):
        """How many (relevant) machines are free.
        @param label: machine ID.
        @param platform: machine platform.
        @param tags: machine tags
        @param arch: machine arch
        @return: free machines count.
        """
        return self.db.count_machines_available(
            label=label, platform=platform, tags=tags, arch=arch, include_reserved=include_reserved, os_version=os_version
        )

    def acquire(self, machine_id=None, platform=None, tags=None, arch=None, os_version=[], need_scheduled=False):
        """Acquire a machine to start analysis.
        @param machine_id: machine ID.
        @param platform: machine platform.
        @param tags: machine tags
        @param arch: machine arch
        @param os_version: tags to filter per OS version. Ex: winxp, win7, win10, win11
        @param need_scheduled: should the result be filtered on 'scheduled' machine status
        @return: machine or None.
        """
        if machine_id:
            return self.db.lock_machine(label=machine_id, need_scheduled=need_scheduled)
        elif platform:
            return self.db.lock_machine(
                platform=platform, tags=tags, arch=arch, os_version=os_version, need_scheduled=need_scheduled
            )
        return self.db.lock_machine(tags=tags, arch=arch, os_version=os_version, need_scheduled=need_scheduled)

    def get_machines_scheduled(self):
        return self.db.get_machines_scheduled()

    def release(self, label=None):
        """Release a machine.
        @param label: machine name.
        """
        self.db.unlock_machine(label)

    def running(self):
        """Returns running virtual machines.
        @return: running virtual machines list.
        """
        return self.db.list_machines(locked=True)

    def screenshot(self, label, path):
        """Screenshot a running virtual machine.
        @param label: machine name
        @param path: where to store the screenshot
        @raise NotImplementedError
        """
        raise NotImplementedError

    def shutdown(self):
        """Shutdown the machine manager. Kills all alive machines.
        @raise CuckooMachineError: if unable to stop machine.
        """
        if len(self.running()) > 0:
            log.info("Still %d guests still alive, shutting down...", len(self.running()))
            for machine in self.running():
                try:
                    self.stop(machine.label)
                except CuckooMachineError as e:
                    log.warning("Unable to shutdown machine %s, please check manually. Error: %s", machine.label, e)

    def set_status(self, label, status):
        """Set status for a virtual machine.
        @param label: virtual machine label
        @param status: new virtual machine status
        """
        self.db.set_machine_status(label, status)

    def start(self, label=None):
        """Start a machine.
        @param label: machine name.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def stop(self, label=None):
        """Stop a machine.
        @param label: machine name.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def _list(self):
        """Lists virtual machines configured.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def dump_memory(self, label, path):
        """Takes a memory dump of a machine.
        @param path: path to where to store the memory dump.
        """
        raise NotImplementedError

    def _wait_status(self, label, state):
        """Waits for a vm status.
        @param label: virtual machine name.
        @param state: virtual machine status, accepts multiple states as list.
        @raise CuckooMachineError: if default waiting timeout expire.
        """
        # This block was originally suggested by Loic Jaquemet.
        waitme = 0
        try:
            current = self._status(label)
        except NameError:
            return

        if isinstance(state, str):
            state = [state]
        while current not in state:
            log.debug("Waiting %d cuckooseconds for machine %s to switch to status %s", waitme, label, state)
            if waitme > int(cfg.timeouts.vm_state):
                raise CuckooMachineError(f"Timeout hit while for machine {label} to change status")
            time.sleep(1)
            waitme += 1
            current = self._status(label)

    def delete_machine(self, name):
        """Delete a virtual machine.
        @param name: virtual machine name
        """
        _ = self.db.delete_machine(name)


class LibVirtMachinery(Machinery):
    """Libvirt based machine manager.

    If you want to write a custom module for a virtualization software
    supported by libvirt you have just to inherit this machine manager and
    change the connection string.
    """

    # VM states.
    RUNNING = "running"
    PAUSED = "paused"
    POWEROFF = "poweroff"
    ERROR = "machete"
    ABORTED = "abort"

    def __init__(self):

        if not categories_need_VM:
            return

        if not HAVE_LIBVIRT:
            raise CuckooDependencyError(
                "Unable to import libvirt. Ensure that you properly installed it by running: cd /opt/CAPEv2/ ; sudo -u cape poetry run extra/libvirt_installer.sh"
            )

        super(LibVirtMachinery, self).__init__()

    def initialize(self, module):
        """Initialize machine manager module. Override default to set proper
        connection string.
        @param module:  machine manager module
        """
        super(LibVirtMachinery, self).initialize(module)

    def _initialize_check(self):
        """Runs all checks when a machine manager is initialized.
        @raise CuckooMachineError: if libvirt version is not supported.
        """
        # Version checks.
        if not self._version_check():
            raise CuckooMachineError("Libvirt version is not supported, please get an updated version")

        # Preload VMs
        self.vms = self._fetch_machines()

        # Base checks. Also attempts to shutdown any machines which are
        # currently still active.
        super(LibVirtMachinery, self)._initialize_check()

    def start(self, label):
        """Starts a virtual machine.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to start virtual machine.
        """
        log.debug("Starting machine %s", label)

        if self._status(label) != self.POWEROFF:
            msg = f"Trying to start a virtual machine that has not been turned off {label}"
            raise CuckooMachineError(msg)

        conn = self._connect(label)

        vm_info = self.db.view_machine_by_label(label)

        snapshot_list = self.vms[label].snapshotListNames(flags=0)

        # If a snapshot is configured try to use it.
        if vm_info.snapshot and vm_info.snapshot in snapshot_list:
            # Revert to desired snapshot, if it exists.
            log.debug("Using snapshot %s for virtual machine %s", vm_info.snapshot, label)
            try:
                vm = self.vms[label]
                snapshot = vm.snapshotLookupByName(vm_info.snapshot, flags=0)
                self.vms[label].revertToSnapshot(snapshot, flags=0)
            except libvirt.libvirtError as e:
                msg = f"Unable to restore snapshot {vm_info.snapshot} on virtual machine {label}"
                raise CuckooMachineError(msg) from e
            finally:
                self._disconnect(conn)
        elif self._get_snapshot(label):
            snapshot = self._get_snapshot(label)
            log.debug("Using snapshot %s for virtual machine %s", snapshot.getName(), label)
            try:
                self.vms[label].revertToSnapshot(snapshot, flags=0)
            except libvirt.libvirtError as e:
                raise CuckooMachineError(f"Unable to restore snapshot on virtual machine {label}") from e
            finally:
                self._disconnect(conn)
        else:
            self._disconnect(conn)
            raise CuckooMachineError(f"No snapshot found for virtual machine {label}")

        # Check state.
        self._wait_status(label, self.RUNNING)

    def stop(self, label):
        """Stops a virtual machine. Kill them all.
        @param label: virtual machine name.
        @raise CuckooMachineError: if unable to stop virtual machine.
        """
        log.debug("Stopping machine %s", label)

        if self._status(label) == self.POWEROFF:
            raise CuckooMachineError(f"Trying to stop an already stopped machine {label}")

        # Force virtual machine shutdown.
        conn = self._connect(label)
        try:
            if not self.vms[label].isActive():
                log.debug("Trying to stop an already stopped machine %s, skipping", label)
            else:
                self.vms[label].destroy()  # Machete's way!
        except libvirt.libvirtError as e:
            raise CuckooMachineError(f"Error stopping virtual machine {label}: {e}") from e
        finally:
            self._disconnect(conn)
        # Check state.
        self._wait_status(label, self.POWEROFF)

    def shutdown(self):
        """Override shutdown to free libvirt handlers - they print errors."""
        for machine in self.machines():
            # If the machine is already shutdown, move on
            if self._status(machine.label) in (self.POWEROFF, self.ABORTED):
                continue
            try:
                log.info("Shutting down machine '%s'", machine.label)
                self.stop(machine.label)
            except CuckooMachineError as e:
                log.warning("Unable to shutdown machine %s, please check manually. Error: %s", machine.label, e)

        # Free handlers.
        self.vms = None

    def screenshot(self, label, path):
        """Screenshot a running virtual machine.
        @param label: machine name
        @param path: where to store the screenshot
        """
        conn = self._connect()
        try:
            vm = conn.lookupByName(label)
        except libvirt.libvirtError as e:
            raise CuckooMachineError(f"Error screenshotting virtual machine {label}: {e}") from e
        stream0, screen = conn.newStream(), 0
        # ignore the mime type returned by the call to screenshot()
        _ = vm.screenshot(stream0, screen)

        buffer = io.BytesIO()

        def stream_handler(_, data, buffer):
            buffer.write(data)

        folder_name, _ = path.rsplit("/", 1)
        if not path_exists(folder_name):
            path_mkdir(folder_name, parent=True, exist_ok=True)

        stream0.recvAll(stream_handler, buffer)
        stream0.finish()
        streamed_img = PIL.Image.open(buffer)
        streamed_img.convert(mode="RGB").save(path)

    def dump_memory(self, label, path):
        """Takes a memory dump.
        @param path: path to where to store the memory dump.
        """
        log.debug("Dumping memory for machine %s", label)

        conn = self._connect(label)
        try:
            # create the memory dump file ourselves first so it doesn't end up root/root 0600
            # it'll still be owned by root, so we can't delete it, but at least we can read it
            fd = open(path, "w")
            fd.close()
            self.vms[label].coreDump(path, flags=libvirt.VIR_DUMP_MEMORY_ONLY)
        except libvirt.libvirtError as e:
            raise CuckooMachineError(f"Error dumping memory virtual machine {label}: {e}") from e
        finally:
            self._disconnect(conn)

    def _status(self, label):
        """Gets current status of a vm.
        @param label: virtual machine name.
        @return: status string.
        """
        log.debug("Getting status for %s", label)

        # Stetes mapping of python-libvirt.
        # virDomainState
        # VIR_DOMAIN_NOSTATE = 0
        # VIR_DOMAIN_RUNNING = 1
        # VIR_DOMAIN_BLOCKED = 2
        # VIR_DOMAIN_PAUSED = 3
        # VIR_DOMAIN_SHUTDOWN = 4
        # VIR_DOMAIN_SHUTOFF = 5
        # VIR_DOMAIN_CRASHED = 6
        # VIR_DOMAIN_PMSUSPENDED = 7

        conn = self._connect(label)
        try:
            state = self.vms[label].state(flags=0)
        except libvirt.libvirtError as e:
            raise CuckooMachineError(f"Error getting status for virtual machine {label}: {e}") from e
        finally:
            self._disconnect(conn)

        if state:
            if state[0] == 1:
                status = self.RUNNING
            elif state[0] == 3:
                status = self.PAUSED
            elif state[0] in {4, 5}:
                status = self.POWEROFF
            else:
                status = self.ERROR

        # Report back status.
        if status:
            self.set_status(label, status)
            return status
        else:
            raise CuckooMachineError(f"Unable to get status for {label}")

    def _connect(self, label=None):
        """Connects to libvirt subsystem.
        @raise CuckooMachineError: when unable to connect to libvirt.
        """
        # Check if a connection string is available.
        if not self.dsn:
            raise CuckooMachineError("You must provide a proper connection string")

        try:
            return libvirt.open(self.dsn)
        except libvirt.libvirtError as e:
            raise CuckooMachineError("Cannot connect to libvirt") from e

    def _disconnect(self, conn):
        """Disconnects to libvirt subsystem.
        @raise CuckooMachineError: if cannot disconnect from libvirt.
        """
        try:
            conn.close()
        except libvirt.libvirtError as e:
            raise CuckooMachineError("Cannot disconnect from libvirt") from e

    def _fetch_machines(self):
        """Fetch machines handlers.
        @return: dict with machine label as key and handle as value.
        """
        return {vm.label: self._lookup(vm.label) for vm in self.machines()}

    def _lookup(self, label):
        """Search for a virtual machine.
        @param conn: libvirt connection handle.
        @param label: virtual machine name.
        @raise CuckooMachineError: if virtual machine is not found.
        """
        conn = self._connect(label)
        try:
            vm = conn.lookupByName(label)
        except libvirt.libvirtError as e:
            raise CuckooMachineError(f"Cannot find machine {label}") from e
        finally:
            self._disconnect(conn)
        return vm

    def _list(self):
        """List available virtual machines.
        @raise CuckooMachineError: if unable to list virtual machines.
        """
        conn = self._connect()
        try:
            names = conn.listDefinedDomains()
        except libvirt.libvirtError as e:
            raise CuckooMachineError("Cannot list domains") from e
        finally:
            self._disconnect(conn)
        return names

    def _version_check(self):
        """Check if libvirt release supports snapshots.
        @return: True or false.
        """
        return libvirt.getVersion() >= 8000

    def _get_snapshot(self, label):
        """Get current snapshot for virtual machine
        @param label: virtual machine name
        @return None or current snapshot
        @raise CuckooMachineError: if cannot find current snapshot or
                                   when there are too many snapshots available
        """

        def _extract_creation_time(node):
            """Extracts creation time from a KVM vm config file.
            @param node: config file node
            @return: extracted creation time
            """
            xml = ET.fromstring(node.getXMLDesc(flags=0))
            return xml.findtext("./creationTime")

        snapshot = None
        conn = self._connect(label)
        try:
            vm = self.vms[label]

            # Try to get the currrent snapshot, otherwise fallback on the latest
            # from config file.
            if vm.hasCurrentSnapshot(flags=0):
                snapshot = vm.snapshotCurrent(flags=0)
            else:
                log.debug("No current snapshot, using latest snapshot")

                # No current snapshot, try to get the last one from config file.
                all_snapshots = vm.listAllSnapshots(flags=0)
                if all_snapshots:
                    snapshot = sorted(all_snapshots, key=_extract_creation_time, reverse=True)[0]
        except libvirt.libvirtError:
            raise CuckooMachineError(f"Unable to get snapshot for virtual machine {label}")
        finally:
            self._disconnect(conn)

        return snapshot


class Processing:
    """Base abstract class for processing module."""

    order = 1
    enabled = True

    def __init__(self, results=None):
        self.analysis_path = ""
        self.logs_path = ""
        self.task = None
        self.options = None
        self.results = results

    def set_options(self, options):
        """Set report options.
        @param options: report options dict.
        """
        self.options = options

    def set_task(self, task):
        """Add task information.
        @param task: task dictionary.
        """
        self.task = task

    def set_path(self, analysis_path):
        """Set paths.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.log_path = os.path.join(self.analysis_path, "analysis.log")
        self.package_files = os.path.join(self.analysis_path, "package_files")
        self.file_path = os.path.realpath(os.path.join(self.analysis_path, "binary"))
        self.dropped_path = os.path.join(self.analysis_path, "files")
        self.files_metadata = os.path.join(self.analysis_path, "files.json")
        self.procdump_path = os.path.join(self.analysis_path, "procdump")
        self.CAPE_path = os.path.join(self.analysis_path, "CAPE")
        self.logs_path = os.path.join(self.analysis_path, "logs")
        self.shots_path = os.path.join(self.analysis_path, "shots")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        self.pmemory_path = os.path.join(self.analysis_path, "memory")
        self.memory_path = get_memdump_path(analysis_path.rsplit("/", 1)[-1])
        # self.memory_path = os.path.join(self.analysis_path, "memory.dmp")
        self.network_path = os.path.join(self.analysis_path, "network")
        self.tlsmaster_path = os.path.join(self.analysis_path, "tlsmaster.txt")
        self.self_extracted = os.path.join(self.analysis_path, "selfextracted")

    def add_statistic_tmp(self, name, field, pretime):
        timediff = timeit.default_timer() - pretime
        value = round(timediff, 3)

        if name not in self.results["temp_processing_stats"]:
            self.results["temp_processing_stats"][name] = {}

        # To be able to add yara/capa and others time summary over all processing modules
        if field in self.results["temp_processing_stats"][name]:
            self.results["temp_processing_stats"][name][field] += value
        else:
            self.results["temp_processing_stats"][name][field] = value

    def run(self):
        """Start processing.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError


class Signature:
    """Base class for Cuckoo signatures."""

    name = ""
    description = ""
    severity = 1
    confidence = 100
    weight = 1
    categories = []
    families = []
    authors = []
    references = []
    alert = False
    enabled = True
    minimum = None
    maximum = None
    ttps = []
    mbcs = []

    # Higher order will be processed later (only for non-evented signatures)
    # this can be used for having meta-signatures that check on other lower-
    # order signatures being matched
    order = 0

    evented = False
    filter_processnames = set()
    filter_apinames = set()
    filter_categories = set()
    filter_analysistypes = set()
    banned_suricata_sids = ()

    def __init__(self, results=None):
        self.data = []
        self.new_data = []
        self.results = results
        self._current_call_cache = None
        self._current_call_dict = None
        self._current_call_raw_cache = None
        self._current_call_raw_dict = None
        self.hostname2ips = {}
        self.machinery_conf = machinery_conf
        self.matched = False

        # These are set during the iteration of evented signatures
        self.pid = None
        self.cid = None
        self.call = None

    def statistics_custom(self, pretime, extracted: bool = False):
        """
        Aux function for custom stadistics on signatures
        @param pretime: start time as datetime object
        @param extracted: conf extraction from inside signature to count success extraction vs sig run
        """
        timediff = timeit.default_timer() - pretime
        self.results["custom_statistics"] = {
            "name": self.name,
            "time": round(timediff, 3),
            "extracted": int(extracted),
        }

    def set_path(self, analysis_path):
        """Set analysis folder path.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.conf_path = os.path.join(self.analysis_path, "analysis.conf")
        self.file_path = os.path.realpath(os.path.join(self.analysis_path, "binary"))
        self.dropped_path = os.path.join(self.analysis_path, "files")
        self.procdump_path = os.path.join(self.analysis_path, "procdump")
        self.CAPE_path = os.path.join(self.analysis_path, "CAPE")
        self.reports_path = os.path.join(self.analysis_path, "reports")
        self.shots_path = os.path.join(self.analysis_path, "shots")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        self.pmemory_path = os.path.join(self.analysis_path, "memory")
        # self.memory_path = os.path.join(self.analysis_path, "memory.dmp")
        self.memory_path = get_memdump_path(analysis_path.rsplit("/", 1)[-1])
        self.self_extracted = os.path.join(self.analysis_path, "selfextracted")

        try:
            create_folder(folder=self.reports_path)
        except CuckooOperationalError as e:
            CuckooReportError(e)

    def yara_detected(self, name):

        target = self.results.get("target", {})
        if target.get("category") in ("file", "static") and target.get("file"):
            for keyword in ("cape_yara", "yara"):
                for yara_block in self.results["target"]["file"].get(keyword, []):
                    if re.findall(name, yara_block["name"], re.I):
                        yield "sample", self.results["target"]["file"]["path"], yara_block, self.results["target"]["file"]

            for block in target["file"].get("extracted_files", []):
                for keyword in ("cape_yara", "yara"):
                    for yara_block in block[keyword]:
                        if re.findall(name, yara_block["name"], re.I):
                            # we can't use here values from set_path
                            yield "sample", block["path"], yara_block, block

        for block in self.results.get("CAPE", {}).get("payloads", []) or []:
            for sub_keyword in ("cape_yara", "yara"):
                for yara_block in block.get(sub_keyword, []):
                    if re.findall(name, yara_block["name"], re.I):
                        yield sub_keyword, block["path"], yara_block, block

            for subblock in block.get("extracted_files", []):
                for keyword in ("cape_yara", "yara"):
                    for yara_block in subblock[keyword]:
                        if re.findall(name, yara_block["name"], re.I):
                            yield "sample", subblock["path"], yara_block, block

        for keyword in ("procdump", "procmemory", "extracted", "dropped"):
            if self.results.get(keyword) is not None:
                for block in self.results.get(keyword, []):
                    if not isinstance(block, dict):
                        continue
                    for sub_keyword in ("cape_yara", "yara"):
                        for yara_block in block.get(sub_keyword, []):
                            if re.findall(name, yara_block["name"], re.I):
                                path = block["path"] if block.get("path", False) else ""
                                yield keyword, path, yara_block, block

                        if keyword == "procmemory":
                            for pe in block.get("extracted_pe", []) or []:
                                for yara_block in pe.get(sub_keyword, []) or []:
                                    if re.findall(name, yara_block["name"], re.I):
                                        yield "extracted_pe", pe["path"], yara_block, block

                    for subblock in block.get("extracted_files", []):
                        for keyword in ("cape_yara", "yara"):
                            for yara_block in subblock[keyword]:
                                if re.findall(name, yara_block["name"], re.I):
                                    yield "sample", subblock["path"], yara_block, block

        macro_path = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.results["info"]["id"]), "macros")
        for macroname in self.results.get("static", {}).get("office", {}).get("Macro", {}).get("info", []) or []:
            for yara_block in self.results["static"]["office"]["Macro"]["info"].get("macroname", []) or []:
                for sub_block in self.results["static"]["office"]["Macro"]["info"]["macroname"].get(yara_block, []) or []:
                    if re.findall(name, sub_block["name"], re.I):
                        yield "macro", os.path.join(macro_path, macroname), sub_block, self.results["static"]["office"]["Macro"][
                            "info"
                        ]

        if self.results.get("static", {}).get("office", {}).get("XLMMacroDeobfuscator", False):
            for yara_block in self.results["static"]["office"]["XLMMacroDeobfuscator"].get("info", []).get("yara_macro", []) or []:
                if re.findall(name, yara_block["name"], re.I):
                    yield "macro", os.path.join(macro_path, "xlm_macro"), yara_block, self.results["static"]["office"][
                        "XLMMacroDeobfuscator"
                    ]["info"]

    def signature_matched(self, signame: str) -> bool:
        # Check if signature has matched (useful for ordered signatures)
        matched_signatures = [sig["name"] for sig in self.results.get("signatures", [])]
        return signame in matched_signatures

    def get_signature_data(self, signame: str) -> List[Dict[str, str]]:
        # Retrieve data from matched signature (useful for ordered signatures)
        if self.signature_matched(signame):
            signature = next((match for match in self.results.get("signatures", []) if match.get("name") == signame), None)

            if signature:
                return signature.get("data", []) + signature.get("new_data", [])
        return []

    def add_statistic(self, name, field, value):
        if name not in self.results["statistics"]["signatures"]:
            self.results["statistics"]["signatures"][name] = {}

        self.results["statistics"]["signatures"][name][field] = value

    def get_pids(self):
        pids = []
        logs = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.results["info"]["id"]), "logs")
        processes = self.results.get("behavior", {}).get("processtree", [])
        if processes:
            for pid in processes:
                pids.append(int(pid.get("pid", "")))
                pids += [int(cpid["pid"]) for cpid in pid.get("children", []) if "pid" in cpid]
        # in case if bsons too big
        if path_exists(logs):
            pids += [int(pidb.replace(".bson", "")) for pidb in os.listdir(logs) if ".bson" in pidb]

        #  in case if injection not follows
        if self.results.get("procmemory") is not None:
            pids += [int(block["pid"]) for block in self.results["procmemory"]]
        if self.results.get("procdump") is not None:
            pids += [int(block["pid"]) for block in self.results["procdump"]]

        log.debug(list(set(pids)))
        return list(set(pids))

    def advanced_url_parse(self, url):
        if HAVE_TLDEXTRACT:
            EXTRA_SUFFIXES = ("bit",)
            parsed = False
            try:
                parsed = TLDExtract(extra_suffixes=EXTRA_SUFFIXES, suffix_list_urls=None)(url)
            except Exception as e:
                log.error(e)
            return parsed
        else:
            log.info("missed tldextract dependency")

    def _get_ip_by_host(self, hostname):
        return next(
            (
                [data.get("ip", "")]
                for data in self.results.get("network", {}).get("hosts", [])
                if data.get("hostname", "") == hostname
            ),
            [],
        )

    def _get_ip_by_host_dns(self, hostname):

        ips = []

        try:
            answers = myresolver.query(hostname, "A")
            for rdata in answers:
                n = dns.reversename.from_address(rdata.address)
                try:
                    answers_inv = myresolver.query(n, "PTR")
                    ips.extend(rdata.address for _ in answers_inv)
                except dns.resolver.NoAnswer:
                    ips.append(rdata.address)
                except dns.resolver.NXDOMAIN:
                    ips.append(rdata.address)
        except dns.name.NeedAbsoluteNameOrOrigin:
            print(
                "An attempt was made to convert a non-absolute name to wire when there was also a non-absolute (or missing) origin"
            )
        except dns.resolver.NoAnswer:
            print("IPs: Impossible to get response")
        except Exception as e:
            log.info(str(e))

        return ips

    def _is_ip(self, ip):
        # is this string an ip?
        try:
            socket.inet_aton(ip)
            return True
        except Exception:
            return False

    def _check_valid_url(self, url, all_checks=False):
        """Checks if url is correct
        @param url: string
        @return: url or None
        """

        try:
            if url_validator(url):
                return url
        except Exception as e:
            print(e)

        if all_checks:
            last = url.rfind("://")
            if url[:last] in ("http", "https"):
                url = url[last + 3 :]

        try:
            if url_validator(f"http://{url}"):
                return f"http://{url}"
        except Exception as e:
            print(e)

    def _check_value(self, pattern, subject, regex=False, all=False, ignorecase=True):
        """Checks a pattern against a given subject.
        @param pattern: string or expression to check for.
        @param subject: target of the check.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @param ignorecase: in non-regex instances, should we ignore case for matches?
                            defaults to true
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        if regex:
            if all:
                retset = set()
            exp = re.compile(pattern, re.IGNORECASE)
            if isinstance(subject, list):
                for item in subject:
                    if exp.match(item):
                        if all:
                            retset.add(item)
                        else:
                            return item
            elif exp.match(subject):
                if all:
                    retset.add(subject)
                else:
                    return subject
            if all and len(retset) > 0:
                return retset
        elif ignorecase:
            lowerpattern = pattern.lower()
            if isinstance(subject, list):
                for item in subject:
                    if item.lower() == lowerpattern:
                        return item
            elif subject.lower() == lowerpattern:
                return subject
        elif isinstance(subject, list):
            for item in subject:
                if item == pattern:
                    return item
        elif subject == pattern:
            return subject

        return None

    def check_process_name(self, pattern, all=False):
        if "behavior" in self.results and "processes" in self.results["behavior"]:
            for process in self.results["behavior"]["processes"]:
                if re.findall(pattern, process["process_name"], re.I):
                    return process if all else True
        return False

    def check_file(self, pattern, regex=False, all=False):
        """Checks for a file being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["files"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_read_file(self, pattern, regex=False, all=False):
        """Checks for a file being read from.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["read_files"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_write_file(self, pattern, regex=False, all=False):
        """Checks for a file being written to.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["write_files"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_delete_file(self, pattern, regex=False, all=False):
        """Checks for a file being deleted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["delete_files"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_key(self, pattern, regex=False, all=False):
        """Checks for a registry key being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["keys"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_read_key(self, pattern, regex=False, all=False):
        """Checks for a registry key/value being read
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["read_keys"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_write_key(self, pattern, regex=False, all=False):
        """Checks for a registry key/value being modified
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["write_keys"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_delete_key(self, pattern, regex=False, all=False):
        """Checks for a registry key/value being modified or deleted
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["delete_keys"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_mutex(self, pattern, regex=False, all=False):
        """Checks for a mutex being opened.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["mutexes"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all, ignorecase=False)

    def check_started_service(self, pattern, regex=False, all=False):
        """Checks for a service being started.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["started_services"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_created_service(self, pattern, regex=False, all=False):
        """Checks for a service being created.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["created_services"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all)

    def check_executed_command(self, pattern, regex=False, all=False, ignorecase=True):
        """Checks for a command being executed.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @param ignorecase: whether the search should be performed case-insensitive
                      or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        subject = self.results["behavior"]["summary"]["executed_commands"]
        return self._check_value(pattern=pattern, subject=subject, regex=regex, all=all, ignorecase=ignorecase)

    def check_api(self, pattern, process=None, regex=False, all=False):
        """Checks for an API being called.
        @param pattern: string or expression to check for.
        @param process: optional filter for a specific process name.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        # Loop through processes.
        if all:
            retset = set()
        for item in self.results["behavior"]["processes"]:
            # Check if there's a process name filter.
            if process and item["process_name"] != process:
                continue

            # Loop through API calls.
            for call in item["calls"]:
                # Check if the name matches.
                ret = self._check_value(pattern=pattern, subject=call["api"], regex=regex, all=all, ignorecase=False)
                if ret:
                    if all:
                        retset.update(ret)
                    else:
                        return call["api"]

        return retset if all and len(retset) > 0 else None

    def check_argument_call(self, call, pattern, name=None, api=None, category=None, regex=False, all=False, ignorecase=False):
        """Checks for a specific argument of an invoked API.
        @param call: API call information.
        @param pattern: string or expression to check for.
        @param name: optional filter for the argument name.
        @param api: optional filter for the API function name.
        @param category: optional filter for a category name.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @param ignorecase: boolean representing whether the search is
                    case-insensitive or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        if all:
            retset = set()

        # Check if there's an API name filter.
        if api and call["api"] != api:
            return False

        # Check if there's a category filter.
        if category and call["category"] != category:
            return False

        # Loop through arguments.
        for argument in call["arguments"]:
            # Check if there's an argument name filter.
            if name and argument["name"] != name:
                continue

            # Check if the argument value matches.
            ret = self._check_value(pattern=pattern, subject=argument["value"], regex=regex, all=all, ignorecase=ignorecase)
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return argument["value"]

        if all and len(retset) > 0:
            return retset

        return False

    def check_argument(self, pattern, name=None, api=None, category=None, process=None, regex=False, all=False, ignorecase=False):
        """Checks for a specific argument of an invoked API.
        @param pattern: string or expression to check for.
        @param name: optional filter for the argument name.
        @param api: optional filter for the API function name.
        @param category: optional filter for a category name.
        @param process: optional filter for a specific process name.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @param ignorecase: boolean representing whether the search is
                    case-insensitive or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """
        if all:
            retset = set()

        # Loop through processes.
        for item in self.results["behavior"]["processes"]:
            # Check if there's a process name filter.
            if process and item["process_name"] != process:
                continue

            # Loop through API calls.
            for call in item["calls"]:
                r = self.check_argument_call(call, pattern, name, api, category, regex, all, ignorecase)
                if r:
                    if all:
                        retset.update(r)
                    else:
                        return r

        if all and len(retset) > 0:
            return retset

        return None

    def check_ip(self, pattern, regex=False, all=False):
        """Checks for an IP address being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """

        if all:
            retset = set()

        if "network" not in self.results:
            return None

        hosts = self.results["network"].get("hosts")
        if not hosts:
            return None

        for item in hosts:
            ret = self._check_value(pattern=pattern, subject=item["ip"], regex=regex, all=all, ignorecase=False)
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return item["ip"]

        if all and len(retset) > 0:
            return retset

        return None

    def check_domain(self, pattern, regex=False, all=False):
        """Checks for a domain being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """

        if all:
            retset = set()

        if "network" not in self.results:
            return None

        domains = self.results["network"].get("domains")
        if not domains:
            return None

        for item in domains:
            ret = self._check_value(pattern=pattern, subject=item["domain"], regex=regex, all=all)
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return item["domain"]

        if all and len(retset) > 0:
            return retset

        return None

    def check_url(self, pattern, regex=False, all=False):
        """Checks for a URL being contacted.
        @param pattern: string or expression to check for.
        @param regex: boolean representing if the pattern is a regular
                      expression or not and therefore should be compiled.
        @param all: boolean representing if all results should be returned
                      in a set or not
        @return: depending on the value of param 'all', either a set of
                      matched items or the first matched item
        """

        if all:
            retset = set()

        if "network" not in self.results:
            return None

        httpitems = self.results["network"].get("http")
        if not httpitems:
            return None
        for item in httpitems:
            ret = self._check_value(pattern=pattern, subject=item["uri"], regex=regex, all=all, ignorecase=False)
            if ret:
                if all:
                    retset.update(ret)
                else:
                    return item["uri"]

        if all and len(retset) > 0:
            return retset

        return None

    def get_initial_process(self):
        """Obtains the initial process information
        @return: dict containing initial process information or None
        """

        if (
            "behavior" not in self.results
            or "processes" not in self.results["behavior"]
            or not len(self.results["behavior"]["processes"])
        ):
            return None

        return self.results["behavior"]["processes"][0]

    def get_environ_entry(self, proc, env_name):
        """Obtains environment entry from process
        @param proc: Process to inspect
        @param env_name: Name of environment entry
        @return: value of environment entry or None
        """
        if not proc or env_name not in proc.get("environ", {}):
            return None

        return proc["environ"][env_name]

    def get_argument(self, call, name):
        """Retrieves the value of a specific argument from an API call.
        @param call: API call object.
        @param name: name of the argument to retrieve.
        @return: value of the required argument.
        """
        # Check if the call passed to it was cached already.
        # If not, we can start caching it and store a copy converted to a dict.
        if call is not self._current_call_cache:
            self._current_call_cache = call
            self._current_call_dict = {argument["name"]: argument["value"] for argument in call["arguments"]}

        # Return the required argument.
        if name in self._current_call_dict:
            return self._current_call_dict[name]

        return None

    def get_name_from_pid(self, pid):
        """Retrieve a process name from a supplied pid
        @param pid: a Process PID observed in the analysis
        @return: basestring name of the process or None
        """
        if pid:
            if isinstance(pid, str) and pid.isdigit():
                pid = int(pid)
            if self.results.get("behavior", {}).get("processes", []):
                for proc in self.results["behavior"]["processes"]:
                    if proc["process_id"] == pid:
                        return proc["process_name"]

        return None

    def get_raw_argument(self, call, name):
        """Retrieves the raw value of a specific argument from an API call.
        @param call: API call object.
        @param name: name of the argument to retrieve.
        @return: value of the requried argument.
        """
        # Check if the call passed to it was cached already.
        # If not, we can start caching it and store a copy converted to a dict.
        if call is not self._current_call_raw_cache:
            self._current_call_raw_cache = call
            self._current_call_raw_dict = {
                argument["name"]: argument["raw_value"] for argument in call["arguments"] if "raw_value" in argument
            }

        # Return the required argument.
        if name in self._current_call_raw_dict:
            return self._current_call_raw_dict[name]

        return None

    def check_suricata_alerts(self, pattern, blacklist=None):
        """Check for pattern in Suricata alert signature
        @param pattern: string or expression to check for.
        @return: True/False
        """
        if blacklist is None:
            blacklist = []
        res = False
        if isinstance(self.results.get("suricata", {}), dict):
            for alert in self.results.get("suricata", {}).get("alerts", []):
                sid = alert.get("sid", 0)
                if (sid not in self.banned_suricata_sids and sid not in blacklist) and re.findall(
                    pattern, alert.get("signature", ""), re.I
                ):
                    res = True
                    break
        return res

    def mark_call(self, *args, **kwargs):
        """Mark the current call as explanation as to why this signature matched."""

        mark = {
            "type": "call",
            "pid": self.pid,
            "cid": self.cid,
        }

        if args or kwargs:
            log.warning("You have provided extra arguments to the mark_call() method which does not support doing so.")

        self.data.append(mark)

    def add_match(self, process, type, match):
        """Adds a match to the signature data.
        @param process: The process triggering the match.
        @param type: The type of matching data (ex: 'api', 'mutex', 'file', etc.)
        @param match: Value or array of values triggering the match.
        """
        signs = []
        if isinstance(match, list):
            signs.extend({"type": type, "value": item} for item in match)
        else:
            signs.append({"type": type, "value": match})

        process_summary = None
        if process:
            process_summary = {"process_name": process["process_name"], "process_id": process["process_id"]}

        self.new_data.append({"process": process_summary, "signs": signs})

    def has_matches(self) -> bool:
        """Returns true if there is matches (data is not empty)
        @return: boolean indicating if there is any match registered
        """
        return len(self.new_data) > 0 or len(self.data) > 0

    def on_call(self, call, process):
        """Notify signature about API call. Return value determines
        if this signature is done or could still match.
        @param call: logged API call.
        @param process: process doing API call.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def on_complete(self):
        """Evented signature is notified when all API calls are done.
        @return: Match state.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def run(self):
        """Start signature processing.
        @param results: analysis results.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def as_result(self):
        """Properties as a dict (for results).
        @return: result dictionary.
        """
        return dict(
            name=self.name,
            description=self.description,
            severity=self.severity,
            weight=self.weight,
            confidence=self.confidence,
            references=self.references,
            data=self.data,
            new_data=self.new_data,
            alert=self.alert,
            families=self.families,
        )


class Report:
    """Base abstract class for reporting module."""

    order = 1

    def __init__(self):
        self.analysis_path = ""
        self.reports_path = ""
        self.task = None
        self.options = None

        if not hasattr(Report, "mitre") and HAVE_MITRE:
            # initialize only once
            Report.mitre = mitre

    def set_path(self, analysis_path):
        """Set analysis folder path.
        @param analysis_path: analysis folder path.
        """
        self.analysis_path = analysis_path
        self.conf_path = os.path.join(self.analysis_path, "analysis.conf")
        self.file_path = os.path.realpath(os.path.join(self.analysis_path, "binary"))
        self.dropped_path = os.path.join(self.analysis_path, "files")
        self.procdump_path = os.path.join(self.analysis_path, "procdump")
        self.CAPE_path = os.path.join(self.analysis_path, "CAPE")
        self.reports_path = os.path.join(self.analysis_path, "reports")
        self.shots_path = os.path.join(self.analysis_path, "shots")
        self.pcap_path = os.path.join(self.analysis_path, "dump.pcap")
        self.pmemory_path = os.path.join(self.analysis_path, "memory")
        # self.memory_path = os.path.join(self.analysis_path, "memory.dmp")
        self.memory_path = get_memdump_path(analysis_path.rsplit("/", 1)[-1])
        self.files_metadata = os.path.join(self.analysis_path, "files.json")
        self.self_extracted = os.path.join(self.analysis_path, "selfextracted")

        try:
            create_folder(folder=self.reports_path)
        except CuckooOperationalError as e:
            CuckooReportError(e)

    def set_options(self, options):
        """Set report options.
        @param options: report options dict.
        """
        self.options = options

    def set_task(self, task):
        """Add task information.
        @param task: task dictionary.
        """
        self.task = task

    def run(self):
        """Start report processing.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError


class Feed:
    """Base abstract class for feeds."""

    name = ""

    def __init__(self):
        self.data = ""
        self.downloaddata = ""
        self.downloadurl = ""
        self.feedname = ""
        self.feedpath = ""
        # default to once per day
        self.frequency = 24
        self.updatefeed = False

    def update(self) -> bool:
        """Determine if the feed needs to be updated based on the configured
        frequency and update if it we have passed that time threshold.
        """
        self.feedpath = os.path.join(CUCKOO_ROOT, "data", "feeds", f"{self.feedname}.feed")
        freq = self.frequency * 3600
        # Check if feed file exists
        mtime = 0
        if os.path.isfile(self.feedpath):
            mtime = os.path.getmtime(self.feedpath)
            # Check if feed file is older than configured update frequency
            self.updatefeed = time.time() - mtime > freq
        else:
            self.updatefeed = True

        if self.updatefeed:
            headers = {}
            if mtime:
                timestr = datetime.datetime.utcfromtimestamp(mtime).strftime("%a, %d %b %Y %H:%M:%S GMT")
                headers["If-Modified-Since"] = timestr
            try:
                req = requests.get(self.downloadurl, headers=headers, verify=True)
            except requests.exceptions.RequestException as e:
                log.warn("Error downloading feed for %s: %s", self.feedname, e)
                return False
            if req.status_code == 200:
                self.downloaddata = req.content
                return True

        return False

    def get_feedpath(self) -> str:
        return self.feedpath

    def modify(self):
        """Modify data before saving it to the feed file.
        @raise NotImplementedError: this method is abstract.
        """
        raise NotImplementedError

    def run(self, modified: bool = False):
        if self.updatefeed:
            lock = threading.Lock()
            with lock:
                if modified and self.data:
                    _ = Path(self.feedpath).write_text(self.data)
                elif self.downloaddata:
                    _ = Path(self.feedpath).write_text(self.downloaddata)


class ProtocolHandler:
    """Abstract class for protocol handlers coming out of the analysis."""

    def __init__(self, task_id, ctx, version=None):
        self.task_id = task_id
        self.handler = ctx
        self.fd = None
        self.version = version

    def __enter__(self):
        self.init()

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self.fd:
            self.fd.close()
            self.fd = None

    def handle(self):
        raise NotImplementedError
