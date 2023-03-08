# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
import os
import queue
import shutil
import signal
import threading
import time
from collections import defaultdict

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import (
    CuckooCriticalError,
    CuckooGuestCriticalTimeout,
    CuckooGuestError,
    CuckooMachineError,
    CuckooNetworkError,
    CuckooOperationalError,
)
from lib.cuckoo.common.integrations.parse_pe import PortableExecutable
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_mkdir
from lib.cuckoo.common.utils import convert_to_printable, create_folder, free_space_monitor, get_memdump_path, load_categories
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_FAILED_ANALYSIS, TASK_PENDING, Database, Task
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.log import task_log_stop
from lib.cuckoo.core.plugins import RunAuxiliary, list_plugins
from lib.cuckoo.core.resultserver import ResultServer
from lib.cuckoo.core.rooter import _load_socks5_operational, rooter, vpns

# os.listdir('/sys/class/net/')
HAVE_NETWORKIFACES = False
try:
    import psutil

    network_interfaces = list(psutil.net_if_addrs().keys())
    HAVE_NETWORKIFACES = True
except ImportError:
    print("Missde dependency: pip3 install psutil")

log = logging.getLogger(__name__)

machinery = None
machine_lock = None
latest_symlink_lock = threading.Lock()
routing = Config("routing")
enable_trim = int(Config("web").general.enable_trim)

active_analysis_count = 0


class CuckooDeadMachine(Exception):
    """Exception thrown when a machine turns dead.

    When this exception has been thrown, the analysis task will start again,
    and will try to use another machine, when available.
    """

    pass


class AnalysisManager(threading.Thread):
    """Analysis Manager.

    This class handles the full analysis process for a given task. It takes
    care of selecting the analysis machine, preparing the configuration and
    interacting with the guest agent and analyzer components to launch and
    complete the analysis and store, process and report its results.
    """

    def __init__(self, task, error_queue):
        """@param task: task object containing the details for the analysis."""
        threading.Thread.__init__(self)

        self.task = task
        self.errors = error_queue
        self.cfg = Config()
        self.aux_cfg = Config("auxiliary")
        self.storage = ""
        self.binary = ""
        self.machine = None
        self.db = Database()
        self.interface = None
        self.rt_table = None
        self.route = None
        self.rooter_response = ""
        self.reject_segments = None
        self.reject_hostports = None

    def init_storage(self):
        """Initialize analysis storage folder."""
        self.storage = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id))

        # If the analysis storage folder already exists, we need to abort the
        # analysis or previous results will be overwritten and lost.
        if path_exists(self.storage):
            log.error("Task #%s: Analysis results folder already exists at path '%s', analysis aborted", self.task.id, self.storage)
            return False

        # If we're not able to create the analysis storage folder, we have to
        # abort the analysis.
        try:
            create_folder(folder=self.storage)
        except CuckooOperationalError:
            log.error("Task #%s: Unable to create analysis folder %s", self.task.id, self.storage)
            return False

        return True

    def check_file(self, sha256):
        """Checks the integrity of the file to be analyzed."""
        sample = self.db.view_sample(self.task.sample_id)

        if sample and sha256 != sample.sha256:
            log.error(
                "Task #%s: Target file has been modified after submission: '%s'",
                self.task.id,
                convert_to_printable(self.task.target),
            )
            return False

        return True

    def store_file(self, sha256):
        """Store a copy of the file being analyzed."""
        if not path_exists(self.task.target):
            log.error(
                "Task #%s: The file to analyze does not exist at path '%s', analysis aborted",
                self.task.id,
                convert_to_printable(self.task.target),
            )
            return False

        self.binary = os.path.join(CUCKOO_ROOT, "storage", "binaries", str(self.task.id), sha256)
        copy_path = os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256)

        if path_exists(self.binary):
            log.info("Task #%s: File already exists at '%s'", self.task.id, self.binary)
        else:
            # TODO: do we really need to abort the analysis in case we are not able to store a copy of the file?
            try:
                create_folder(folder=os.path.join(CUCKOO_ROOT, "storage", "binaries", str(self.task.id)))
                shutil.copy(self.task.target, self.binary)
            except (IOError, shutil.Error):
                log.error(
                    "Task #%s: Unable to store file from '%s' to '%s', analysis aborted",
                    self.task.id,
                    self.task.target,
                    self.binary,
                )
                return False

        if path_exists(copy_path):
            log.info("Task #%s: File already exists at '%s'", self.task.id, copy_path)
        else:
            # TODO: do we really need to abort the analysis in case we are not able to store a copy of the file?
            try:
                shutil.copy(self.task.target, copy_path)
            except (IOError, shutil.Error):
                log.error(
                    "Task #%s: Unable to store file from '%s' to '%s', analysis aborted", self.task.id, self.task.target, copy_path
                )
                return False

        try:
            new_binary_path = os.path.join(self.storage, "binary")

            if hasattr(os, "symlink"):
                os.symlink(self.binary, new_binary_path)
            else:
                shutil.copy(self.binary, new_binary_path)
        except (AttributeError, OSError) as e:
            log.error("Task #%s: Unable to create symlink/copy from '%s' to '%s': %s", self.task.id, self.binary, self.storage, e)

        return True

    def acquire_machine(self):
        """Acquire an analysis machine from the pool of available ones."""
        machine = None

        # Start a loop to acquire a machine to run the analysis on.
        while True:
            machine_lock.acquire()

            # If the user specified a specific machine ID, a platform to be
            # used or machine tags acquire the machine accordingly.
            task_archs, task_tags = self.db._task_arch_tags_helper(self.task)
            os_version = self.db._package_vm_requires_check(self.task.package)

            # In some cases it's possible that we enter this loop without having any available machines. We should make sure this is not
            # such case, or the analysis task will fail completely.
            if not machinery.availables(
                label=self.task.machine, platform=self.task.platform, tags=task_tags, arch=task_archs, os_version=os_version
            ):
                machine_lock.release()
                log.debug(
                    "Task #%s: no machine available yet for machine '%s', platform '%s' or tags '%s'.",
                    self.task.id,
                    self.task.machine,
                    self.task.platform,
                    self.task.tags,
                )
                time.sleep(1)
                continue

            machine = machinery.acquire(
                machine_id=self.task.machine, platform=self.task.platform, tags=task_tags, arch=task_archs, os_version=os_version
            )

            # If no machine is available at this moment, wait for one second and try again.
            if not machine:
                machine_lock.release()
                log.debug(
                    "Task #%s: no machine available yet for machine '%s', platform '%s' or tags '%s'.",
                    self.task.id,
                    self.task.machine,
                    self.task.platform,
                    self.task.tags,
                )
                time.sleep(1)
            else:
                log.info(
                    "Task #%s: acquired machine %s (label=%s, arch=%s, platform=%s)",
                    self.task.id,
                    machine.name,
                    machine.label,
                    machine.arch,
                    machine.platform,
                )
                break

        self.machine = machine

    def build_options(self):
        """Generate analysis options.
        @return: options dict.
        """
        options = {
            "id": self.task.id,
            "ip": self.machine.resultserver_ip,
            "port": self.machine.resultserver_port,
            "category": self.task.category,
            "target": self.task.target,
            "package": self.task.package,
            "options": self.task.options,
            "enforce_timeout": self.task.enforce_timeout,
            "clock": self.task.clock,
            "terminate_processes": self.cfg.cuckoo.terminate_processes,
            "upload_max_size": self.cfg.resultserver.upload_max_size,
            "do_upload_max_size": int(self.cfg.resultserver.do_upload_max_size),
            "enable_trim": enable_trim,
            "timeout": self.task.timeout or self.cfg.timeouts.default,
        }

        if self.task.category == "file":
            file_obj = File(self.task.target)
            options["file_name"] = file_obj.get_name()
            options["file_type"] = file_obj.get_type()
            # if it's a PE file, collect export information to use in more smartly determining the right package to use
            options["exports"] = PortableExecutable(self.task.target).get_dll_exports()
            del file_obj

        # options from auxiliary.conf
        for plugin in self.aux_cfg.auxiliary_modules.keys():
            options[plugin] = self.aux_cfg.auxiliary_modules[plugin]

        return options

    def category_checks(self):
        if self.task.category in ("file", "pcap", "static"):
            sha256 = File(self.task.target).get_sha256()
            # Check whether the file has been changed for some unknown reason.
            # And fail this analysis if it has been modified.
            if not self.check_file(sha256):
                log.debug("check file")
                return False

            # Store a copy of the original file.
            if not self.store_file(sha256):
                log.debug("store file")
                return False

        if self.task.category in ("pcap", "static"):
            if self.task.category == "pcap":
                if hasattr(os, "symlink"):
                    os.symlink(self.binary, os.path.join(self.storage, "dump.pcap"))
                else:
                    shutil.copy(self.binary, os.path.join(self.storage, "dump.pcap"))
            # create the logs/files directories as
            # normally the resultserver would do it
            dirnames = ["logs", "files", "aux"]
            for dirname in dirnames:
                try:
                    path_mkdir(os.path.join(self.storage, dirname))
                except Exception:
                    log.debug("Failed to create folder %s", dirname)
            return True

    def launch_analysis(self):
        """Start analysis."""
        succeeded = False
        dead_machine = False
        self.socks5s = _load_socks5_operational()

        # Initialize the analysis folders.
        if not self.init_storage():
            log.debug("Failed to initialize the analysis folder")
            return False

        category_early_escape = self.category_checks()
        if isinstance(category_early_escape, bool):
            return category_early_escape

        log.info(
            "Task #%s: Starting analysis of %s '%s'",
            self.task.id,
            self.task.category.upper(),
            convert_to_printable(self.task.target),
        )

        # Acquire analysis machine.
        try:
            self.acquire_machine()
            self.db.set_task_vm(self.task.id, self.machine.label, self.machine.id)
        # At this point we can tell the ResultServer about it.
        except CuckooOperationalError as e:
            machine_lock.release()
            log.error("Task #%s: Cannot acquire machine: %s", self.task.id, e, exc_info=True)
            return False

        # Generate the analysis configuration file.
        options = self.build_options()

        try:
            ResultServer().add_task(self.task, self.machine)
        except Exception as e:
            machinery.release(self.machine.label)
            log.exception(e, exc_info=True)
            self.errors.put(e)

        aux = RunAuxiliary(task=self.task, machine=self.machine)

        try:
            unlocked = False

            # Mark the selected analysis machine in the database as started.
            guest_log = self.db.guest_start(self.task.id, self.machine.name, self.machine.label, machinery.__class__.__name__)
            # Start the machine.
            machinery.start(self.machine.label)

            # Enable network routing.
            self.route_network()

            # By the time start returns it will have fully started the Virtual
            # Machine. We can now safely release the machine lock.
            machine_lock.release()
            unlocked = True

            aux.start()

            # Initialize the guest manager.
            guest = GuestManager(self.machine.name, self.machine.ip, self.machine.platform, self.task.id, self)

            options["clock"] = self.db.update_clock(self.task.id)
            self.db.guest_set_status(self.task.id, "starting")
            # Start the analysis.
            guest.start_analysis(options)
            if self.db.guest_get_status(self.task.id) == "starting":
                self.db.guest_set_status(self.task.id, "running")
                guest.wait_for_completion()

            self.db.guest_set_status(self.task.id, "stopping")
            succeeded = True
        except (CuckooMachineError, CuckooNetworkError) as e:
            if not unlocked:
                machine_lock.release()
            log.error(str(e), extra={"task_id": self.task.id}, exc_info=True)
            dead_machine = True
        except CuckooGuestCriticalTimeout as e:
            if not unlocked:
                machine_lock.release()
            log.error(str(e), extra={"task_id": self.task.id}, exc_info=True)
            dead_machine = True
        except CuckooGuestError as e:
            if not unlocked:
                machine_lock.release()
            log.error(str(e), extra={"task_id": self.task.id}, exc_info=True)
        finally:
            # Stop Auxiliary modules.
            aux.stop()

            # Take a memory dump of the machine before shutting it off.
            if self.cfg.cuckoo.memory_dump or self.task.memory:
                try:
                    dump_path = get_memdump_path(self.task.id)
                    need_space, space_available = free_space_monitor(os.path.dirname(dump_path), return_value=True)
                    if need_space:
                        log.error("Not enough free disk space! Could not dump ram (Only %d MB!)", space_available)
                    else:
                        machinery.dump_memory(self.machine.label, dump_path)
                except NotImplementedError:
                    log.error("The memory dump functionality is not available for the current machine manager")

                except CuckooMachineError as e:
                    log.error(e, exc_info=True)

            try:
                # Stop the analysis machine.
                machinery.stop(self.machine.label)

            except CuckooMachineError as e:
                log.warning("Task #%s: Unable to stop machine %s: %s", self.task.id, self.machine.label, e)

            # Mark the machine in the database as stopped. Unless this machine
            # has been marked as dead, we just keep it as "started" in the
            # database so it'll not be used later on in this session.
            self.db.guest_stop(guest_log)

            # After all this, we can make the ResultServer forget about the
            # internal state for this analysis task.
            ResultServer().del_task(self.task, self.machine)

            # Drop the network routing rules if any.
            self.unroute_network()

            if dead_machine:
                # Remove the guest from the database, so that we can assign a
                # new guest when the task is being analyzed with another
                # machine.
                self.db.guest_remove(guest_log)
                machinery.delete_machine(self.machine.name)

                # Remove the analysis directory that has been created so
                # far, as launch_analysis() is going to be doing that again.
                shutil.rmtree(self.storage)

                # This machine has turned dead, so we throw an exception here
                # which informs the AnalysisManager that it should analyze
                # this task again with another available machine.
                raise CuckooDeadMachine()

            try:
                # Release the analysis machine. But only if the machine has
                # not turned dead yet.
                machinery.release(self.machine.label)

            except CuckooMachineError as e:
                log.error(
                    "Task #%s: Unable to release machine %s, reason %s. You might need to restore it manually",
                    self.task.id,
                    self.machine.label,
                    e,
                )

        return succeeded

    def run(self):
        """Run manager thread."""
        global active_analysis_count
        active_analysis_count += 1
        try:
            while True:
                try:
                    success = self.launch_analysis()
                except CuckooDeadMachine as e:
                    log.exception(e)
                    continue

                break

            self.db.set_status(self.task.id, TASK_COMPLETED)

            # If the task is still available in the database, update our task
            # variable with what's in the database, as otherwise we're missing
            # out on the status and completed_on change. This would then in
            # turn thrown an exception in the analysisinfo processing module.
            self.task = self.db.view_task(self.task.id) or self.task

            log.debug("Task #%s: Released database task with status %s", self.task.id, success)

            # We make a symbolic link ("latest") which links to the latest
            # analysis - this is useful for debugging purposes. This is only
            # supported under systems that support symbolic links.
            if hasattr(os, "symlink"):
                latest = os.path.join(CUCKOO_ROOT, "storage", "analyses", "latest")

                # First we have to remove the existing symbolic link, then we
                # have to create the new one.
                # Deal with race conditions using a lock.
                latest_symlink_lock.acquire()
                try:
                    # As per documentation, lexists() returns True for dead symbolic links.
                    if os.path.lexists(latest):
                        path_delete(latest)

                    os.symlink(self.storage, latest)
                except OSError as e:
                    log.warning("Task #%s: Error pointing latest analysis symlink: %s", self.task.id, e)
                finally:
                    latest_symlink_lock.release()

            log.info("Task #%s: analysis procedure completed", self.task.id)
        except Exception as e:
            log.exception("Task #%s: Failure in AnalysisManager.run: %s", self.task.id, e)
        finally:
            self.db.set_status(self.task.id, TASK_COMPLETED)
            task_log_stop(self.task.id)
            active_analysis_count -= 1

    def _rooter_response_check(self):
        if self.rooter_response and self.rooter_response["exception"] is not None:
            raise CuckooCriticalError(f"Error execution rooter command: {self.rooter_response['exception']}")

    def route_network(self):
        """Enable network routing if desired."""
        # Determine the desired routing strategy (none, internet, VPN).
        self.route = routing.routing.route

        if self.task.route:
            self.route = self.task.route

        if self.route in ("none", "None", "drop", "false"):
            self.interface = None
            self.rt_table = None
        elif self.route == "inetsim":
            self.interface = routing.inetsim.interface
        elif self.route == "tor":
            self.interface = routing.tor.interface
        elif self.route == "internet" and routing.routing.internet != "none":
            self.interface = routing.routing.internet
            self.rt_table = routing.routing.rt_table
            if routing.routing.reject_segments != "none":
                self.reject_segments = routing.routing.reject_segments
            if routing.routing.reject_hostports != "none":
                self.reject_hostports = str(routing.routing.reject_hostports)
        elif self.route in vpns:
            self.interface = vpns[self.route].interface
            self.rt_table = vpns[self.route].rt_table
        elif self.route in self.socks5s:
            self.interface = ""
        else:
            log.warning("Unknown network routing destination specified, ignoring routing for this analysis: %s", self.route)
            self.interface = None
            self.rt_table = None

        # Check if the network interface is still available. If a VPN dies for
        # some reason, its tunX interface will no longer be available.
        if self.interface and not rooter("nic_available", self.interface):
            log.error(
                "The network interface '%s' configured for this analysis is "
                "not available at the moment, switching to route=none mode",
                self.interface,
            )
            self.route = "none"
            self.interface = None
            self.rt_table = None

        if self.route == "inetsim":
            self.rooter_response = rooter(
                "inetsim_enable",
                self.machine.ip,
                str(routing.inetsim.server),
                str(routing.inetsim.dnsport),
                str(self.cfg.resultserver.port),
                str(routing.inetsim.ports),
            )

        elif self.route == "tor":
            self.rooter_response = rooter(
                "socks5_enable",
                self.machine.ip,
                str(self.cfg.resultserver.port),
                str(routing.tor.dnsport),
                str(routing.tor.proxyport),
            )

        elif self.route in self.socks5s:
            self.rooter_response = rooter(
                "socks5_enable",
                self.machine.ip,
                str(self.cfg.resultserver.port),
                str(self.socks5s[self.route]["dnsport"]),
                str(self.socks5s[self.route]["port"]),
            )

        elif self.route in ("none", "None", "drop"):
            self.rooter_response = rooter("drop_enable", self.machine.ip, str(self.cfg.resultserver.port))

        self._rooter_response_check()

        # check if the interface is up
        if HAVE_NETWORKIFACES and routing.routing.verify_interface and self.interface and self.interface not in network_interfaces:
            raise CuckooNetworkError(f"Network interface {self.interface} not found")

        if self.interface:
            self.rooter_response = rooter("forward_enable", self.machine.interface, self.interface, self.machine.ip)
            self._rooter_response_check()
            if self.reject_segments:
                self.rooter_response = rooter(
                    "forward_reject_enable", self.machine.interface, self.interface, self.machine.ip, self.reject_segments
                )
                self._rooter_response_check()
            if self.reject_hostports:
                self.rooter_response = rooter(
                    "hostports_reject_enable", self.machine.interface, self.machine.ip, self.reject_hostports
                )
                self._rooter_response_check()

        log.info("Enabled route '%s'. Bear in mind that routes none and drop won't generate PCAP file", self.route)

        if self.rt_table:
            self.rooter_response = rooter("srcroute_enable", self.rt_table, self.machine.ip)
            self._rooter_response_check()

    def unroute_network(self):
        if self.interface:
            self.rooter_response = rooter("forward_disable", self.machine.interface, self.interface, self.machine.ip)
            self._rooter_response_check()
            if self.reject_segments:
                self.rooter_response = rooter(
                    "forward_reject_disable", self.machine.interface, self.interface, self.machine.ip, self.reject_segments
                )
                self._rooter_response_check()
            if self.reject_hostports:
                self.rooter_response = rooter(
                    "hostports_reject_disable", self.machine.interface, self.machine.ip, self.reject_hostports
                )
                self._rooter_response_check()
            log.info("Disabled route '%s'", self.route)

        if self.rt_table:
            self.rooter_response = rooter("srcroute_disable", self.rt_table, self.machine.ip)
            self._rooter_response_check()

        if self.route == "inetsim":
            self.rooter_response = rooter(
                "inetsim_disable",
                self.machine.ip,
                routing.inetsim.server,
                str(routing.inetsim.dnsport),
                str(self.cfg.resultserver.port),
                str(routing.inetsim.ports),
            )

        elif self.route == "tor":
            self.rooter_response = rooter(
                "socks5_disable",
                self.machine.ip,
                str(self.cfg.resultserver.port),
                str(routing.tor.dnsport),
                str(routing.tor.proxyport),
            )

        elif self.route in self.socks5s:
            self.rooter_response = rooter(
                "socks5_disable",
                self.machine.ip,
                str(self.cfg.resultserver.port),
                str(self.socks5s[self.route]["dnsport"]),
                str(self.socks5s[self.route]["port"]),
            )

        elif self.route in ("none", "None", "drop"):
            self.rooter_response = rooter("drop_disable", self.machine.ip, str(self.cfg.resultserver.port))

        self._rooter_response_check()


class Scheduler:
    """Tasks Scheduler.

    This class is responsible for the main execution loop of the tool. It
    prepares the analysis machines and keep waiting and loading for new
    analysis tasks.
    Whenever a new task is available, it launches AnalysisManager which will
    take care of running the full analysis process and operating with the
    assigned analysis machine.
    """

    def __init__(self, maxcount=None):
        self.running = True
        self.cfg = Config()
        self.db = Database()
        self.maxcount = maxcount
        self.total_analysis_count = 0
        self.analyzing_categories, self.categories_need_VM = load_categories()

    def set_stop_analyzing(self, signum, stack):
        self.running = False
        log.info("Now wait till all running tasks are completed")

    def initialize(self):
        """Initialize the machine manager."""
        global machinery, machine_lock

        machinery_name = self.cfg.cuckoo.machinery
        if not self.categories_need_VM:
            return

        max_vmstartup_count = self.cfg.cuckoo.max_vmstartup_count
        if max_vmstartup_count:
            # machine_lock = threading.Semaphore(max_vmstartup_count)
            machine_lock = threading.BoundedSemaphore(max_vmstartup_count)
        else:
            machine_lock = threading.Lock()

        log.info(
            'Using "%s" machine manager with max_analysis_count=%d, max_machines_count=%d, and max_vmstartup_count=%d',
            machinery_name,
            self.cfg.cuckoo.max_analysis_count,
            self.cfg.cuckoo.max_machines_count,
            self.cfg.cuckoo.max_vmstartup_count,
        )

        # Get registered class name. Only one machine manager is imported,
        # therefore there should be only one class in the list.
        plugin = list_plugins("machinery")[0]
        # Initialize the machine manager.
        machinery = plugin()

        # Find its configuration file.
        conf = os.path.join(CUCKOO_ROOT, "conf", f"{machinery_name}.conf")

        if not path_exists(conf):
            raise CuckooCriticalError(
                f'The configuration file for machine manager "{machinery_name}" does not exist at path: {conf}'
            )

        # Provide a dictionary with the configuration options to the
        # machine manager instance.
        machinery.set_options(Config(machinery_name))

        # Initialize the machine manager.
        try:
            machinery.initialize(machinery_name)
        except CuckooMachineError as e:
            raise CuckooCriticalError(f"Error initializing machines: {e}")

        # At this point all the available machines should have been identified
        # and added to the list. If none were found, Cuckoo needs to abort the
        # execution.
        if not len(machinery.machines()):
            raise CuckooCriticalError("No machines available")
        else:
            log.info("Loaded %d machine/s", len(machinery.machines()))

        if len(machinery.machines()) > 1 and self.db.engine.name == "sqlite":
            log.warning(
                "As you've configured Cuckoo to execute parallel "
                "analyses, we recommend you to switch to a MySQL "
                "a PostgreSQL database as SQLite might cause some "
                "issues"
            )

        # Drop all existing packet forwarding rules for each VM. Just in case
        # Cuckoo was terminated for some reason and various forwarding rules
        # have thus not been dropped yet.
        for machine in machinery.machines():
            if not machine.interface:
                log.info(
                    "Unable to determine the network interface for VM "
                    "with name %s, Cuckoo will not be able to give it "
                    "full internet access or route it through a VPN! "
                    "Please define a default network interface for the "
                    "machinery or define a network interface for each "
                    "VM",
                    machine.name,
                )
                continue

            # Drop forwarding rule to each VPN.
            for vpn in vpns.values():
                rooter("forward_disable", machine.interface, vpn.interface, machine.ip)

            # Drop forwarding rule to the internet / dirty line.
            if routing.routing.internet != "none":
                rooter("forward_disable", machine.interface, routing.routing.internet, machine.ip)

    def stop(self):
        """Stop scheduler."""
        self.running = False
        # Shutdown machine manager (used to kill machines that still alive).
        if self.categories_need_VM:
            machinery.shutdown()

    def start(self):
        """Start scheduler."""
        self.initialize()

        log.info("Waiting for analysis tasks")

        # To handle stop analyzing when we need to restart process without break tasks
        signal.signal(signal.SIGHUP, self.set_stop_analyzing)

        # Message queue with threads to transmit exceptions (used as IPC).
        errors = queue.Queue()

        # Command-line overrides the configuration file.
        if self.maxcount is None:
            self.maxcount = self.cfg.cuckoo.max_analysis_count

        # Start the logger which grabs database information
        if self.cfg.cuckoo.periodic_log:
            self._thr_periodic_log()

        # This loop runs forever.
        while self.running:
            time.sleep(1)
            # Wait until the machine lock is not locked. This is only the case
            # when all machines are fully running, rather that about to start
            # or still busy starting. This way we won't have race conditions
            # with finding out there are no available machines in the analysis
            # manager or having two analyses pick the same machine.
            if self.categories_need_VM:
                if not machine_lock.acquire(False):
                    continue
                machine_lock.release()

            # If not enough free disk space is available, then we print an
            # error message and wait another round (this check is ignored
            # when the freespace configuration variable is set to zero).
            if self.cfg.cuckoo.freespace:
                # Resolve the full base path to the analysis folder, just in
                # case somebody decides to make a symbolic link out of it.
                dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")
                need_space, space_available = free_space_monitor(dir_path, return_value=True, analysis=True)
                if need_space:
                    log.error(
                        "Not enough free disk space! (Only %d MB!). You can change limits it in cuckoo.conf -> freespace",
                        space_available,
                    )
                    continue

            # Have we limited the number of concurrently executing machines?
            if self.cfg.cuckoo.max_machines_count > 0 and self.categories_need_VM:
                # Are too many running?
                if len(machinery.running()) >= self.cfg.cuckoo.max_machines_count:
                    continue

            # If no machines are available, it's pointless to fetch for pending tasks. Loop over.
            # But if we analyze pcaps/static only it's fine
            # ToDo verify that it works with static and file/url
            if self.categories_need_VM and not machinery.availables(include_reserved=True):
                continue
            # Exits if max_analysis_count is defined in the configuration
            # file and has been reached.
            if self.maxcount and self.total_analysis_count >= self.maxcount:
                if active_analysis_count <= 0:
                    self.stop()
            else:
                if self.categories_need_VM:
                    # First things first, are there pending tasks?
                    if not self.db.count_tasks(status=TASK_PENDING):
                        continue
                    relevant_machine_is_available = False
                    # There are? Great, let's get them, ordered by priority and then oldest to newest
                    for task in self.db.list_tasks(
                        status=TASK_PENDING, order_by=(Task.priority.desc(), Task.added_on), options_not_like="node="
                    ):
                        # Can this task ever be serviced?
                        if not self.db.is_serviceable(task):
                            if self.cfg.cuckoo.fail_unserviceable:
                                log.debug("Task #%s: Failing unserviceable task", task.id)
                                self.db.set_status(task.id, TASK_FAILED_ANALYSIS)
                                continue
                            log.debug("Task #%s: Unserviceable task", task.id)
                        relevant_machine_is_available = self.db.is_relevant_machine_available(task)
                        if relevant_machine_is_available:
                            break
                    if not relevant_machine_is_available:
                        task = None
                    else:
                        task = self.db.view_task(task.id)
                else:
                    task = self.db.fetch_task(self.analyzing_categories)
                if task:
                    log.debug("Task #%s: Processing task", task.id)
                    self.total_analysis_count += 1
                    # Initialize and start the analysis manager.
                    analysis = AnalysisManager(task, errors)
                    analysis.daemon = True
                    analysis.start()

            # Deal with errors.
            try:
                raise errors.get(block=False)
            except queue.Empty:
                pass

    def _thr_periodic_log(self):
        specific_available_machine_counts = defaultdict(int)
        for machine in self.db.get_available_machines():
            for tag in machine.tags:
                if tag:
                    specific_available_machine_counts[tag.name] += 1
            if machine.platform:
                specific_available_machine_counts[machine.platform] += 1
        specific_pending_task_counts = defaultdict(int)
        for task in self.db.list_tasks(status=TASK_PENDING):
            for tag in task.tags:
                if tag:
                    specific_pending_task_counts[tag.name] += 1
            if task.platform:
                specific_pending_task_counts[task.platform] += 1
            if task.machine:
                specific_pending_task_counts[task.machine] += 1
        specific_locked_machine_counts = defaultdict(int)
        for machine in self.db.list_machines(locked=True):
            for tag in machine.tags:
                if tag:
                    specific_locked_machine_counts[tag.name] += 1
            if machine.platform:
                specific_locked_machine_counts[machine.platform] += 1

        log.debug(
            "# Pending Tasks: %d; # Specific Pending Tasks: %s; # Available Machines: %d; # Available Specific Machines: %s; # Locked Machines: %d; # Specific Locked Machines: %s; # Total Machines: %d;",
            self.db.count_tasks(status=TASK_PENDING),
            dict(specific_pending_task_counts),
            self.db.count_machines_available(),
            dict(specific_available_machine_counts),
            len(self.db.list_machines(locked=True)),
            dict(specific_locked_machine_counts),
            len(self.db.list_machines()),
        )
        threading.Timer(10, self._thr_periodic_log).start()
