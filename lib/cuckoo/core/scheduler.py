# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import
import os
import gc
import time
import shutil
import signal
import logging
import threading
import queue

try:
    import re2 as re
except ImportError:
    import re

# os.listdir('/sys/class/net/')
HAVE_NETWORKIFACES = False
try:
    import psutil
    network_interfaces = list(psutil.net_if_addrs().keys())
    HAVE_NETWORKIFACES = True
except ImportError:
    print("Missde dependency: pip3 install netifaces")

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooMachineError, CuckooGuestError
from lib.cuckoo.common.exceptions import CuckooOperationalError, CuckooNetworkError
from lib.cuckoo.common.exceptions import CuckooCriticalError
from lib.cuckoo.common.objects import File, HAVE_PEFILE, pefile
from lib.cuckoo.common.utils import create_folder, get_memdump_path, free_space_monitor
from lib.cuckoo.core.database import Database, TASK_COMPLETED
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.plugins import list_plugins, RunAuxiliary
from lib.cuckoo.core.resultserver import ResultServer
from lib.cuckoo.core.rooter import rooter, vpns, _load_socks5_operational
from lib.cuckoo.common.utils import convert_to_printable

log = logging.getLogger(__name__)

machinery = None
machine_lock = None
latest_symlink_lock = threading.Lock()
routing = Config("routing")

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

    def init_storage(self):
        """Initialize analysis storage folder."""
        self.storage = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id))

        # If the analysis storage folder already exists, we need to abort the
        # analysis or previous results will be overwritten and lost.
        if os.path.exists(self.storage):
            log.error("Task #{0}: Analysis results folder already exists at path '{1}', " "analysis aborted".format(self.task.id, self.storage))
            return False

        # If we're not able to create the analysis storage folder, we have to
        # abort the analysis.
        try:
            create_folder(folder=self.storage)
        except CuckooOperationalError:
            log.error("Task #{0}: Unable to create analysis folder {1}".format(self.task.id, self.storage))
            return False

        return True

    def check_file(self, sha256):
        """Checks the integrity of the file to be analyzed."""
        sample = self.db.view_sample(self.task.sample_id)

        if sha256 != sample.sha256:
            log.error(
                "Task #{0}: Target file has been modified after submission: "
                "'{1}'".format(self.task.id, convert_to_printable(self.task.target))
            )
            return False

        return True

    def store_file(self, sha256):
        """Store a copy of the file being analyzed."""
        if not os.path.exists(self.task.target):
            log.error(
                "Task #{0}: The file to analyze does not exist at path '{1}', "
                "analysis aborted".format(self.task.id, convert_to_printable(self.task.target))
            )
            return False

        self.binary = os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256)

        if os.path.exists(self.binary):
            log.info("Task #{0}: File already exists at '{1}'".format(self.task.id, self.binary))
        else:
            # TODO: do we really need to abort the analysis in case we are not able to store a copy of the file?
            try:
                shutil.copy(self.task.target, self.binary)
            except (IOError, shutil.Error) as e:
                log.error("Task #{0}: Unable to store file from '{1}' to '{2}', analysis aborted".format(self.task.id, self.task.target, self.binary))
                return False

        try:
            new_binary_path = os.path.join(self.storage, "binary")

            if hasattr(os, "symlink"):
                os.symlink(self.binary, new_binary_path)
            else:
                shutil.copy(self.binary, new_binary_path)
        except (AttributeError, OSError) as e:
            log.error("Task #{0}: Unable to create symlink/copy from '{1}' to '{2}': {3}".format(self.task.id, self.binary, self.storage, e))

        return True

    def acquire_machine(self):
        """Acquire an analysis machine from the pool of available ones."""
        machine = None

        # Start a loop to acquire a machine to run the analysis on.
        while True:
            machine_lock.acquire()

            # In some cases it's possible that we enter this loop without
            # having any available machines. We should make sure this is not
            # such case, or the analysis task will fail completely.
            if not machinery.availables():
                machine_lock.release()
                time.sleep(1)
                continue

            # If the user specified a specific machine ID, a platform to be
            # used or machine tags acquire the machine accordingly.
            machine = machinery.acquire(machine_id=self.task.machine, platform=self.task.platform, tags=self.task.tags)

            # If no machine is available at this moment, wait for one second and try again.
            if not machine:
                machine_lock.release()
                log.debug("Task #{0}: no machine available yet. To analyze x64 samples ensure to have set tags=x64 in hypervisor config".format(self.task.id))
                time.sleep(1)
            else:
                log.info("Task #{}: acquired machine {} (label={}, platform={})".format(self.task.id, machine.name, machine.label, machine.platform))
                break

        self.machine = machine

    def build_options(self):
        """Generate analysis options.
        @return: options dict.
        """
        options = {}

        options["id"] = self.task.id
        options["ip"] = self.machine.resultserver_ip
        options["port"] = self.machine.resultserver_port
        options["category"] = self.task.category
        options["target"] = self.task.target
        options["package"] = self.task.package
        options["options"] = self.task.options
        options["enforce_timeout"] = self.task.enforce_timeout
        options["clock"] = self.task.clock
        options["terminate_processes"] = self.cfg.cuckoo.terminate_processes
        options["upload_max_size"] = self.cfg.resultserver.upload_max_size
        options["do_upload_max_size"] = int(self.cfg.resultserver.do_upload_max_size)


        if not self.task.timeout or self.task.timeout == 0:
            options["timeout"] = self.cfg.timeouts.default
        else:
            options["timeout"] = self.task.timeout

        if self.task.category == "file":
            options["file_name"] = File(self.task.target).get_name()
            options["file_type"] = File(self.task.target).get_type()
            # if it's a PE file, collect export information to use in more smartly determining the right
            # package to use
            options["exports"] = ""
            if HAVE_PEFILE and ("PE32" in options["file_type"] or "MS-DOS executable" in options["file_type"]):
                try:
                    pe = pefile.PE(self.task.target)
                    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                        exports = []
                        for exported_symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                            try:
                                if not exported_symbol.name:
                                    continue
                                if isinstance(exported_symbol.name, bytes):
                                    exports.append(re.sub(b"[^A-Za-z0-9_?@-]", b"", exported_symbol.name).decode("utf-8"))
                                else:
                                    exports.append(re.sub("[^A-Za-z0-9_?@-]", "", exported_symbol.name))
                            except Exception as e:
                                log.error(e, exc_info=True)

                        options["exports"] = ",".join(exports)
                except Exception as e:
                    log.error("PE type not recognised")
                    log.error(e, exc_info=True)

        # options from auxiliar.conf
        for plugin in self.aux_cfg.auxiliar_modules.keys():
            options[plugin] = self.aux_cfg.auxiliar_modules[plugin]

        return options

    def category_checks(self):
        if self.task.category in ["file", "pcap", "static"]:
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
                    os.makedirs(os.path.join(self.storage, dirname))
                except:
                    pass
            return True

    def launch_analysis(self):
        """Start analysis."""
        succeeded = False
        dead_machine = False
        self.socks5s = _load_socks5_operational()

        log.info("Task #{0}: Starting analysis of {1} '{2}'".format(self.task.id, self.task.category.upper(), convert_to_printable(self.task.target)))

        # Initialize the analysis folders.
        if not self.init_storage():
            log.debug("Failed to initialize the analysis folder")
            return False

        category_early_escape = self.category_checks()
        if isinstance(category_early_escape, bool):
            return category_early_escape

        # Acquire analysis machine.
        try:
            self.acquire_machine()
            self.db.set_task_vm(self.task.id, self.machine.label, self.machine.id)
        # At this point we can tell the ResultServer about it.
        except CuckooOperationalError as e:
            machine_lock.release()
            log.error("Task #{0}: Cannot acquire machine: {1}".format(self.task.id, e), exc_info=True)
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
        except CuckooMachineError as e:
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
                    log.error("The memory dump functionality is not available for the current machine manager.")

                except CuckooMachineError as e:
                    log.error(e, exc_info=True)

            try:
                # Stop the analysis machine.
                machinery.stop(self.machine.label)

            except CuckooMachineError as e:
                log.warning("Task #{0}: Unable to stop machine {1}: {2}".format(self.task.id, self.machine.label, e))

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
                    "Task #{0}: Unable to release machine {1}, reason "
                    "{2}. You might need to restore it manually.".format(self.task.id, self.machine.label, e)
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

            log.debug("Task #{0}: Released database task with status {1}".format(self.task.id, success))

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
                    # As per documentation, lexists() returns True for dead
                    # symbolic links.
                    if os.path.lexists(latest):
                        os.remove(latest)

                    os.symlink(self.storage, latest)
                except OSError as e:
                    log.warning("Task #{0}: Error pointing latest analysis symlink: {1}".format(self.task.id, e))
                finally:
                    latest_symlink_lock.release()

            log.info("Task #{0}: analysis procedure completed".format(self.task.id))
        except Exception as e:
            log.exception("Task #{0}: Failure in AnalysisManager.run: {1}".format(self.task.id, e))

        active_analysis_count -= 1

    def _rooter_response_check(self):
        if self.rooter_response and self.rooter_response["exception"] is not None:
            raise CuckooCriticalError("Error execution rooter command: %s" % self.rooter_response["exception"])

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
        elif self.route in vpns:
            self.interface = vpns[self.route].interface
            self.rt_table = vpns[self.route].rt_table
        elif self.route in self.socks5s:
            self.interface = ""
        else:
            log.warning("Unknown network routing destination specified, ignoring routing for this analysis: %r", self.route)
            self.interface = None
            self.rt_table = None

        # Check if the network interface is still available. If a VPN dies for
        # some reason, its tunX interface will no longer be available.
        if self.interface and not rooter("nic_available", self.interface):
            log.error(
                "The network interface '%s' configured for this analysis is " "not available at the moment, switching to route=none mode.",
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
                "socks5_enable", self.machine.ip, str(self.cfg.resultserver.port), str(routing.tor.dnsport), str(routing.tor.proxyport)
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
            raise CuckooNetworkError("Network interface {} not found".format(self.interface))

        if self.interface:
            self.rooter_response = rooter("forward_enable", self.machine.interface, self.interface, self.machine.ip)
            self._rooter_response_check()

        log.info("Enabled route '%s'", self.route)

        if self.rt_table:
            self.rooter_response = rooter("srcroute_enable", self.rt_table, self.machine.ip)
            self._rooter_response_check()

    def unroute_network(self):
        if self.interface:
            self.rooter_response = rooter("forward_disable", self.machine.interface, self.interface, self.machine.ip)
            log.info("Disabled route '%s'", self.route)
            self._rooter_response_check()

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
                "socks5_disable", self.machine.ip, str(self.cfg.resultserver.port), str(routing.tor.dnsport), str(routing.tor.proxyport),
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

    def set_stop_analyzing(self, signum, stack):
        self.running = False
        log.info("Now wait till all running tasks are completed")

    def initialize(self):
        """Initialize the machine manager."""
        global machinery, machine_lock

        machinery_name = self.cfg.cuckoo.machinery

        max_vmstartup_count = self.cfg.cuckoo.max_vmstartup_count
        if max_vmstartup_count:
            # machine_lock = threading.Semaphore(max_vmstartup_count)
            machine_lock = threading.BoundedSemaphore(max_vmstartup_count)
        else:
            machine_lock = threading.Lock()

        log.info(
            'Using "%s" machine manager with max_analysis_count=%d, ' "max_machines_count=%d, and max_vmstartup_count=%d",
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
        conf = os.path.join(CUCKOO_ROOT, "conf", "%s.conf" % machinery_name)

        if not os.path.exists(conf):
            raise CuckooCriticalError("The configuration file for machine " 'manager "{0}" does not exist at path:' " {1}".format(machinery_name, conf))

        # Provide a dictionary with the configuration options to the
        # machine manager instance.
        machinery.set_options(Config(machinery_name))

        # Initialize the machine manager.
        try:
            machinery.initialize(machinery_name)
        except CuckooMachineError as e:
            raise CuckooCriticalError("Error initializing machines: %s" % e)

        # At this point all the available machines should have been identified
        # and added to the list. If none were found, Cuckoo needs to abort the
        # execution.
        if not len(machinery.machines()):
            raise CuckooCriticalError("No machines available.")
        else:
            log.info("Loaded %s machine/s", len(machinery.machines()))

        if len(machinery.machines()) > 1 and self.db.engine.name == "sqlite":
            log.warning(
                "As you've configured Cuckoo to execute parallel "
                "analyses, we recommend you to switch to a MySQL "
                "a PostgreSQL database as SQLite might cause some "
                "issues."
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
                    "VM.",
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
        machinery.shutdown()

    def start(self):
        """Start scheduler."""
        self.initialize()

        log.info("Waiting for analysis tasks.")

        # To handle stop analyzing when we need to restart process without break tasks
        signal.signal(signal.SIGHUP, self.set_stop_analyzing)

        # Message queue with threads to transmit exceptions (used as IPC).
        errors = queue.Queue()

        # Command-line overrides the configuration file.
        if self.maxcount is None:
            self.maxcount = self.cfg.cuckoo.max_analysis_count

        # This loop runs forever.
        while self.running:
            time.sleep(1)

            # Wait until the machine lock is not locked. This is only the case
            # when all machines are fully running, rather that about to start
            # or still busy starting. This way we won't have race conditions
            # with finding out there are no available machines in the analysis
            # manager or having two analyses pick the same machine.
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
                need_space, space_available = free_space_monitor(dir_path,  return_value=True, analysis=True)
                if need_space:
                    log.error("Not enough free disk space! (Only %d MB!). You can change limits it in cuckoo.conf -> freespace", space_available)
                    continue

            # Have we limited the number of concurrently executing machines?
            if self.cfg.cuckoo.max_machines_count > 0:
                # Are too many running?
                if len(machinery.running()) >= self.cfg.cuckoo.max_machines_count:
                    continue

            # If no machines are available, it's pointless to fetch for
            # pending tasks. Loop over.
            if not machinery.availables():
                continue

            # Exits if max_analysis_count is defined in the configuration
            # file and has been reached.
            if self.maxcount and self.total_analysis_count >= self.maxcount:
                if active_analysis_count <= 0:
                    self.stop()
            else:
                # Fetch a pending analysis task.
                # TODO: this fixes only submissions by --machine, need to add other attributes (tags etc.)
                for machine in self.db.get_available_machines():
                    task = self.db.fetch(machine.name, machine.label)
                    if task:
                        break

                if task:
                    log.debug("Task #{0}: Processing task".format(task.id))
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
