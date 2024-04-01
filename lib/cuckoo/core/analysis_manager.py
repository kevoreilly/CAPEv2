import logging
import os
import shutil
import threading
import time

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import (
    CuckooCriticalError,
    CuckooGuestCriticalTimeout,
    CuckooGuestError,
    CuckooMachineError,
    CuckooOperationalError,
)
from lib.cuckoo.common.integrations.parse_pe import PortableExecutable
from lib.cuckoo.common.objects import File
from lib.cuckoo.common.path_utils import path_delete, path_exists, path_mkdir
from lib.cuckoo.common.utils import convert_to_printable, create_folder, free_space_monitor, get_memdump_path
from lib.cuckoo.core import scheduler
from lib.cuckoo.core.database import TASK_COMPLETED, Database
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.log import task_log_stop
from lib.cuckoo.core.plugins import RunAuxiliary
from lib.cuckoo.core.resultserver import ResultServer
from lib.cuckoo.core.rooter import _load_socks5_operational, rooter, vpns
from lib.cuckoo.core.scheduler import CuckooDeadMachine

log = logging.getLogger(__name__)

# os.listdir('/sys/class/net/')
HAVE_NETWORKIFACES = False
try:
    import psutil

    network_interfaces = list(psutil.net_if_addrs().keys())
    HAVE_NETWORKIFACES = True
except ImportError:
    print("Missed dependency: pip3 install psutil")

web_cfg = Config("web")
enable_trim = int(web_cfg.general.enable_trim)
expose_vnc_port = web_cfg.guacamole.enabled
routing = Config("routing")
latest_symlink_lock = threading.Lock()


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
        self.screenshot_path = ""
        self.num_screenshots = 0
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
        self.screenshot_path = os.path.join(self.storage, "shots")

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

        self.binary = os.path.join(CUCKOO_ROOT, "storage", "binaries", sha256)

        if path_exists(self.binary):
            log.info("Task #%s: File already exists at '%s'", self.task.id, self.binary)
        else:
            # TODO: do we really need to abort the analysis in case we are not able to store a copy of the file?
            try:
                shutil.copy(self.task.target, self.binary)
            except (IOError, shutil.Error):
                log.error(
                    "Task #%s: Unable to store file from '%s' to '%s', analysis aborted",
                    self.task.id,
                    self.task.target,
                    self.binary,
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

    def screenshot_machine(self):
        if not self.cfg.cuckoo.machinery_screenshots:
            return
        if self.machine is None:
            log.error("Task #%s: screenshot not possible, no machine acquired yet", self.task.id)
            return

        # same format and filename approach here as VM-based screenshots
        self.num_screenshots += 1
        screenshot_filename = f"{str(self.num_screenshots).rjust(4, '0')}.jpg"
        screenshot_path = os.path.join(self.screenshot_path, screenshot_filename)
        scheduler.machinery.screenshot(self.machine.label, screenshot_path)

    def acquire_machine(self):
        """Acquire an analysis machine from the pool of available ones."""
        machine = None
        orphan = False
        # Start a loop to acquire a machine to run the analysis on.
        while True:
            scheduler.machine_lock.acquire()

            # If the user specified a specific machine ID, a platform to be
            # used or machine tags acquire the machine accordingly.
            task_archs, task_tags = self.db._task_arch_tags_helper(self.task)
            os_version = self.db._package_vm_requires_check(self.task.package)

            # In some cases it's possible that we enter this loop without having any available machines. We should make sure this is not
            # such case, or the analysis task will fail completely.
            if not scheduler.machinery.availables(
                label=self.task.machine, platform=self.task.platform, tags=task_tags, arch=task_archs, os_version=os_version
            ):
                scheduler.machine_lock.release()
                log.debug(
                    "Task #%s: no machine available yet for machine '%s', platform '%s' or tags '%s'.",
                    self.task.id,
                    self.task.machine,
                    self.task.platform,
                    self.task.tags,
                )
                time.sleep(1)
                continue
            if self.cfg.cuckoo.batch_scheduling and not orphan:
                machine = scheduler.machinery.acquire(
                    machine_id=self.task.machine,
                    platform=self.task.platform,
                    tags=task_tags,
                    arch=task_archs,
                    os_version=os_version,
                    need_scheduled=True,
                )
            else:
                machine = scheduler.machinery.acquire(
                    machine_id=self.task.machine,
                    platform=self.task.platform,
                    tags=task_tags,
                    arch=task_archs,
                    os_version=os_version,
                    need_scheduled=True,
                )

            # If no machine is available at this moment, wait for one second and try again.
            if not machine:
                scheduler.machine_lock.release()
                log.debug(
                    "Task #%s: no machine available yet for machine '%s', platform '%s' or tags '%s'.",
                    self.task.id,
                    self.task.machine,
                    self.task.platform,
                    self.task.tags,
                )
                time.sleep(1)
                orphan = True
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
        global active_analysis_count
        succeeded = False
        dead_machine = False
        self.socks5s = _load_socks5_operational()
        aux = False
        # Initialize the analysis folders.
        if not self.init_storage():
            log.debug("Failed to initialize the analysis folder")
            return False

        with self.db.session.begin():
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
            with self.db.session.begin():
                self.acquire_machine()
                self.set_machine_specific_options()
                guest_log = self.db.set_task_vm_and_guest_start(
                    self.task.id,
                    self.machine.name,
                    self.machine.label,
                    self.task.platform,
                    self.machine.id,
                    scheduler.machinery.__class__.__name__,
                    self.task.options,
                )
                self.db.session.flush()
                self.db.session.expunge(self.machine)
        # At this point we can tell the ResultServer about it.
        except CuckooOperationalError as e:
            scheduler.machine_lock.release()
            log.error("Task #%s: Cannot acquire machine: %s", self.task.id, e, exc_info=True)
            return False

        try:
            unlocked = False

            # Mark the selected analysis machine in the database as started.
            # Start the machine.
            with self.db.session.begin():
                scheduler.machinery.start(self.machine.label)

            # By the time start returns it will have fully started the Virtual
            # Machine. We can now safely release the machine lock.
            scheduler.machine_lock.release()
            unlocked = True

            # Generate the analysis configuration file.
            options = self.build_options()

            if expose_vnc_port and hasattr(scheduler.machinery, "store_vnc_port"):
                scheduler.machinery.store_vnc_port(self.machine.label, self.task.id)

            try:
                ResultServer().add_task(self.task, self.machine)
            except Exception as e:
                with self.db.session.begin():
                    scheduler.machinery.release(self.machine.label)
                log.exception(e, exc_info=True)
                self.errors.put(e)

            aux = RunAuxiliary(task=self.task, machine=self.machine)

            # Enable network routing.
            self.route_network()

            with self.db.session.begin():
                aux.start()

            # Initialize the guest manager.
            guest = GuestManager(self.machine.name, self.machine.ip, self.machine.platform, self.task.id, self)

            with self.db.session.begin():
                options["clock"] = self.db.update_clock(self.task.id)
                self.db.guest_set_status(self.task.id, "starting")
            # Start the analysis.
            guest.start_analysis(options)
            if guest.get_status_from_db() == "starting":
                guest.set_status_in_db("running")
                guest.wait_for_completion()

            guest.set_status_in_db("stopping")
            succeeded = True
        except (CuckooMachineError, CuckooGuestCriticalTimeout) as e:
            if not unlocked:
                scheduler.machine_lock.release()
            log.error(str(e), extra={"task_id": self.task.id}, exc_info=True)
            dead_machine = True
        except CuckooGuestError as e:
            if not unlocked:
                scheduler.machine_lock.release()
            log.error(str(e), extra={"task_id": self.task.id}, exc_info=True)
        finally:
            # Stop Auxiliary modules.
            if aux:
                with self.db.session.begin():
                    aux.stop()

            # Take a memory dump of the machine before shutting it off.
            if self.cfg.cuckoo.memory_dump or self.task.memory:
                try:
                    dump_path = get_memdump_path(self.task.id)
                    need_space, space_available = free_space_monitor(os.path.dirname(dump_path), return_value=True)
                    if need_space:
                        log.error("Not enough free disk space! Could not dump ram (Only %d MB!)", space_available)
                    else:
                        scheduler.machinery.dump_memory(self.machine.label, dump_path)
                except NotImplementedError:
                    log.error("The memory dump functionality is not available for the current machine manager")

                except CuckooMachineError as e:
                    log.error(e, exc_info=True)

            try:
                # Stop the analysis machine.
                with self.db.session.begin():
                    scheduler.machinery.stop(self.machine.label)

            except CuckooMachineError as e:
                log.warning("Task #%s: Unable to stop machine %s: %s", self.task.id, self.machine.label, e)

            # Mark the machine in the database as stopped. Unless this machine
            # has been marked as dead, we just keep it as "started" in the
            # database so it'll not be used later on in this session.
            with self.db.session.begin():
                self.db.guest_stop(guest_log)

            # After all this, we can make the ResultServer forget about the
            # internal state for this analysis task.
            ResultServer().del_task(self.task, self.machine)

            # Drop the network routing rules if any.
            self.unroute_network()

            if dead_machine:
                # Remove the guest from the database, so that we can assign a
                # new guest when the task is being analyzed with another machine.
                with self.db.session.begin():
                    self.db.guest_remove(guest_log)
                    scheduler.machinery.delete_machine(self.machine.name)

                # Remove the analysis directory that has been created so
                # far, as launch_analysis() is going to be doing that again.
                shutil.rmtree(self.storage)

                # This machine has turned dead, so we throw an exception here
                # which informs the AnalysisManager that it should analyze
                # this task again with another available machine.
                raise CuckooDeadMachine()

            try:
                # Release the analysis machine. But only if the machine has not turned dead yet.
                with self.db.session.begin():
                    scheduler.machinery.release(self.machine.label)

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
        with scheduler.active_analysis_count_lock:
            scheduler.active_analysis_count += 1
        try:
            while True:
                try:
                    success = self.launch_analysis()
                except CuckooDeadMachine as e:
                    log.exception(e)
                    continue

                break

            with self.db.session.begin():
                self.db.set_status(self.task.id, TASK_COMPLETED)

                # If the task is still available in the database, update our task
                # variable with what's in the database, as otherwise we're missing
                # out on the status and completed_on change. This would then in
                # turn thrown an exception in the analysisinfo processing module.
                self.task = self.db.view_task(self.task.id) or self.task
                self.db.session.expunge(self.task)

            log.debug("Task #%s: Released database task with status %s", self.task.id, success)

            # We make a symbolic link ("latest") which links to the latest
            # analysis - this is useful for debugging purposes. This is only
            # supported under systems that support symbolic links.
            if hasattr(os, "symlink"):
                latest = os.path.join(CUCKOO_ROOT, "storage", "analyses", "latest")

                # First we have to remove the existing symbolic link, then we have to create the new one.
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
            with self.db.session.begin():
                self.db.set_status(self.task.id, TASK_COMPLETED)
            task_log_stop(self.task.id)
            with scheduler.active_analysis_count_lock:
                scheduler.active_analysis_count -= 1

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
            log.info("Network interface {} not found, falling back to dropping network traffic", self.interface)
            self.interface = None
            self.rt_table = None
            self.route = "drop"

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

        log.info("Enabled route '%s'.", self.route)

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

    def set_machine_specific_options(self):
        """This function may be used to update self.task.options based on the machine
        that has been selected (self.machine).
        """
        return
