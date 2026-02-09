import contextlib
import functools
import logging
import os
import queue
import shutil
import threading
from typing import Any, Callable, Generator, MutableMapping, Optional, Tuple

from lib.cuckoo.common.cleaners_utils import free_space_monitor
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
from lib.cuckoo.common.utils import convert_to_printable, create_folder, get_memdump_path
from lib.cuckoo.core.database import Database, _Database
from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_PENDING, TASK_RUNNING, Task
from lib.cuckoo.core.data.machines import Machine
from lib.cuckoo.core.data.guests import Guest
from lib.cuckoo.core.guest import GuestManager
from lib.cuckoo.core.machinery_manager import MachineryManager
from lib.cuckoo.core.plugins import RunAuxiliary
from lib.cuckoo.core.resultserver import ResultServer
from lib.cuckoo.core.rooter import _load_socks5_operational, rooter, vpns

log = logging.getLogger(__name__)

# os.listdir('/sys/class/net/')
HAVE_NETWORKIFACES = False

try:
    import psutil

    network_interfaces = list(psutil.net_if_addrs().keys())
    HAVE_NETWORKIFACES = True
except ImportError:
    print("Missed dependency: poetry run pip install psutil")

latest_symlink_lock = threading.Lock()


def is_network_interface(intf: str):
    global network_interfaces
    network_interfaces = list(psutil.net_if_addrs().keys())
    return intf in network_interfaces


class CuckooDeadMachine(Exception):
    """Exception thrown when a machine turns dead.

    When this exception has been thrown, the analysis task will start again,
    and will try to use another machine, when available.
    """

    def __init__(self, machine_name: str):
        super().__init__()
        self.machine_name = machine_name

    def __str__(self) -> str:
        return f"{self.machine_name} is dead!"


def main_thread_only(func):
    # Since most methods of the AnalysisManager class will be called within a child
    # thread, let's decorate ones that must only be called from the main thread so
    # that it's easy to differentiate between them.
    @functools.wraps(func)
    def inner(*args, **kwargs):
        if threading.current_thread() is not threading.main_thread():
            raise AssertionError(f"{func.__name__} must only be called from the main thread")
        return func(*args, **kwargs)

    return inner


class AnalysisLogger(logging.LoggerAdapter):
    """This class will be used by AnalysisManager so that all of its log entries
    will include the task ID, without having to explicitly include it in the log message.
    """

    def process(self, msg: str, kwargs: MutableMapping[str, Any]) -> Tuple[str, MutableMapping[str, Any]]:
        task_id: Optional[int] = self.extra.get("task_id") if self.extra is not None else None
        if task_id is not None:
            msg = f"Task #{task_id}: {msg}"
        return msg, kwargs


class AnalysisManager(threading.Thread):
    """Analysis Manager.

    This class handles the full analysis process for a given task. It takes
    care of selecting the analysis machine, preparing the configuration and
    interacting with the guest agent and analyzer components to launch and
    complete the analysis and store, process and report its results.
    """

    def __init__(
        self,
        task: Task,
        *,
        machine: Optional[Machine] = None,
        machinery_manager: Optional[MachineryManager] = None,
        error_queue: Optional[queue.Queue] = None,
        done_callback: Optional[Callable[["AnalysisManager"], None]] = None,
    ):
        """@param task: task object containing the details for the analysis."""
        super().__init__(name=f"task-{task.id}", daemon=True)
        self.db: _Database = Database()
        self.task = task
        self.log = AnalysisLogger(log, {"task_id": self.task.id})
        self.machine = machine
        self.machinery_manager = machinery_manager
        self.error_queue = error_queue
        self.done_callback = done_callback
        self.guest: Optional[Guest] = None
        self.cfg = Config()
        self.aux_cfg = Config("auxiliary")
        self.storage = os.path.join(CUCKOO_ROOT, "storage", "analyses", str(self.task.id))
        self.screenshot_path = os.path.join(self.storage, "shots")
        self.num_screenshots = 0
        self.binary = ""
        self.interface = None
        self.rt_table = None
        self.route = None
        self.rooter_response = ""
        self.reject_segments = None
        self.reject_hostports = None
        self.no_local_routing = None

    @main_thread_only
    def prepare_task_and_machine_to_start(self) -> None:
        """If the task doesn't use a machine, just set its state to running.
        Otherwise, update the task and machine in the database so that the
        task is running, the machine is locked and assigned to the task, and
        create a Guest row for the analysis.
        """
        self.db.set_task_status(self.task, TASK_RUNNING)
        if self.machine and self.machinery_manager:
            self.db.assign_machine_to_task(self.task, self.machine)
            self.db.lock_machine(self.machine)
            self.guest = self.db.create_guest(
                self.machine,
                self.machinery_manager.machinery.__class__.__name__,
                self.task,
            )

    def init_storage(self):
        """Initialize analysis storage folder."""
        # If the analysis storage folder already exists, we need to abort the
        # analysis or previous results will be overwritten and lost.
        if path_exists(self.storage):
            self.log.error("Analysis results folder already exists at path '%s', analysis aborted", self.storage)
            return False

        # If we're not able to create the analysis storage folder, we have to
        # abort the analysis.
        try:
            create_folder(folder=self.storage)
        except CuckooOperationalError:
            self.log.error("Unable to create analysis folder %s", self.storage)
            return False

        return True

    def check_file(self, sha256):
        """Checks the integrity of the file to be analyzed."""
        sample = self.db.view_sample(self.task.sample_id)

        if sample and sha256 != sample.sha256:
            self.log.error("Target file has been modified after submission: '%s'", convert_to_printable(self.task.target))
            return False

        return True

    def store_file(self, sha256):
        """Store a copy of the file being analyzed."""
        if not path_exists(self.task.target):
            self.log.error(
                "The file to analyze does not exist at path '%s', analysis aborted", convert_to_printable(self.task.target)
            )
            return False

        binaries_dir = os.path.join(CUCKOO_ROOT, "storage", "binaries")
        self.binary = os.path.join(binaries_dir, sha256)

        if path_exists(self.binary):
            self.log.info("File already exists at '%s'", self.binary)
        else:
            path_mkdir(binaries_dir, exist_ok=True)
            # TODO: do we really need to abort the analysis in case we are not able to store a copy of the file?
            try:
                shutil.copy(self.task.target, self.binary)
            except (IOError, shutil.Error):
                self.log.error(
                    "Unable to store file from '%s' to '%s', analysis aborted",
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
            self.log.error("Unable to create symlink/copy from '%s' to '%s': %s", self.binary, self.storage, e)

        return True

    def screenshot_machine(self):
        if not self.cfg.cuckoo.machinery_screenshots:
            return
        if self.machinery_manager is None or self.machine is None:
            self.log.error("screenshot not possible, no machine is used for this analysis")
            return

        # same format and filename approach here as VM-based screenshots
        self.num_screenshots += 1
        screenshot_filename = f"{str(self.num_screenshots).rjust(4, '0')}.jpg"
        screenshot_path = os.path.join(self.screenshot_path, screenshot_filename)
        try:
            self.machinery_manager.machinery.screenshot(self.machine.label, screenshot_path)
        except Exception as err:
            self.log.warning("Failed to take screenshot of %s: %s", self.machine.label, err)
            self.num_screenshots -= 1

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
            "options": self.get_machine_specific_options(self.task.options),
            "enforce_timeout": self.task.enforce_timeout,
            "clock": self.task.clock,
            "terminate_processes": self.cfg.cuckoo.terminate_processes,
            "upload_max_size": self.cfg.resultserver.upload_max_size,
            "do_upload_max_size": int(self.cfg.resultserver.do_upload_max_size),
            "enable_trim": int(Config("web").general.enable_trim),
            "timeout": self.task.timeout or self.cfg.timeouts.default,
        }

        if self.task.category == "file":
            file_obj = File(self.task.target)
            options["file_name"] = file_obj.get_name()
            options["file_type"] = file_obj.get_type()
            # if it's a PE file, collect export information to use in more smartly determining the right package to use
            with PortableExecutable(self.task.target) as pe:
                options["exports"] = pe.get_dll_exports()
            del file_obj

        # options from auxiliary.conf
        for plugin in self.aux_cfg.auxiliary_modules.keys():
            options[plugin] = self.aux_cfg.auxiliary_modules[plugin]

        return options

    def category_checks(self) -> Optional[bool]:
        if self.task.category in ("file", "pcap", "static"):
            try:
                sha256 = File(self.task.target).get_sha256()
            except FileNotFoundError:
                # Happens when cleaner deleted target file
                self.log.error("File %s missed", self.task.target)
                return False
            # Check whether the file has been changed for some unknown reason.
            # And fail this analysis if it has been modified.
            if not self.check_file(sha256):
                self.log.debug("check file")
                return False

            # Store a copy of the original file.
            if not self.store_file(sha256):
                self.log.debug("store file")
                return False

        if self.task.category in ("pcap", "static"):
            if self.task.category == "pcap":
                if hasattr(os, "symlink"):
                    os.symlink(self.binary, os.path.join(self.storage, "dump.pcap"))
                else:
                    shutil.copy(self.binary, os.path.join(self.storage, "dump.pcap"))
            # create the logs/files directories as normally the resultserver would do it
            for dirname in ("logs", "files", "aux"):
                try:
                    path_mkdir(os.path.join(self.storage, dirname))
                except Exception:
                    self.log.debug("Failed to create folder %s", dirname)
            return True

        return None

    @contextlib.contextmanager
    def machine_running(self) -> Generator[None, None, None]:
        assert self.machinery_manager and self.machine and self.guest

        try:
            with self.db.session.begin():
                self.machinery_manager.start_machine(self.machine)

            yield

            # Take a memory dump of the machine before shutting it off.
            self.dump_machine_memory()

        except (CuckooMachineError, CuckooGuestCriticalTimeout) as e:
            # This machine has turned dead, so we'll throw an exception
            # which informs the AnalysisManager that it should analyze
            # this task again with another available machine.
            self.log.exception(str(e))

            # Remove the guest from the database, so that we can assign a
            # new guest when the task is being analyzed with another machine.
            with self.db.session.begin():
                self.db.guest_remove(self.guest.id)
                self.db.assign_machine_to_task(self.task, None)
                # ToDo do we really need to delete machine here?
                self.machinery_manager.machinery.delete_machine(self.machine.name)

            # Remove the analysis directory that has been created so
            # far, as perform_analysis() is going to be doing that again.
            shutil.rmtree(self.storage)

            raise CuckooDeadMachine(self.machine.name) from e

        with self.db.session.begin():
            try:
                self.machinery_manager.stop_machine(self.machine)
            except CuckooMachineError as e:
                self.log.warning("Unable to stop machine %s: %s", self.machine.label, e)
                # Explicitly rollback since we don't re-raise the exception.
                self.db.session.rollback()

        try:
            # Release the analysis machine, but only if the machine is not dead.
            with self.db.session.begin():
                self.machinery_manager.machinery.release(self.machine)
        except CuckooMachineError as e:
            self.log.error(
                "Unable to release machine %s, reason %s. You might need to restore it manually",
                self.machine.label,
                e,
            )

    def dump_machine_memory(self) -> None:
        if not self.cfg.cuckoo.memory_dump and not self.task.memory:
            return

        assert self.machinery_manager and self.machine

        try:
            dump_path = get_memdump_path(self.task.id)
            need_space, space_available = free_space_monitor(os.path.dirname(dump_path), return_value=True)
            if need_space:
                self.log.error("Not enough free disk space! Could not dump ram (Only %d MB!)", space_available)
            else:
                self.machinery_manager.machinery.dump_memory(self.machine.label, dump_path)
        except NotImplementedError:
            self.log.error("The memory dump functionality is not available for the current machine manager")

        except CuckooMachineError as e:
            self.log.exception(str(e))

    @contextlib.contextmanager
    def result_server(self) -> Generator[None, None, None]:
        try:
            ResultServer().add_task(self.task, self.machine)
        except Exception as e:
            self.log.exception("Failed to add task to result-server")
            if self.error_queue:
                self.error_queue.put(e)
            raise
        try:
            yield
        finally:
            # After all this, we can make the ResultServer forget about the
            # internal state for this analysis task.
            ResultServer().del_task(self.task, self.machine)

    @contextlib.contextmanager
    def network_routing(self) -> Generator[None, None, None]:
        self.route_network()
        try:
            yield
        finally:
            # Drop the network routing rules if any.
            self.unroute_network()

    @contextlib.contextmanager
    def run_auxiliary(self) -> Generator[None, None, None]:
        aux = RunAuxiliary(task=self.task, machine=self.machine)

        with self.db.session.begin():
            aux.start()

        try:
            yield
        finally:
            with self.db.session.begin():
                aux.stop()

    def run_analysis_on_guest(self) -> None:
        # Generate the analysis configuration file.
        options = self.build_options()

        guest_manager = GuestManager(self.machine.name, self.machine.ip, self.machine.platform, self.task.id, self)

        with self.db.session.begin():
            if Config("web").guacamole.enabled and hasattr(self.machinery_manager.machinery, "store_vnc_port"):
                self.machinery_manager.machinery.store_vnc_port(self.machine.label, self.task.id)
            options["clock"] = self.db.update_clock(self.task.id)
            self.db.guest_set_status(self.task.id, "starting")
        guest_manager.start_analysis(options)
        try:
            if guest_manager.get_status_from_db() == "starting":
                guest_manager.set_status_in_db("running")
                guest_manager.wait_for_completion()
            guest_manager.set_status_in_db("stopping")
        except Exception as e:
            guest_manager.set_status_in_db("failed")
            self.log.exception("Unknown exception waiting for guest completion: %s", str(e))

        return

    def perform_analysis(self) -> bool:
        """Start analysis."""
        succeeded = False
        self.socks5s = _load_socks5_operational()

        # Initialize the analysis folders.
        if not self.init_storage():
            self.log.debug("Failed to initialize the analysis folder")
            return False

        with self.db.session.begin():
            category_early_escape = self.category_checks()
            if isinstance(category_early_escape, bool):
                return category_early_escape

        # At this point, we're sure that this analysis requires a machine.
        assert self.machinery_manager and self.machine and self.guest

        with self.db.session.begin():
            self.machinery_manager.scale_pool(self.machine)

        self.log.info("Starting analysis of %s '%s'", self.task.category.upper(), convert_to_printable(self.task.target))

        with self.machine_running(), self.result_server(), self.network_routing(), self.run_auxiliary():
            try:
                self.run_analysis_on_guest()
            except CuckooGuestError as e:
                self.log.exception(str(e))
            else:
                succeeded = True
            finally:
                with self.db.session.begin():
                    self.db.guest_stop(self.guest.id)

        return succeeded

    def launch_analysis(self) -> None:
        success = False
        try:
            success = self.perform_analysis()
        except CuckooDeadMachine:
            with self.db.session.begin():
                # Put the task back in pending so that the schedule can attempt to choose a new machine.
                self.db.set_status(self.task.id, TASK_PENDING)
            raise
        else:
            with self.db.session.begin():
                self.db.set_status(self.task.id, TASK_COMPLETED)
                self.log.info("Completed analysis %ssuccessfully.", "" if success else "un")
                # Need to be release on unsucess
                if not success and hasattr(self, "machine") and self.machine:
                    self.db.unlock_machine(self.machine)

            self.update_latest_symlink()

    def update_latest_symlink(self):
        # We make a symbolic link ("latest") which links to the latest analysis this is useful for debugging purposes.
        # This is only supported under systems that support symbolic links.
        if not hasattr(os, "symlink"):
            return

        latest = os.path.join(CUCKOO_ROOT, "storage", "analyses", "latest")

        # First we have to remove the existing symbolic link, then we have to create the new one.
        # Deal with race conditions using a lock.
        with latest_symlink_lock:
            try:
                # As per documentation, lexists() returns True for dead symbolic links.
                if os.path.lexists(latest):
                    path_delete(latest)

                os.symlink(self.storage, latest)
            except OSError as e:
                self.log.warning("Error pointing latest analysis symlink: %s", e)

    def run(self):
        """Run manager thread."""
        try:
            self.launch_analysis()
        except Exception:
            self.log.exception("failure in AnalysisManager.run")
        else:
            self.log.info("analysis procedure completed")
        finally:
            if self.done_callback:
                self.done_callback(self)

    def _rooter_response_check(self):
        if self.rooter_response and self.rooter_response["exception"] is not None:
            raise CuckooCriticalError(f"Error execution rooter command: {self.rooter_response['exception']}")

    def route_network(self):
        """Enable network routing if desired."""
        # Determine the desired routing strategy (none, internet, VPN).
        routing = Config("routing")
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
            self.no_local_routing = routing.routing.no_local_routing and not routing.routing.nat
            if routing.routing.reject_segments != "none":
                self.reject_segments = routing.routing.reject_segments
            if routing.routing.reject_hostports != "none":
                self.reject_hostports = str(routing.routing.reject_hostports)
        elif self.route in vpns:
            self.interface = vpns[self.route].interface
            self.rt_table = vpns[self.route].rt_table
        elif self.route in self.socks5s:
            self.interface = ""
        elif self.route[:3] == "tun" and is_network_interface(self.route):
            # tunnel interface starts with "tun" and interface exists on machine
            self.interface = self.route
        else:
            self.log.warning("Unknown network routing destination specified, ignoring routing for this analysis: %s", self.route)
            self.interface = None
            self.rt_table = None

        # Check if the network interface is still available. If a VPN dies for
        # some reason, its tunX interface will no longer be available.
        if self.interface and not rooter("nic_available", self.interface):
            self.log.error(
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
            self.rooter_response = rooter("libvirt_fwo_enable", self.machine.interface, self.machine.ip)

        elif self.route in ("none", "None", "drop"):
            self.rooter_response = rooter("drop_enable", self.machine.ip, str(self.cfg.resultserver.port))
        elif self.route[:3] == "tun" and is_network_interface(self.route):
            self.log.info("Network interface %s is tunnel", self.interface)
            self.rooter_response = rooter("interface_route_tun_enable", self.machine.ip, self.route, str(self.task.id))

        self._rooter_response_check()

        # check if the interface is up
        if HAVE_NETWORKIFACES and routing.routing.verify_interface and self.interface and self.interface not in network_interfaces:
            self.log.info("Network interface %s not found, falling back to dropping network traffic", self.interface)
            self.interface = None
            self.rt_table = None
            self.route = "drop"

        if self.interface:
            self.rooter_response = rooter("libvirt_fwo_enable", self.machine.interface, self.machine.ip)
            if self.no_local_routing:
                input_interface = "dirty-line"
                # Traffic from lan to machine
                self.rooter_response = rooter(
                    "forward_enable", input_interface, self.machine.interface, "0.0.0.0/0", self.machine.ip
                )
            else:
                input_interface = self.machine.interface
            # Traffic outbound from machine
            self.rooter_response = rooter("forward_enable", input_interface, self.interface, self.machine.ip)
            self._rooter_response_check()
            if self.reject_segments:
                self.rooter_response = rooter(
                    "forward_reject_enable", self.machine.interface, self.interface, self.machine.ip, self.reject_segments
                )
                self._rooter_response_check()
            if self.no_local_routing:
                # Need for forward traffic between sandbox and CAPE
                self.rooter_response = rooter(
                    "forward_enable",
                    input_interface,
                    self.interface,
                    self.machine.ip,
                    self.cfg.resultserver.ip,
                    "tcp",
                    str(self.cfg.resultserver.port),
                )
                self.rooter_response = rooter(
                    "forward_enable", input_interface, self.machine.interface, self.cfg.resultserver.ip, self.machine.ip
                )
                self._rooter_response_check()
            if self.reject_hostports:
                self.rooter_response = rooter(
                    "hostports_reject_enable", self.machine.interface, self.machine.ip, self.reject_hostports
                )
                self._rooter_response_check()

        self.log.info("Enabled route '%s'.", self.route)

        if self.no_local_routing:
            rooter("add_dev_to_vrf", self.machine.interface)
        elif self.rt_table:
            self.rooter_response = rooter("srcroute_enable", self.rt_table, self.machine.ip)
            self._rooter_response_check()

    def unroute_network(self):
        routing = Config("routing")
        if self.interface:
            self.rooter_response = rooter("libvirt_fwo_disable", self.machine.interface, self.machine.ip)
            if self.no_local_routing:
                input_interface = "dirty-line"
                # Traffic from lan to machine
                self.rooter_response = rooter(
                    "forward_disable", input_interface, self.machine.interface, "0.0.0.0/0", self.machine.ip
                )
            else:
                input_interface = self.machine.interface
            # Traffic outbound from machine
            self.rooter_response = rooter("forward_disable", input_interface, self.interface, self.machine.ip)
            self._rooter_response_check()
            if self.reject_segments:
                self.rooter_response = rooter(
                    "forward_reject_disable", self.machine.interface, self.interface, self.machine.ip, self.reject_segments
                )
                self._rooter_response_check()
            if self.no_local_routing:
                self.rooter_response = rooter(
                    "forward_disable",
                    input_interface,
                    self.interface,
                    self.machine.ip,
                    self.cfg.resultserver.ip,
                    "tcp",
                    str(self.cfg.resultserver.port),
                )
                self.rooter_response = rooter(
                    "forward_disable", input_interface, self.machine.interface, self.cfg.resultserver.ip, self.machine.ip
                )
            if self.reject_hostports:
                self.rooter_response = rooter(
                    "hostports_reject_disable", self.machine.interface, self.machine.ip, self.reject_hostports
                )
                self._rooter_response_check()
            self.log.info("Disabled route '%s'", self.route)

        if self.no_local_routing:
            rooter("delete_dev_from_vrf", self.machine.interface)
        elif self.rt_table:
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
            self.rooter_response = rooter("libvirt_fwo_disable", self.machine.interface, self.machine.ip)

        elif self.route in ("none", "None", "drop"):
            self.rooter_response = rooter("drop_disable", self.machine.ip, str(self.cfg.resultserver.port))
        elif self.route[:3] == "tun":
            self.log.info("Disable tunnel interface: %s", self.interface)
            self.rooter_response = rooter("interface_route_tun_disable", self.machine.ip, self.route, str(self.task.id))

        self._rooter_response_check()

    def get_machine_specific_options(self, task_opts: str) -> str:
        """This function may be used to return an updated version of the
        provided options string based on the machine that has been selected
        (self.machine).
        """
        return task_opts
