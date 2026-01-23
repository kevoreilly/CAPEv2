import logging
import threading
import time
from time import monotonic as _time
from typing import Optional, Union

from lib.cuckoo.common.abstracts import Machinery
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError
from lib.cuckoo.core.database import Database, Machine, Task, _Database
from lib.cuckoo.core.plugins import list_plugins
from lib.cuckoo.core.rooter import rooter, vpns

log = logging.getLogger(__name__)

routing = Config("routing")


class ScalingBoundedSemaphore(threading.Semaphore):
    """Implements a dynamic bounded semaphore.

    A bounded semaphore checks to make sure its current value doesn't exceed its
    limit value. If it does, ValueError is raised. In most situations
    semaphores are used to guard resources with limited capacity.

    If the semaphore is released too many times it's a sign of a bug. If not
    given, value defaults to 1.

    Like regular semaphores, bounded semaphores manage a counter representing
    the number of release() calls minus the number of acquire() calls, plus a
    limit value. The acquire() method blocks if necessary until it can return
    without making the counter negative. If not given, value defaults to 1.

    In this version of semaphore there is an upper limit where its limit value
    can never reach when it is changed. The idea behind it is that in machinery
    documentation there is a limit of machines that can be available so there is
    no point having it higher than that.
    """

    def __init__(self, value=1, upper_limit=1):
        threading.Semaphore.__init__(self, value)
        self._limit_value = value
        self._upper_limit = upper_limit

    def acquire(self, blocking=True, timeout=None):
        """Acquire a semaphore, decrementing the internal counter by one.

        When invoked without arguments: if the internal counter is larger than
        zero on entry, decrement it by one and return immediately. If it is zero
        on entry, block, waiting until some other thread has called release() to
        make it larger than zero. This is done with proper interlocking so that
        if multiple acquire() calls are blocked, release() will wake exactly one
        of them up. The implementation may pick one at random, so the order in
        which blocked threads are awakened should not be relied on. There is no
        return value in this case.

        When invoked with blocking set to true, do the same thing as when called
        without arguments, and return true.

        When invoked with blocking set to false, do not block. If a call without
        an argument would block, return false immediately; otherwise, do the
        same thing as when called without arguments, and return true.

        When invoked with a timeout other than None, it will block for at
        most timeout seconds.  If acquire does not complete successfully in
        that interval, return false.  Return true otherwise.

        """
        if not blocking and timeout is not None:
            raise ValueError("Cannot specify timeout for non-blocking acquire()")
        rc = False
        endtime = None
        with self._cond:
            while self._value == 0:
                if not blocking:
                    break
                if timeout is not None:
                    if endtime is None:
                        endtime = _time() + timeout
                    else:
                        timeout = endtime - _time()
                        if timeout <= 0:
                            break
                self._cond.wait(timeout)
            else:
                self._value -= 1
                rc = True
        return rc

    __enter__ = acquire

    def release(self):
        """Release a semaphore, incrementing the internal counter by one.

        When the counter is zero on entry and another thread is waiting for it
        to become larger than zero again, wake up that thread.

        If the number of releases exceeds the number of acquires,
        raise a ValueError.

        """
        with self._cond:
            if self._value > self._upper_limit:
                raise ValueError("Semaphore released too many times")
            if self._value >= self._limit_value:
                self._value = self._limit_value
                self._cond.notify()
                return
            self._value += 1
            self._cond.notify()

    def __exit__(self, t, v, tb):
        self.release()

    def update_limit(self, value):
        """Update the limit value for the semaphore

        This limit value is the bounded limit, and proposed limit values
        are validated against the upper limit.

        """
        if 0 < value < self._upper_limit:
            self._limit_value = value
        if self._value > value:
            self._value = value

    def check_for_starvation(self, available_count: int):
        """Check for preventing starvation from coming up after updating the limit.
        Take no parameter.
        Return true on starvation.
        """
        if self._value == 0 and available_count == self._limit_value:
            self._value = self._limit_value
            return True
        # Resync of the lock value
        if abs(self._value - available_count) > 0:
            self._value = available_count
            return True
        return False


MachineryLockType = Union[threading.Lock, threading.BoundedSemaphore, ScalingBoundedSemaphore]


class MachineryManager:
    def __init__(self):
        self.cfg = Config()
        self.db: _Database = Database()
        self.machinery_name: str = self.cfg.cuckoo.machinery
        self.machinery: Machinery = self.create_machinery()
        self.pool_scaling_lock = threading.Lock()
        self.machines_limit: Optional[int] = None
        if self.machinery.module_name != self.machinery_name:
            raise CuckooCriticalError(
                f"Incorrect machinery module was imported. "
                f"Should've been {self.machinery_name} but was {self.machinery.module_name}"
            )
        log.info(
            "Using %s with max_machines_count=%d",
            self,
            self.cfg.cuckoo.max_machines_count,
        )
        self.machine_lock: Optional[MachineryLockType] = None

    def __str__(self):
        return f"{self.__class__.__name__}[{self.machinery_name}]"

    def create_machine_lock(self) -> MachineryLockType:
        retval: MachineryLockType = threading.Lock()

        # You set this value if you are using a machinery that is NOT auto-scaling
        max_vmstartup_count = self.cfg.cuckoo.max_vmstartup_count
        if max_vmstartup_count:
            # The BoundedSemaphore is used to prevent CPU starvation when starting up multiple VMs
            log.info("max_vmstartup_count for BoundedSemaphore = %d", max_vmstartup_count)
            retval = threading.BoundedSemaphore(max_vmstartup_count)

        # You set this value if you are using a machinery that IS auto-scaling
        elif self.cfg.cuckoo.scaling_semaphore:
            # If the user wants to use the scaling bounded semaphore, check what machinery is specified, and then
            # grab the required configuration key for setting the upper limit
            machinery_opts = self.machinery.options.get(self.machinery_name)
            if self.machinery_name == "az":
                self.machines_limit = machinery_opts.get("total_machines_limit")
            elif self.machinery_name == "aws":
                self.machines_limit = machinery_opts.get("dynamic_machines_limit")
            if self.machines_limit:
                # The ScalingBoundedSemaphore is used to keep feeding available machines from the pending tasks queue
                log.info("upper limit for ScalingBoundedSemaphore = %d", self.machines_limit)
                retval = ScalingBoundedSemaphore(value=len(self.machinery.machines()), upper_limit=self.machines_limit)
            else:
                log.warning(
                    "scaling_semaphore is set but the %s machinery does not set the machines limit. Ignoring scaling semaphore.",
                    self.machinery_name,
                )

        return retval

    @staticmethod
    def create_machinery() -> Machinery:
        # Get registered class name. Only one machine manager is imported,
        # therefore there should be only one class in the list.
        plugin = list_plugins("machinery")[0]
        machinery: Machinery = plugin()

        return machinery

    def find_machine_to_service_task(self, task: Task) -> Optional[Machine]:
        machine = self.machinery.find_machine_to_service_task(task)
        if machine:
            log.info(
                "Task #%s: found useable machine %s (arch=%s, platform=%s)",
                task.id,
                machine.name,
                machine.arch,
                machine.platform,
            )
        else:
            log.debug(
                "Task #%s: no machine available yet for task requiring machine '%s', platform '%s' or tags '%s'.",
                task.id,
                task.machine,
                task.platform,
                task.tags,
            )

        return machine

    def initialize_machinery(self) -> None:
        """Initialize the machines in the database and initialize routing for them."""
        try:
            self.machinery.initialize()
        except CuckooMachineError as e:
            raise CuckooCriticalError("Error initializing machines") from e

        # At this point all the available machines should have been identified
        # and added to the list. If none were found, Cuckoo needs to abort the
        # execution.
        available_machines = list(self.machinery.machines())
        if not len(available_machines):
            raise CuckooCriticalError("No machines available")
        else:
            log.info("Loaded %d machine%s", len(available_machines), "s" if len(available_machines) != 1 else "")

        if len(available_machines) > 1 and self.db.engine.name == "sqlite":
            log.warning(
                "As you've configured CAPE to execute parallel analyses, we recommend you to switch to a PostgreSQL database as SQLite might cause some issues"
            )

        # Drop all existing packet forwarding rules for each VM. Just in case
        # Cuckoo was terminated for some reason and various forwarding rules
        # have thus not been dropped yet.
        for machine in available_machines:
            rooter(
                "inetsim_disable",
                machine.ip,
                routing.inetsim.server,
                str(routing.inetsim.dnsport),
                str(self.cfg.resultserver.port),
                str(routing.inetsim.ports),
            )
            if not machine.interface:
                log.info(
                    "Unable to determine the network interface for VM with name %s, Cape will not be able to give it "
                    "full internet access or route it through a VPN! Please define a default network interface for the "
                    "machinery or define a network interface for each VM",
                    machine.name,
                )
                continue

            # Drop forwarding rule to each VPN.
            for vpn in vpns.values():
                rooter("forward_disable", machine.interface, vpn.interface, machine.ip)

            # Drop forwarding rule to the internet / dirty line.
            if routing.routing.internet != "none":
                rooter("forward_disable", machine.interface, routing.routing.internet, machine.ip)

        self.machine_lock = self.create_machine_lock()
        threading.Thread(target=self.thr_maintain_scaling_bounded_semaphore, daemon=True).start()

    def running_machines_max_reached(self) -> bool:
        """Return true if we've reached the maximum number of running machines."""
        return 0 < self.cfg.cuckoo.max_machines_count <= self.machinery.running_count()

    def scale_pool(self, machine: Machine) -> None:
        """For machinery backends that support auto-scaling, make sure that enough machines
        are spun up. For other types of machinery, this is basically a noop. This is called
        from the AnalysisManager (i.e. child) thread, so we use a lock to make sure that
        it doesn't get called multiple times simultaneously. We don't want to call it from
        the main thread as that would block the scheduler while machines are spun up.
        Note that the az machinery maintains its own thread to monitor to size of the pool.
        """
        with self.pool_scaling_lock:
            self.machinery.scale_pool(machine)

    def start_machine(self, machine: Machine) -> None:
        if (
            isinstance(self.machine_lock, ScalingBoundedSemaphore)
            and self.db.count_machines_running() <= self.machines_limit
            and self.machine_lock._value == 0
        ):
            self.machine_lock.release()
        with self.machine_lock:
            self.machinery.start(machine.label)

    def stop_machine(self, machine: Machine) -> None:
        self.machinery.stop(machine.label)

    def thr_maintain_scaling_bounded_semaphore(self) -> None:
        """Maintain the limit of the ScalingBoundedSemaphore if one is being used."""
        if not isinstance(self.machine_lock, ScalingBoundedSemaphore) or not self.cfg.cuckoo.scaling_semaphore_update_timer:
            return

        while True:
            with self.db.session.begin():
                # Here be dragons! Making these calls on the ScalingBoundedSemaphore is not
                # thread safe.
                self.machine_lock.update_limit(len(self.machinery.machines()))
                self.machine_lock.check_for_starvation(self.machinery.availables(include_reserved=True))
            time.sleep(self.cfg.cuckoo.scaling_semaphore_update_timer)
