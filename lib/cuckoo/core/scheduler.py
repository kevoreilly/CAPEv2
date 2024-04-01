# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import enum
import logging
import os
import queue
import signal
import threading
import time
from collections import defaultdict
from time import monotonic as _time

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooCriticalError, CuckooMachineError
from lib.cuckoo.common.utils import free_space_monitor, load_categories
from lib.cuckoo.core.analysis_manager import AnalysisManager
from lib.cuckoo.core.database import TASK_FAILED_ANALYSIS, TASK_PENDING, Database, Task
from lib.cuckoo.core.plugins import list_plugins
from lib.cuckoo.core.rooter import rooter, vpns

log = logging.getLogger(__name__)

machinery = None
machine_lock = None
routing = Config("routing")

active_analysis_count = 0
active_analysis_count_lock = threading.Lock()


class LoopState(enum.IntEnum):
    """Enum that represents the state of the main scheduler loop."""

    RUNNING = 1
    PAUSED = 2
    STOPPING = 3
    INACTIVE = 4


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
        if value < self._upper_limit and value > 0:
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


class CuckooDeadMachine(Exception):
    """Exception thrown when a machine turns dead.

    When this exception has been thrown, the analysis task will start again,
    and will try to use another machine, when available.
    """

    pass


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
        self.loop_state = LoopState.INACTIVE
        self.cfg = Config()
        self.db = Database()
        self.maxcount = maxcount
        self.total_analysis_count = 0
        self.analyzing_categories, self.categories_need_VM = load_categories()
        self.analysis_threads = []

    def signal_handler(self, signum, frame):
        """Scheduler signal handler"""
        sig = signal.Signals(signum)
        if sig in (signal.SIGHUP, signal.SIGTERM):
            log.info("received signal '%s', waiting for remaining analysis to finish before stopping", sig.name)
            self.loop_state = LoopState.STOPPING
        elif sig == signal.SIGUSR1:
            log.info("received signal '%s', pausing new detonations, running detonations will continue until completion", sig.name)
            self.loop_state = LoopState.PAUSED
        elif sig == signal.SIGUSR2:
            log.info("received signal '%s', resuming detonations", sig.name)
            self.loop_state = LoopState.RUNNING
        else:
            log.info("received signal '%s', nothing to do", sig.name)

    def initialize(self):
        """Initialize the machine manager."""
        global machinery, machine_lock

        machinery_name = self.cfg.cuckoo.machinery
        if not self.categories_need_VM:
            return

        # Get registered class name. Only one machine manager is imported,
        # therefore there should be only one class in the list.
        plugin = list_plugins("machinery")[0]
        # Initialize the machine manager.
        machinery = plugin()

        # Provide a dictionary with the configuration options to the
        # machine manager instance.
        machinery.set_options(Config(machinery_name))

        # Initialize the machine manager.
        try:
            machinery.initialize(machinery_name)
        except CuckooMachineError as e:
            raise CuckooCriticalError(f"Error initializing machines: {e}")
        # If the user wants to use the scaling bounded semaphore, check what machinery is specified, and then
        # grab the required configuration key for setting the upper limit
        if self.cfg.cuckoo.scaling_semaphore:
            machinery_opts = machinery.options.get(machinery_name)
            if machinery_name == "az":
                machines_limit = machinery_opts.get("total_machines_limit")
            elif machinery_name == "aws":
                machines_limit = machinery_opts.get("dynamic_machines_limit")
        # You set this value if you are using a machinery that is NOT auto-scaling
        max_vmstartup_count = self.cfg.cuckoo.max_vmstartup_count
        if max_vmstartup_count:
            # The BoundedSemaphore is used to prevent CPU starvation when starting up multiple VMs
            machine_lock = threading.BoundedSemaphore(max_vmstartup_count)
        # You set this value if you are using a machinery that IS auto-scaling
        elif self.cfg.cuckoo.scaling_semaphore and machines_limit:
            # The ScalingBoundedSemaphore is used to keep feeding available machines from the pending tasks queue
            machine_lock = ScalingBoundedSemaphore(value=len(machinery.machines()), upper_limit=machines_limit)
        else:
            machine_lock = threading.Lock()

        log.info(
            'Using "%s" machine manager with max_analysis_count=%d, max_machines_count=%d, and max_vmstartup_count=%d',
            machinery_name,
            self.cfg.cuckoo.max_analysis_count,
            self.cfg.cuckoo.max_machines_count,
            self.cfg.cuckoo.max_vmstartup_count,
        )

        # At this point all the available machines should have been identified
        # and added to the list. If none were found, Cuckoo needs to abort the
        # execution.

        if not len(machinery.machines()):
            raise CuckooCriticalError("No machines available")
        else:
            log.info("Loaded %d machine/s", len(machinery.machines()))

        if len(machinery.machines()) > 1 and self.db.engine.name == "sqlite":
            log.warning(
                "As you've configured CAPE to execute parallelanalyses, we recommend you to switch to a PostgreSQL database as SQLite might cause some issues"
            )

        # Drop all existing packet forwarding rules for each VM. Just in case
        # Cuckoo was terminated for some reason and various forwarding rules
        # have thus not been dropped yet.
        for machine in machinery.machines():
            if not machine.interface:
                log.info(
                    "Unable to determine the network interface for VM with name %s, Cuckoo will not be able to give it "
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

    def stop(self):
        """Set loop state to stopping."""
        self.loop_state = LoopState.STOPPING

    def shutdown_machinery(self):
        """Shutdown machine manager (used to kill machines that still alive)."""
        if self.categories_need_VM:
            machinery.shutdown()

    def start(self):
        """Start scheduler."""
        with self.db.session.begin():
            self.initialize()

        log.info("Waiting for analysis tasks")

        # Handle interrupts
        for _signal in [signal.SIGHUP, signal.SIGTERM, signal.SIGUSR1, signal.SIGUSR2]:
            signal.signal(_signal, self.signal_handler)

        # Message queue with threads to transmit exceptions (used as IPC).
        errors = queue.Queue()

        # Command-line overrides the configuration file.
        if self.maxcount is None:
            self.maxcount = self.cfg.cuckoo.max_analysis_count

        # Start the logger which grabs database information
        if self.cfg.cuckoo.periodic_log:
            self._thr_periodic_log()
        # Update timer for semaphore limit value if enabled
        if self.cfg.cuckoo.scaling_semaphore and not self.cfg.cuckoo.max_vmstartup_count:
            # Note that this variable only exists under these conditions
            scaling_semaphore_timer = time.time()

        if self.cfg.cuckoo.batch_scheduling:
            max_batch_scheduling_count = (
                self.cfg.cuckoo.max_batch_count if self.cfg.cuckoo.max_batch_count and self.cfg.cuckoo.max_batch_count > 1 else 5
            )
        # This loop runs forever.

        self.loop_state = LoopState.RUNNING
        while self.loop_state in (LoopState.RUNNING, LoopState.PAUSED, LoopState.STOPPING):
            # Avoid high CPU utilization due to a tight loop under certain conditions
            time.sleep(0.5)

            if self.loop_state == LoopState.STOPPING:
                # Wait for analyses to finish before stopping
                while self.analysis_threads:
                    thread = self.analysis_threads.pop()
                    log.debug("Waiting for analysis PID %d", thread.native_id)
                    thread.join()
                break
            if self.loop_state == LoopState.PAUSED:
                log.debug("scheduler is paused, send '%s' to process %d to resume", signal.SIGUSR2, os.getpid())
                time.sleep(5)
                continue
            # Update scaling bounded semaphore limit value, if enabled, based on the number of machines
            # Wait until the machine lock is not locked. This is only the case
            # when all machines are fully running, rather than "about to start"
            # or "still busy starting". This way we won't have race conditions
            # with finding out there are no available machines in the analysis
            # manager or having two analyses pick the same machine.

            # Update semaphore limit value if enabled based on the number of machines
            if self.cfg.cuckoo.scaling_semaphore and not self.cfg.cuckoo.max_vmstartup_count:
                # Every x seconds, update the semaphore limit. This requires a database call to machinery.availables(),
                # hence waiting a bit between calls
                if scaling_semaphore_timer + int(self.cfg.cuckoo.scaling_semaphore_update_timer) < time.time():
                    machine_lock.update_limit(len(machinery.machines()))
                    # Prevent full starvation, very unlikely to ever happen.
                    machine_lock.check_for_starvation(machinery.availables())
                    # Note that this variable only exists under these conditions
                    scaling_semaphore_timer = time.time()

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

            with self.db.session.begin():
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
                        log.info("Maximum analysis count has been reached, shutting down.")
                        self.stop()
                else:
                    if self.cfg.cuckoo.batch_scheduling:
                        tasks_to_create = []
                        if self.categories_need_VM:
                            # First things first, are there pending tasks?
                            if not self.db.count_tasks(status=TASK_PENDING):
                                continue
                            # There are? Great, let's get them, ordered by priority and then oldest to newest
                            tasks_with_relevant_machine_available = []
                            for task in self.db.list_tasks(
                                status=TASK_PENDING, order_by=(Task.priority.desc(), Task.added_on), options_not_like="node="
                            ):
                                # Can this task ever be serviced?
                                if not self.db.is_serviceable(task):
                                    if self.cfg.cuckoo.fail_unserviceable:
                                        log.info("Task #%s: Failing unserviceable task", task.id)
                                        self.db.set_status(task.id, TASK_FAILED_ANALYSIS)
                                        continue
                                    log.info("Task #%s: Unserviceable task", task.id)
                                if self.db.is_relevant_machine_available(task=task, set_status=False):
                                    tasks_with_relevant_machine_available.append(task)
                            # The batching number is the number of tasks that will be considered to mapping to machines for starting
                            # Max_batch_scheduling_count is referring to the batch_scheduling config however this number
                            # is the maximum and capped for each usage by the number of locks available which refer to
                            # the number of expected available machines.
                            batching_number = (
                                max_batch_scheduling_count
                                if machine_lock._value > max_batch_scheduling_count
                                else machine_lock._value
                            )
                            if len(tasks_with_relevant_machine_available) > batching_number:
                                tasks_with_relevant_machine_available = tasks_with_relevant_machine_available[:batching_number]
                            tasks_to_create = self.db.map_tasks_to_available_machines(tasks_with_relevant_machine_available)
                        else:
                            tasks_to_create = []
                            while True:
                                task = self.db.fetch_task(self.analyzing_categories)
                                if not task:
                                    break
                                else:
                                    tasks_to_create.append(task)
                        for task in tasks_to_create:
                            task = self.db.view_task(task.id)
                            log.debug("Task #%s: Processing task", task.id)
                            self.total_analysis_count += 1
                            # Initialize and start the analysis manager.
                            analysis = AnalysisManager(task, errors)
                            analysis.daemon = True
                            analysis.start()
                            self.analysis_threads.append(analysis)
                        # We only want to keep track of active threads
                        self.analysis_threads = [t for t in self.analysis_threads if t.is_alive()]
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
                            # Make sure that changes to the status of the task is flushed to the
                            # database before passing the object off to the child thread.
                            self.db.session.flush()
                            self.db.session.expunge_all()
                            log.debug("Task #%s: Processing task", task.id)
                            self.total_analysis_count += 1
                            # Initialize and start the analysis manager.
                            analysis = AnalysisManager(task, errors)
                            analysis.daemon = True
                            analysis.start()
                            self.analysis_threads.append(analysis)
                        # We only want to keep track of active threads
                        self.analysis_threads = [t for t in self.analysis_threads if t.is_alive()]

            # Deal with errors.
            try:
                raise errors.get(block=False)
            except queue.Empty:
                pass
        self.loop_state = LoopState.INACTIVE

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
        if self.cfg.cuckoo.scaling_semaphore:
            number_of_machine_scheduled = machinery.get_machines_scheduled()
            log.debug(
                "# Pending Tasks: %d; # Specific Pending Tasks: %s; # Available Machines: %d; # Available Specific Machines: %s; # Locked Machines: %d; # Specific Locked Machines: %s; # Total Machines: %d; Lock value: %d/%d; # Active analysis: %d; # Machines scheduled: %d",
                self.db.count_tasks(status=TASK_PENDING),
                dict(specific_pending_task_counts),
                self.db.count_machines_available(),
                dict(specific_available_machine_counts),
                len(self.db.list_machines(locked=True)),
                dict(specific_locked_machine_counts),
                len(self.db.list_machines()),
                machine_lock._value,
                machine_lock._limit_value,
                active_analysis_count,
                number_of_machine_scheduled,
            )
        else:
            log.debug(
                "# Pending Tasks: %d; # Specific Pending Tasks: %s; # Available Machines: %d; # Available Specific Machines: %s; # Locked Machines: %d; # Specific Locked Machines: %s; # Total Machines: %d",
                self.db.count_tasks(status=TASK_PENDING),
                dict(specific_pending_task_counts),
                self.db.count_machines_available(),
                dict(specific_available_machine_counts),
                len(self.db.list_machines(locked=True)),
                dict(specific_locked_machine_counts),
                len(self.db.list_machines()),
            )
        thr = threading.Timer(10, self._thr_periodic_log)
        thr.daemon = True
        thr.start()
