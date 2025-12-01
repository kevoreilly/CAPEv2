# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import contextlib
import enum
import logging
import os
import queue
import signal
import sys
import threading
import time
from collections import defaultdict
from typing import DefaultDict, List, Optional, Tuple

from lib.cuckoo.common.cleaners_utils import free_space_monitor
from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooUnserviceableTaskError
from lib.cuckoo.common.utils import CATEGORIES_NEEDING_VM, load_categories
from lib.cuckoo.core.analysis_manager import AnalysisManager
from lib.cuckoo.core.database import TASK_FAILED_ANALYSIS, TASK_PENDING, Database, Machine, Task, _Database
from lib.cuckoo.core.machinery_manager import MachineryManager

log = logging.getLogger(__name__)


class LoopState(enum.IntEnum):
    """Enum that represents the state of the main scheduler loop."""

    RUNNING = 1
    PAUSED = 2
    STOPPING = 3
    INACTIVE = 4


class SchedulerCycleDelay(enum.IntEnum):
    SUCCESS = 0
    NO_PENDING_TASKS = 1
    MAX_MACHINES_RUNNING = 1
    SCHEDULER_PAUSED = 5
    FAILURE = 5
    LOW_DISK_SPACE = 30


class Scheduler:
    """Tasks Scheduler.

    This class is responsible for the main execution loop of the tool. It
    prepares the analysis machines and keep waiting and loading for new
    analysis tasks.
    Whenever a new task is available, it launches AnalysisManager which will
    take care of running the full analysis process and operating with the
    assigned analysis machine.
    """

    def __init__(self, maxcount=0):
        self.loop_state = LoopState.INACTIVE
        self.cfg = Config()
        self.db: _Database = Database()
        self.max_analysis_count: int = maxcount or self.cfg.cuckoo.max_analysis_count
        self.analysis_threads_lock = threading.Lock()
        self.total_analysis_count: int = 0
        self.analysis_threads: List[AnalysisManager] = []
        self.analyzing_categories, categories_need_VM = load_categories()
        self.machinery_manager = MachineryManager() if categories_need_VM else None
        if self.cfg.cuckoo.get("task_timeout", False):
            self.next_timeout_time = time.time() + self.cfg.cuckoo.get("task_timeout_scan_interval", 30)
        log.info("Creating scheduler with max_analysis_count=%s", self.max_analysis_count or "unlimited")

    @property
    def active_analysis_count(self) -> int:
        with self.analysis_threads_lock:
            return len(self.analysis_threads)

    def analysis_finished(self, analysis_manager: AnalysisManager):
        with self.analysis_threads_lock:
            try:
                self.analysis_threads.remove(analysis_manager)
            except ValueError:
                pass

    def do_main_loop_work(self, error_queue: queue.Queue) -> SchedulerCycleDelay:
        """Return the number of seconds to sleep after returning."""
        if self.loop_state == LoopState.STOPPING:
            # This blocks the main loop until the analyses are finished.
            self.wait_for_running_analyses_to_finish()
            self.loop_state = LoopState.INACTIVE
            return SchedulerCycleDelay.SUCCESS

        if self.loop_state == LoopState.PAUSED:
            log.debug("scheduler is paused, send '%s' to process %d to resume", signal.SIGUSR2, os.getpid())
            return SchedulerCycleDelay.SCHEDULER_PAUSED

        if 0 < self.max_analysis_count <= self.total_analysis_count:
            log.info("Maximum analysis count has been reached, shutting down.")
            self.stop()
            return SchedulerCycleDelay.SUCCESS

        if self.is_short_on_disk_space():
            return SchedulerCycleDelay.LOW_DISK_SPACE

        if self.cfg.cuckoo.get("task_timeout", False):
            if self.next_timeout_time < time.time():
                self.next_timeout_time = time.time() + self.cfg.cuckoo.get("task_timeout_scan_interval", 30)
                with self.db.session.begin():
                    self.db.clean_timed_out_tasks(self.cfg.cuckoo.get("task_pending_timeout", 0))

        analysis_manager: Optional[AnalysisManager] = None
        with self.db.session.begin():
            max_machines_reached = False
            if self.machinery_manager and self.machinery_manager.running_machines_max_reached():
                if not self.cfg.cuckoo.allow_static:
                    return SchedulerCycleDelay.MAX_MACHINES_RUNNING
                max_machines_reached = True

            try:
                task, machine = self.find_next_serviceable_task(max_machines_reached)
            except Exception:
                log.exception("Failed to find next serviceable task")
                # Explicitly call rollback since we're not re-raising the exception and letting the
                # begin() context manager handle rolling back the transaction.
                self.db.session.rollback()
                return SchedulerCycleDelay.FAILURE

            if task is None:
                # There are no pending tasks so try again in 1 second.
                return SchedulerCycleDelay.NO_PENDING_TASKS

            log.info("Task #%s: Processing task", task.id)
            self.total_analysis_count += 1
            analysis_manager = AnalysisManager(
                task,
                machine=machine,
                machinery_manager=self.machinery_manager,
                error_queue=error_queue,
                done_callback=self.analysis_finished,
            )
            analysis_manager.prepare_task_and_machine_to_start()
        self.db.session.expunge_all()

        with self.analysis_threads_lock:
            self.analysis_threads.append(analysis_manager)
        analysis_manager.start()

        return SchedulerCycleDelay.SUCCESS

    def find_next_serviceable_task(self, max_machines_reached: bool) -> Tuple[Optional[Task], Optional[Machine]]:
        task: Optional[Task] = None
        machine: Optional[Machine] = None

        if self.machinery_manager and not max_machines_reached:
            task, machine = self.find_pending_task_to_service()
        else:
            task = self.find_pending_task_not_requiring_machinery()

        return task, machine

    def find_pending_task_not_requiring_machinery(self) -> Optional[Task]:
        task: Optional[Task] = None
        tasks = self.db.list_tasks(
            category=[category for category in self.analyzing_categories if category not in CATEGORIES_NEEDING_VM],
            status=TASK_PENDING,
            order_by=(Task.priority.desc(), Task.added_on),
            options_not_like="node=",
            limit=1,
            for_update=True,
        )
        if tasks:
            task = tasks[0]
        return task

    def find_pending_task_to_service(self) -> Tuple[Optional[Task], Optional[Machine]]:
        # This function must only be called when we have the ability to use machinery.
        assert self.machinery_manager

        task: Optional[Task] = None
        machine: Optional[Machine] = None
        # Cache available machine stats to avoid repeated DB queries within the loop.
        available_tags_stats = self.get_available_machine_stats()

        # Get the list of all pending tasks in the order that they should be processed.
        for task_candidate in self.db.list_tasks(
            status=TASK_PENDING,
            order_by=(Task.priority.desc(), Task.added_on),
            options_not_like="node=",
            for_update=True,
        ):
            if task_candidate.category not in CATEGORIES_NEEDING_VM:
                # This task can definitely be processed because it doesn't need a machine.
                task = task_candidate
                break

            try:
                machine = self.machinery_manager.find_machine_to_service_task(task_candidate)
            except CuckooUnserviceableTaskError:
                requested_tags = ", ".join(tag.name for tag in task_candidate.tags)
                log_message = (
                    "Task #{task_id}: {status} unserviceable task because no matching machine could be found. "
                    "Requested tags: '{tags}'. Available machine tags: {available}. "
                    "Please check your machinery configuration."
                )

                if self.cfg.cuckoo.fail_unserviceable:
                    log.info(
                        log_message.format(
                            task_id=task_candidate.id,
                            status="Failing",
                            tags=requested_tags,
                            available=available_tags_stats,
                        )
                    )
                    self.db.set_status(task_candidate.id, TASK_FAILED_ANALYSIS)
                else:
                    log.info(
                        log_message.format(
                            task_id=task_candidate.id,
                            status="Unserviceable",
                            tags=requested_tags,
                            available=available_tags_stats,
                        )
                    )
                continue

            if machine:
                task = task_candidate
                break

        return task, machine

    def get_available_machine_stats(self) -> DefaultDict[str, int]:
        available_machine_stats = defaultdict(int)
        for machine in self.db.get_available_machines():
            for tag in machine.tags:
                if tag:
                    available_machine_stats[tag.name] += 1
            if machine.platform:
                available_machine_stats[machine.platform] += 1

        return available_machine_stats

    def get_locked_machine_stats(self) -> DefaultDict[str, int]:
        locked_machine_stats = defaultdict(int)
        for machine in self.db.list_machines(locked=True):
            for tag in machine.tags:
                if tag:
                    locked_machine_stats[tag.name] += 1
            if machine.platform:
                locked_machine_stats[machine.platform] += 1

        return locked_machine_stats

    def get_pending_task_stats(self) -> DefaultDict[str, int]:
        pending_task_stats = defaultdict(int)
        for task in self.db.list_tasks(status=TASK_PENDING):
            for tag in task.tags:
                if tag:
                    pending_task_stats[tag.name] += 1
            if task.platform:
                pending_task_stats[task.platform] += 1
            if task.machine:
                pending_task_stats[task.machine] += 1

        return pending_task_stats

    def is_short_on_disk_space(self):
        """If not enough free disk space is available, then we print an
        error message and wait another round. This check is ignored
        when the freespace configuration variable is set to zero.
        """
        if not self.cfg.cuckoo.freespace:
            return False

        # Resolve the full base path to the analysis folder, just in
        # case somebody decides to make a symbolic link out of it.
        dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")
        free_space_monitor(dir_path, analysis=True)

    @contextlib.contextmanager
    def loop_signals(self):
        signals_to_handle = (signal.SIGHUP, signal.SIGTERM, signal.SIGUSR1, signal.SIGUSR2)
        for sig in signals_to_handle:
            signal.signal(sig, self.signal_handler)
        try:
            yield
        finally:
            for sig in signals_to_handle:
                signal.signal(sig, signal.SIG_DFL)

    def shutdown_machinery(self):
        """Shutdown machine manager (used to kill machines that still alive)."""
        if self.machinery_manager:
            with self.db.session.begin():
                self.machinery_manager.machinery.shutdown()

    def signal_handler(self, signum, frame):
        """Scheduler signal handler"""
        sig = signal.Signals(signum)
        if sig in (signal.SIGHUP, signal.SIGTERM):
            log.info("received signal '%s', waiting for remaining analysis to finish before stopping", sig.name)
            self.stop()
        elif sig == signal.SIGUSR1:
            log.info("received signal '%s', pausing new detonations, running detonations will continue until completion", sig.name)
            self.loop_state = LoopState.PAUSED
            if self.cfg.cuckoo.ignore_signals:
                sys.exit()
        elif sig == signal.SIGUSR2:
            log.info("received signal '%s', resuming detonations", sig.name)
            self.loop_state = LoopState.RUNNING
        else:
            log.info("received signal '%s', nothing to do", sig.name)

    def start(self):
        """Start scheduler."""
        if self.machinery_manager:
            with self.db.session.begin():
                self.machinery_manager.initialize_machinery()

        # Message queue with threads to transmit exceptions (used as IPC).
        error_queue = queue.Queue()

        # Start the logger which grabs database information
        if self.cfg.cuckoo.periodic_log:
            threading.Thread(target=self.thr_periodic_log, name="periodic_log", daemon=True).start()

        with self.loop_signals():
            log.info("Waiting for analysis tasks")
            self.loop_state = LoopState.RUNNING
            try:
                while self.loop_state in (LoopState.RUNNING, LoopState.PAUSED, LoopState.STOPPING):
                    sleep_time = self.do_main_loop_work(error_queue)
                    time.sleep(sleep_time)
                    try:
                        raise error_queue.get(block=False)
                    except queue.Empty:
                        pass
            finally:
                self.loop_state = LoopState.INACTIVE

    def stop(self):
        """Set loop state to stopping."""
        self.loop_state = LoopState.STOPPING
        if self.cfg.cuckoo.ignore_signals:
            sys.exit()

    def thr_periodic_log(self, oneshot=False):
        # Ordinarily, this is the entry-point for a child thread. The oneshot parameter makes
        # it easier for testing.
        if not log.isEnabledFor(logging.DEBUG):
            # The only purpose of this function is to log a debug message, so if debug
            # logging is disabled, don't bother making all the database queries every 10
            # seconds--just return.
            return

        while True:
            # Since we know we'll be logging the resulting message, just use f-strings
            # because they're faster and easier to read than using %s/%d and params to
            # log.debug().
            msgs = [f"# Active analysis: {self.active_analysis_count}"]

            with self.db.session.begin():
                pending_task_count = self.db.count_tasks(status=TASK_PENDING)
                pending_task_stats = self.get_pending_task_stats()
                msgs.extend(
                    (
                        f"# Pending Tasks: {pending_task_count}",
                        f"# Specific Pending Tasks: {dict(pending_task_stats)}",
                    )
                )
                if self.machinery_manager:
                    available_machine_count = self.db.count_machines_available()
                    available_machine_stats = self.get_available_machine_stats()
                    locked_machine_count = len(self.db.list_machines(locked=True))
                    locked_machine_stats = self.get_locked_machine_stats()
                    total_machine_count = len(self.db.list_machines())
                    msgs.extend(
                        (
                            f"# Available Machines: {available_machine_count}",
                            f"# Available Specific Machines: {dict(available_machine_stats)}",
                            f"# Locked Machines: {locked_machine_count}",
                            f"# Specific Locked Machines: {dict(locked_machine_stats)}",
                            f"# Total Machines: {total_machine_count}",
                        )
                    )
                    if self.cfg.cuckoo.scaling_semaphore:
                        lock_value = (
                            f"{self.machinery_manager.machine_lock._value}/{self.machinery_manager.machine_lock._limit_value}"
                        )
                        msgs.append(f"# Lock value: {lock_value}")
            log.debug("; ".join(msgs))

            if oneshot:
                break

            time.sleep(10)

    def wait_for_running_analyses_to_finish(self) -> None:
        log.info("Waiting for running analyses to finish.")
        while self.analysis_threads:
            thread = self.analysis_threads.pop()
            log.debug("Waiting for analysis thread (%r)", thread)
            thread.join()
