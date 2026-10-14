"""Pebble-pool engine — preserved as the A/B control. Mirrors the historical
autoprocess loop, parameterized behind the engine seam."""
import logging
import os
import time
import threading

import pebble
from concurrent.futures import TimeoutError

from lib.cuckoo.core.processing_engine.base import ProcessingEngine

log = logging.getLogger(__name__)


class PebbleEngine(ProcessingEngine):
    """Pebble-pool processing engine.

    Parameters
    ----------
    task_fn : callable
        Called in a worker process for each task: ``task_fn(task) -> None``.
    worker_init : callable
        Called once per worker process at pool initialisation.
    source : TaskSource
        Supplies tasks to run and records failure status.
    parallel : int
        Maximum number of concurrent worker processes.
    timeout : int
        Per-task timeout in seconds (passed to pebble).
    max_tasks : int
        Max tasks per child process (pebble ``max_tasks``). Defaults to 0
        (no recycling) at the constructor level; ``utils/process.py`` overrides
        this with ``maxtasksperchild`` from ``processing.conf`` (default 7).
    max_count : int
        Exit after scheduling this many tasks. 0 (default) = run forever,
        matching ``cfg.cuckoo.max_analysis_count == 0`` production default.
    """

    def __init__(self, task_fn, worker_init, source, parallel, timeout,
                 max_tasks=0, max_count=0, stall_grace=300):
        super().__init__(task_fn, worker_init, source, parallel, timeout)
        self.max_tasks = max_tasks
        self.max_count = max_count
        self.stall_grace = stall_grace
        self._lock = threading.Lock()
        self._pending = {}  # future -> task_id
        self._scheduled_at = {}  # future -> time.monotonic() when scheduled

    def _safe_mark_failed(self, task_id):
        """Record task failure without letting a transient DB error kill the caller."""
        if task_id is None:
            return
        try:
            self.source.mark_failed(task_id)
        except Exception as db_error:
            log.exception("[%s] Failed to mark task as FAILED_PROCESSING: %s", task_id, db_error)

    def _done(self, future):
        """Pebble done-callback: fires in the pool's internal thread."""
        with self._lock:
            task_id = self._pending.pop(future, None)
            self._scheduled_at.pop(future, None)

        try:
            future.result()
            log.info("Reports generation completed for Task #%s", task_id)
        except TimeoutError as error:
            log.error("[%s] Processing timeout: %s. Function: %s", task_id, error, error.args[1] if len(error.args) > 1 else "")
            self._safe_mark_failed(task_id)
        except BaseException as error:
            # BaseException, not Exception: anything escaping this callback
            # propagates into pebble's message-manager thread and kills it.
            log.exception("[%s] Exception when processing task: %s", task_id, error)
            self._safe_mark_failed(task_id)

    def _reap_stalled(self):
        """Fail tasks that were scheduled but never ran.

        pebble only applies a task's timeout once that task is RUNNING. If the
        worker dies before picking it up, pebble cannot associate the dead
        worker with any task, so the future never resolves: the task never
        runs, never times out, is never marked failed, and stays in
        ``_pending`` forever. Both the scheduling loop (via the saturation
        check) and the drain loop then spin indefinitely.

        Anything still pending past ``timeout + stall_grace`` is therefore
        presumed dead and failed explicitly."""
        if not self.stall_grace:
            return

        with self._lock:
            if not self._pending:
                return
            pending_keys = list(self._pending.keys())

        deadline = self.timeout + self.stall_grace
        now = time.monotonic()
        for future in pending_keys:
            with self._lock:
                if future not in self._pending:
                    continue
                if now - self._scheduled_at.get(future, now) < deadline:
                    continue
                task_id = self._pending.pop(future, None)
                self._scheduled_at.pop(future, None)

            log.error(
                "[%s] Task never ran (worker died before pickup?); marking it failed after %ss",
                task_id, deadline,
            )
            try:
                future.cancel()
            except Exception:
                pass
            self._safe_mark_failed(task_id)

    def run(self):
        """Drive the pebble pool loop, mirroring the historical autoprocess body."""
        from lib.cuckoo.common.config import Config
        from lib.cuckoo.common.constants import CUCKOO_ROOT

        cfg = Config()
        count = 0

        with pebble.ProcessPool(max_workers=self.parallel, max_tasks=self.max_tasks,
                                initializer=self.worker_init) as pool:
            while not self.max_count or count < self.max_count:
                # Fail anything that was scheduled but never picked up, so a
                # dead worker can't wedge the saturation check below forever.
                self._reap_stalled()

                # If not enough free disk space is available, block until space
                # is reclaimed.  Mirrors the original autoprocess freespace check
                # (only when cfg.cuckoo.freespace_processing is non-zero).
                if cfg.cuckoo.freespace_processing:
                    from lib.cuckoo.common.cleaners_utils import free_space_monitor
                    dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")
                    free_space_monitor(dir_path, processing=True)

                # If the pool is saturated, wait before polling again.
                with self._lock:
                    pending_count = len(self._pending)
                if pending_count >= self.parallel:
                    time.sleep(1)
                    continue

                with self._lock:
                    exclude = set(self._pending.values())
                try:
                    tasks = self.source.fetch(limit=self.parallel, exclude_ids=exclude)
                except Exception as db_error:
                    log.error("Database connection error during task fetch: %s. Retrying in 10s...", db_error)
                    time.sleep(10)
                    continue
                added = False
                # Schedule at most one task per iteration to avoid overshooting
                # max_count (same rationale as the original "For loop to add
                # only one, nice." comment).
                for task in tasks:
                    log.info("Processing analysis data for Task #%d", task.id)
                    future = pool.schedule(self.task_fn, args=(task,), timeout=self.timeout)
                    with self._lock:
                        self._pending[future] = task.id
                        self._scheduled_at[future] = time.monotonic()
                    future.add_done_callback(self._done)
                    count += 1
                    added = True
                    break

                if not added and not self.max_count:
                    # Nothing ready; avoid busy-wait in production.
                    time.sleep(5)
                if not added and self.max_count:
                    # We've exhausted available tasks and we have a fixed
                    # max_count limit — break out so the drain below runs.
                    break

            # Drain: wait for all in-flight tasks to finish before returning.
            while True:
                with self._lock:
                    pending_exists = bool(self._pending)
                if not pending_exists:
                    break
                self._reap_stalled()
                time.sleep(0.2)
