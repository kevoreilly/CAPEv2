"""Pebble-pool engine — preserved as the A/B control. Mirrors the historical
autoprocess loop, parameterized behind the engine seam. max_tasks defaults to 0
(no recycle): worker recycling deadlocks in multiprocessing _exit_function while
joining the nested extractor pool — see the redesign spec."""
import logging
import os
import time

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
        Max tasks per child process (pebble ``max_tasks``). Default 0 = no
        recycling — prevents the multiprocessing ``_exit_function`` / pool-join
        deadlock seen with worker recycling in production.
    max_count : int
        Exit after scheduling this many tasks. 0 (default) = run forever,
        matching ``cfg.cuckoo.max_analysis_count == 0`` production default.
    """

    def __init__(self, task_fn, worker_init, source, parallel, timeout,
                 max_tasks=0, max_count=0):
        super().__init__(task_fn, worker_init, source, parallel, timeout)
        self.max_tasks = max_tasks
        self.max_count = max_count
        self._pending = {}  # future -> task_id

    def _done(self, future):
        """Pebble done-callback: fires in the pool's internal thread."""
        task_id = self._pending.pop(future, None)
        try:
            future.result()
            log.info("Reports generation completed for Task #%s", task_id)
        except TimeoutError as error:
            log.error("[%s] Processing timeout: %s. Function: %s", task_id, error, error.args[1] if len(error.args) > 1 else "")
            if task_id is not None:
                self.source.mark_failed(task_id)
        except (pebble.ProcessExpired, Exception) as error:
            log.exception("[%s] Exception when processing task: %s", task_id, error)
            if task_id is not None:
                self.source.mark_failed(task_id)

    def run(self):
        """Drive the pebble pool loop, mirroring the historical autoprocess body."""
        from lib.cuckoo.common.config import Config
        from lib.cuckoo.common.constants import CUCKOO_ROOT

        cfg = Config()
        count = 0

        with pebble.ProcessPool(max_workers=self.parallel, max_tasks=self.max_tasks,
                                initializer=self.worker_init) as pool:
            while not self.max_count or count < self.max_count:
                # If not enough free disk space is available, block until space
                # is reclaimed.  Mirrors the original autoprocess freespace check
                # (only when cfg.cuckoo.freespace_processing is non-zero).
                if cfg.cuckoo.freespace_processing:
                    from lib.cuckoo.common.cleaners_utils import free_space_monitor
                    dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")
                    free_space_monitor(dir_path, processing=True)

                # If the pool is saturated, wait before polling again.
                if len(self._pending) >= self.parallel:
                    time.sleep(1)
                    continue

                tasks = self.source.fetch(limit=self.parallel,
                                          exclude_ids=set(self._pending.values()))
                added = False
                # Schedule at most one task per iteration to avoid overshooting
                # max_count (same rationale as the original "For loop to add
                # only one, nice." comment).
                for task in tasks:
                    log.info("Processing analysis data for Task #%d", task.id)
                    future = pool.schedule(self.task_fn, args=(task,), timeout=self.timeout)
                    self._pending[future] = task.id
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
            while self._pending:
                time.sleep(0.2)
