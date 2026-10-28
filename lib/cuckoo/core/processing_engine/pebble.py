"""Pebble-pool engine — preserved as the A/B control. Mirrors the historical
autoprocess loop, parameterized behind the engine seam."""
import logging
import multiprocessing
import os
import threading
import time
from concurrent.futures import CancelledError, TimeoutError
from concurrent.futures.process import BrokenProcessPool

import pebble

try:
    from pebble.pool.base_pool import PoolStatus
except ImportError:
    PoolStatus = None

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
    stall_grace : int
        Grace period in seconds after timeout (for running tasks) or since
        scheduling (for tasks not yet picked up by a worker) before the task
        is reaped.
    join_timeout : int
        Seconds to wait for graceful pool drain on normal teardown before
        escalating to force-stop (defaults to 60).
    stop_join_timeout : int
        Seconds to wait after ``pool.stop()`` for the OS to reap workers
        (defaults to 5).
    """

    def __init__(self, task_fn, worker_init, source, parallel, timeout,
                 max_tasks=0, max_count=0, stall_grace=300,
                 join_timeout=60, stop_join_timeout=5):
        super().__init__(task_fn, worker_init, source, parallel, timeout)
        self.max_tasks = max_tasks
        self.max_count = max_count
        self.stall_grace = stall_grace
        self.join_timeout = join_timeout
        self.stop_join_timeout = stop_join_timeout
        self._lock = threading.Lock()
        self._wake = threading.Event()
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
            self._wake.set()

        if task_id is None or future.cancelled():
            return

        try:
            future.result()
            log.info("Reports generation completed for Task #%s", task_id)
        except CancelledError:
            return
        except TimeoutError as error:
            fn_name = getattr(getattr(self.task_fn, "func", self.task_fn), "__name__", self.task_fn)
            log.error("[%s] Processing timeout: %s. Function: %s", task_id, error, fn_name)
            self._safe_mark_failed(task_id)
        except BaseException as error:
            # BaseException, not Exception: anything escaping this callback
            # propagates into pebble's message-manager thread and kills it.
            log.exception("[%s] Exception when processing task: %s", task_id, error)
            self._safe_mark_failed(task_id)

    def _reap_stalled(self):
        """Fail tasks that were scheduled but never ran or stalled past deadline.

        Two-tier stall deadline:
        - If the task is still waiting for worker pickup (``not future.running()``),
          reap after ``stall_grace`` seconds without waiting for ``timeout``.
        - If the task is running (``future.running()``), reap after
          ``timeout + stall_grace`` seconds as a safety net if pebble's own
          timeout thread or worker-expiration tracking misses an orphaned task.
        """
        if not self.stall_grace:
            return

        with self._lock:
            if not self._pending:
                return
            pending_keys = list(self._pending.keys())

        now = time.monotonic()
        for future in pending_keys:
            try:
                is_running = future.running()
            except Exception:
                is_running = False

            deadline = (self.timeout + self.stall_grace) if is_running else self.stall_grace

            with self._lock:
                if future not in self._pending:
                    continue
                if now - self._scheduled_at.get(future, now) < deadline:
                    continue
                task_id = self._pending.pop(future, None)
                self._scheduled_at.pop(future, None)
                self._wake.set()

            if is_running:
                log.error(
                    "[%s] Task stalled past timeout+grace (%ss); marking it failed",
                    task_id,
                    deadline,
                )
            else:
                log.error(
                    "[%s] Task never ran (worker died before pickup?); marking it failed after %ss",
                    task_id,
                    deadline,
                )
            try:
                future.cancel()
            except Exception:
                pass
            self._safe_mark_failed(task_id)

    def _new_pool(self):
        """Create a fresh fork-context pebble process pool."""
        ctx = multiprocessing.get_context("fork")
        return pebble.ProcessPool(
            max_workers=self.parallel,
            max_tasks=self.max_tasks,
            initializer=self.worker_init,
            context=ctx,
        )

    @staticmethod
    def _is_pool_healthy(pool):
        """Check whether the pool's management threads and status are healthy."""
        if pool is None:
            return False
        for attr in ("_task_scheduler_loop", "_pool_manager_loop", "_message_manager_loop"):
            loop = getattr(pool, attr, None)
            if loop is not None and not loop.is_alive():
                return False

        status = getattr(getattr(pool, "_context", None), "status", None)
        if PoolStatus is not None:
            if status == PoolStatus.ERROR:
                return False
            if hasattr(pool, "active") and status != PoolStatus.CREATED and not pool.active:
                return False
        elif status == 4:
            return False
        elif hasattr(pool, "active") and status is None:
            try:
                if not pool.active:
                    return False
            except Exception:
                return False

        return True

    def _teardown_pool(self, pool, force=False):
        """Close+join a pool with bounded waits, escalating to stop() on failure."""
        if pool is None:
            return
        try:
            if force or not self._is_pool_healthy(pool):
                try:
                    pool.stop()
                except Exception as stop_err:
                    log.debug("PebbleEngine: pool.stop() raised: %s", stop_err)
                try:
                    pool.join(timeout=self.stop_join_timeout)
                except Exception as join_err:
                    log.debug("PebbleEngine: pool.join() after stop raised: %s", join_err)
            else:
                try:
                    pool.close()
                    pool.join(timeout=self.join_timeout)
                except Exception as join_err:
                    log.warning(
                        "PebbleEngine: pool did not drain within %ss (%s); force-stopping",
                        self.join_timeout,
                        join_err,
                    )
                    try:
                        pool.stop()
                    except Exception as stop_err:
                        log.debug("PebbleEngine: pool.stop() raised: %s", stop_err)
                    try:
                        pool.join(timeout=self.stop_join_timeout)
                    except Exception as post_stop_err:
                        log.debug("PebbleEngine: pool.join() after stop raised: %s", post_stop_err)
        except Exception:
            log.debug("PebbleEngine: _teardown_pool raised", exc_info=True)

    def _fail_all_pending(self, reason):
        """Fail and cancel all currently pending tasks when a pool breaks."""
        with self._lock:
            items = list(self._pending.items())
            self._pending.clear()
            self._scheduled_at.clear()
            self._wake.set()

        for future, task_id in items:
            log.error("[%s] Pebble pool broken (%s); marking in-flight task failed", task_id, reason)
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
        pool = self._new_pool()

        try:
            while not self.max_count or count < self.max_count:
                # Fail anything that was scheduled but never picked up or stalled,
                # so a dead worker can't wedge the saturation check below forever.
                self._reap_stalled()

                if not self._is_pool_healthy(pool):
                    log.error("PebbleEngine: pool became unhealthy; recreating pool and failing in-flight tasks")
                    self._fail_all_pending("pool unhealthy")
                    self._teardown_pool(pool, force=True)
                    pool = self._new_pool()

                # If not enough free disk space is available, block until space
                # is reclaimed. Mirrors the original autoprocess freespace check
                # (only when cfg.cuckoo.freespace_processing is non-zero).
                if cfg.cuckoo.freespace_processing:
                    from lib.cuckoo.common.cleaners_utils import free_space_monitor
                    dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")
                    free_space_monitor(dir_path, processing=True)

                self._wake.clear()

                with self._lock:
                    pending_count = len(self._pending)
                    exclude = set(self._pending.values())

                free = self.parallel - pending_count
                if free <= 0:
                    self._wake.wait(timeout=1.0)
                    continue

                launchable = free if not self.max_count else min(free, self.max_count - count)
                try:
                    tasks = self.source.fetch(limit=launchable, exclude_ids=exclude)
                except Exception as db_error:
                    log.error("Database connection error during task fetch: %s. Retrying in 10s...", db_error)
                    self._wake.wait(timeout=10.0)
                    continue

                added = False
                pool_recreated = False
                for task in tasks[:launchable]:
                    try:
                        future = pool.schedule(self.task_fn, args=(task,), timeout=self.timeout)
                    except (RuntimeError, BrokenProcessPool) as pool_err:
                        log.error("PebbleEngine: pool.schedule failed (%s); recreating pool", pool_err)
                        self._fail_all_pending("schedule failed")
                        self._teardown_pool(pool, force=True)
                        pool = self._new_pool()
                        pool_recreated = True
                        break

                    log.info("Processing analysis data for Task #%d", task.id)
                    with self._lock:
                        self._pending[future] = task.id
                        self._scheduled_at[future] = time.monotonic()
                    future.add_done_callback(self._done)
                    count += 1
                    added = True
                    if self.max_count and count >= self.max_count:
                        break

                if pool_recreated:
                    continue
                if not added and not self.max_count:
                    # Nothing ready; avoid busy-wait in production.
                    self._wake.wait(timeout=5.0)
                if not added and self.max_count:
                    # We've exhausted available tasks and we have a fixed
                    # max_count limit — break out so the drain below runs.
                    break

            # Drain: wait for all in-flight tasks to finish before returning.
            while True:
                self._wake.clear()
                with self._lock:
                    pending_exists = bool(self._pending)
                if not pending_exists:
                    break
                if not self._is_pool_healthy(pool):
                    log.error("PebbleEngine: pool died during drain; failing pending tasks")
                    self._fail_all_pending("pool died during drain")
                    break
                self._reap_stalled()
                self._wake.wait(timeout=0.2)
        finally:
            self._teardown_pool(pool)
