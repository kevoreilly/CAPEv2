"""Single-threaded prefork supervisor: forks one child per task, each child runs
exactly one task then os._exit(); the supervisor reaps children and enforces a
launch-relative wall-clock timeout via process-group kill. No supervisor<->child
channel exists. See docs/superpowers/specs/2026-05-27-processor-concurrency-redesign-design.md."""
import logging
import os
import signal
import threading
import time

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.core.processing_engine.base import ProcessingEngine

log = logging.getLogger(__name__)


class _Child:
    __slots__ = ("task_id", "pid", "start", "pgid", "timed_out", "kill_deadline")

    def __init__(self, task_id, pid, start, pgid):
        self.task_id = task_id
        self.pid = pid
        self.start = start
        self.pgid = pgid
        self.timed_out = False
        self.kill_deadline = None


class PreforkEngine(ProcessingEngine):
    def __init__(self, task_fn, worker_init, source, parallel, timeout,
                 heartbeat_interval=30, term_grace=5, max_count=0, poll_interval=0.2):
        super().__init__(task_fn, worker_init, source, parallel, timeout)
        self.heartbeat_interval = heartbeat_interval
        self.term_grace = term_grace
        self.max_count = max_count
        self.poll_interval = poll_interval
        self._inflight = {}  # pid -> _Child

    def _assert_single_threaded(self):
        py_count = threading.active_count()
        try:
            kernel_count = len(os.listdir("/proc/self/task"))
        except OSError:
            kernel_count = None  # /proc unavailable; fall back to Python check only

        if py_count != 1 or (kernel_count is not None and kernel_count != 1):
            raise RuntimeError(
                "prefork supervisor must be single-threaded before fork; "
                "python active_count=%d kernel /proc/self/task=%s "
                "(a thread / Mongo client / pool / native C extension like STPyV8 "
                "leaked into the supervisor)" % (py_count, kernel_count))

    def _inflight_task_ids(self):
        return {c.task_id for c in self._inflight.values()}

    def _heartbeat(self):
        if self._inflight:
            oldest = max(time.monotonic() - c.start for c in self._inflight.values())
        else:
            oldest = 0.0
        log.info("prefork heartbeat: in_flight=%d oldest=%.0fs", len(self._inflight), oldest)

    def _child_main(self, task):
        os.setsid()  # own session/process group; supervisor killpg sweeps the subtree
        try:
            self.worker_init()
            self.task_fn(task)
            return 0
        except BaseException:
            log.exception("prefork child: task %s crashed", getattr(task, "id", "?"))
            return 1

    def _launch(self, task):
        self._assert_single_threaded()
        pid = os.fork()
        if pid == 0:
            code = 1
            try:
                code = self._child_main(task)
            finally:
                os._exit(code)  # NEVER return: skip multiprocessing atexit join
        self._inflight[pid] = _Child(task_id=task.id, pid=pid, start=time.monotonic(), pgid=pid)
        log.debug("prefork: launched task %d as pid %d", task.id, pid)

    def _reap(self):
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                return
            child = self._inflight.pop(pid, None)
            if child is None:
                continue
            if child.timed_out:
                continue  # already marked failed during timeout enforcement
            ok = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            if ok:
                log.info("Reports generation completed for Task #%d", child.task_id)
            else:
                if os.WIFEXITED(status):
                    detail = "exit=%d" % os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    detail = "signal=%d" % os.WTERMSIG(status)
                else:
                    detail = "status=%d" % status
                log.warning("prefork: task %d (pid %d) abnormal %s -> FAILED_PROCESSING",
                            child.task_id, pid, detail)
                self.source.mark_failed(child.task_id)

    def _enforce_timeouts(self):
        now = time.monotonic()
        for child in list(self._inflight.values()):
            if child.timed_out or now - child.start <= self.timeout:
                continue
            log.error("prefork: task %d (pid %d) exceeded %ds -> killpg",
                      child.task_id, child.pid, self.timeout)
            child.timed_out = True
            self.source.mark_failed(child.task_id)
            try:
                os.killpg(child.pgid, signal.SIGTERM)
            except ProcessLookupError:
                continue
            except OSError as e:
                log.warning("prefork: killpg(SIGTERM) failed for task %d (pid %d): %s",
                            child.task_id, child.pid, e)
                continue
            child.kill_deadline = now + self.term_grace

    def _escalate_kills(self):
        now = time.monotonic()
        for child in list(self._inflight.values()):
            if child.timed_out and child.kill_deadline and now > child.kill_deadline:
                log.warning("prefork: task %d (pid %d) did not exit after SIGTERM, escalating to SIGKILL",
                            child.task_id, child.pid)
                try:
                    os.killpg(child.pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except OSError as e:
                    log.warning("prefork: killpg(SIGKILL) failed for task %d (pid %d): %s",
                                child.task_id, child.pid, e)
                child.kill_deadline = None

    def run(self):
        cfg = Config()
        count = 0
        last_hb = 0.0
        while True:
            self._reap()
            self._enforce_timeouts()
            self._escalate_kills()
            if cfg.cuckoo.freespace_processing:
                from lib.cuckoo.common.cleaners_utils import free_space_monitor
                dir_path = os.path.join(CUCKOO_ROOT, "storage", "analyses")
                free_space_monitor(dir_path, processing=True)
            if self.max_count and count >= self.max_count and not self._inflight:
                return
            free = self.parallel - len(self._inflight)
            launchable = free if not self.max_count else min(free, self.max_count - count)
            if launchable > 0:
                tasks = self.source.fetch(limit=launchable, exclude_ids=self._inflight_task_ids())
                for task in tasks[:launchable]:
                    self._launch(task)
                    count += 1
            now = time.monotonic()
            if now - last_hb >= self.heartbeat_interval:
                self._heartbeat()
                last_hb = now
            time.sleep(self.poll_interval)
