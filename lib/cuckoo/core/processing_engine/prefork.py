"""Single-threaded prefork supervisor: forks one child per task, each child runs
exactly one task then os._exit(); the supervisor reaps children and enforces a
launch-relative wall-clock timeout via process-group kill. No supervisor<->child
channel exists. See docs/superpowers/specs/2026-05-27-processor-concurrency-redesign-design.md."""
import logging
import os
import signal
import threading
import time

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
        n = threading.active_count()
        if n != 1:
            raise RuntimeError(
                "prefork supervisor must be single-threaded before fork; "
                "active_count=%d (a thread/Mongo client/pool leaked into the supervisor)" % n)

    def _inflight_task_ids(self):
        return {c.task_id for c in self._inflight.values()}

    def _heartbeat(self):
        if self._inflight:
            oldest = max(time.monotonic() - c.start for c in self._inflight.values())
        else:
            oldest = 0.0
        log.info("prefork heartbeat: in_flight=%d oldest=%.0fs", len(self._inflight), oldest)
