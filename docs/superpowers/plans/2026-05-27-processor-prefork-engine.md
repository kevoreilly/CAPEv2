# Processor Prefork Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the deadlock-prone pebble worker pool in `utils/process.py` with a pluggable engine layer: the existing pebble loop preserved as an A/B control, and a new single-threaded **prefork supervisor** (fork-per-task children, `os._exit`, process-group timeout kill) as the reliability target.

**Architecture:** A thin `autoprocess()` dispatches to a `ProcessingEngine` chosen by `--engine {pebble,prefork}`. Both engines share a `TaskSource` (DB poll + status writes) and a `run_task(task)` adapter. `PebbleEngine` wraps today's loop unchanged. `PreforkEngine` is a single-threaded supervisor that forks one child per task; the child `os.setsid()`s, runs the task, and `os._exit()`s; the supervisor reaps children and enforces a launch-relative wall-clock timeout via `os.killpg`. No supervisor↔child channel exists.

**Tech Stack:** Python 3.12, SQLAlchemy (CAPE `Database`), pytest 7.2.2 (`poetry run pytest`, sqlite `db` fixture), `os.fork`/`waitpid`/`killpg`/`setsid`.

**Spec:** `docs/superpowers/specs/2026-05-27-processor-concurrency-redesign-design.md`

**Conventions for every task below:**
- Run tests with: `cd /opt/CAPEv2 && poetry run pytest <path> -v`
- Commit only the files listed in the task (the repo working tree has many unrelated dirty files — never `git add -A`).
- Status constants import from `lib.cuckoo.core.data.task` (`TASK_COMPLETED`, `TASK_FAILED_PROCESSING`, `TASK_REPORTED`, `Task`).

---

## Phase 1 — Engine seam (behavior-preserving)

After Phase 1, behavior is unchanged: `--engine pebble` (the default) runs exactly today's loop, now behind the seam.

### Task 1: `TaskSource` — DB polling + status writes

**Files:**
- Create: `lib/cuckoo/core/processing_engine/__init__.py` (empty)
- Create: `lib/cuckoo/core/processing_engine/source.py`
- Test: `tests/test_processing_engine_source.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_processing_engine_source.py
import pytest
from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_FAILED_PROCESSING
from lib.cuckoo.core.processing_engine.source import TaskSource


def test_fetch_returns_completed_tasks_excluding_inflight(db, temp_pe32):
    t1 = db.add_path(temp_pe32)
    t2 = db.add_path(temp_pe32)
    db.set_status(t1, TASK_COMPLETED)
    db.set_status(t2, TASK_COMPLETED)

    src = TaskSource(db)
    got = src.fetch(limit=10, exclude_ids={t2})
    ids = [t.id for t in got]
    assert t1 in ids and t2 not in ids


def test_mark_failed_sets_status(db, temp_pe32):
    t1 = db.add_path(temp_pe32)
    db.set_status(t1, TASK_COMPLETED)

    src = TaskSource(db)
    src.mark_failed(t1)
    assert db.view_task(t1).status == TASK_FAILED_PROCESSING
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_processing_engine_source.py -v`
Expected: FAIL with `ModuleNotFoundError: lib.cuckoo.core.processing_engine.source`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/cuckoo/core/processing_engine/source.py
"""Shared task source for processing engines: pulls tasks needing processing
from the DB and writes terminal status. Engines differ in how they *run* tasks,
not in how they pull them."""
import logging

from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_FAILED_PROCESSING, Task

log = logging.getLogger(__name__)


class TaskSource:
    def __init__(self, db, failed_processing=False):
        self.db = db
        self._status = TASK_FAILED_PROCESSING if failed_processing else TASK_COMPLETED

    def fetch(self, limit, exclude_ids):
        """Return up to `limit` tasks needing processing, excluding `exclude_ids`
        (in-flight). Tasks are expunged so they are safe to use after the txn."""
        if limit <= 0:
            return []
        with self.db.session.begin():
            tasks = self.db.list_tasks(status=self._status, limit=limit, order_by=Task.completed_on.asc())
            self.db.session.expunge_all()
        return [t for t in tasks if t.id not in exclude_ids]

    def mark_failed(self, task_id):
        with self.db.session.begin():
            self.db.set_status(task_id, TASK_FAILED_PROCESSING)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_processing_engine_source.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cuckoo/core/processing_engine/__init__.py lib/cuckoo/core/processing_engine/source.py tests/test_processing_engine_source.py
git commit -m "feat(processor): add TaskSource for engine task polling/status"
```

---

### Task 2: `ProcessingEngine` base + `get_engine()` registry

**Files:**
- Create: `lib/cuckoo/core/processing_engine/base.py`
- Modify: `lib/cuckoo/core/processing_engine/__init__.py`
- Test: `tests/test_processing_engine_registry.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_processing_engine_registry.py
import pytest
from lib.cuckoo.core.processing_engine import get_engine
from lib.cuckoo.core.processing_engine.base import ProcessingEngine


def _noop(*a, **k):
    pass


def test_get_engine_returns_requested_class():
    eng = get_engine("pebble", task_fn=_noop, worker_init=_noop, source=None, parallel=2, timeout=900)
    assert isinstance(eng, ProcessingEngine)


def test_get_engine_unknown_raises():
    with pytest.raises(ValueError):
        get_engine("nope", task_fn=_noop, worker_init=_noop, source=None, parallel=2, timeout=900)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_processing_engine_registry.py -v`
Expected: FAIL with `ImportError`/`cannot import name 'get_engine'`

- [ ] **Step 3: Write minimal implementation**

```python
# lib/cuckoo/core/processing_engine/base.py
"""Abstract processing engine: drives the per-task lifecycle for autoprocess.
Concrete engines (pebble, prefork) differ only in worker isolation."""


class ProcessingEngine:
    def __init__(self, task_fn, worker_init, source, parallel, timeout):
        self.task_fn = task_fn        # task_fn(task) -> None: runs ONE task to completion
        self.worker_init = worker_init  # called in worker context (pool init / post-fork)
        self.source = source          # TaskSource
        self.parallel = parallel
        self.timeout = timeout

    def run(self):
        raise NotImplementedError
```

```python
# lib/cuckoo/core/processing_engine/__init__.py
from lib.cuckoo.core.processing_engine.base import ProcessingEngine


def get_engine(name, **kwargs):
    """Construct the named engine. Imports are local so that selecting one engine
    never imports the other's dependencies."""
    if name == "pebble":
        from lib.cuckoo.core.processing_engine.pebble import PebbleEngine
        return PebbleEngine(**kwargs)
    if name == "prefork":
        from lib.cuckoo.core.processing_engine.prefork import PreforkEngine
        return PreforkEngine(**kwargs)
    raise ValueError("unknown processing engine: %r" % name)


__all__ = ["ProcessingEngine", "get_engine"]
```

NOTE: this task references `pebble.PebbleEngine` (Task 4) and `prefork.PreforkEngine` (Task 5). The registry test only exercises the `pebble` branch, which Task 4 makes importable. Run Task 2's test again after Task 4. For now, add a temporary stub so Task 2 passes in isolation:

```python
# lib/cuckoo/core/processing_engine/pebble.py  (TEMPORARY STUB — replaced in Task 4)
from lib.cuckoo.core.processing_engine.base import ProcessingEngine


class PebbleEngine(ProcessingEngine):
    def run(self):
        raise NotImplementedError
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_processing_engine_registry.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cuckoo/core/processing_engine/base.py lib/cuckoo/core/processing_engine/__init__.py lib/cuckoo/core/processing_engine/pebble.py tests/test_processing_engine_registry.py
git commit -m "feat(processor): add ProcessingEngine base + get_engine registry"
```

---

### Task 3: Extract `run_task(task)` adapter in `process.py`

The per-task argument building currently inlined in `autoprocess()` (`utils/process.py` ~lines 463–470: sample-hash lookup + building `args`/`kwargs` for `process()`) becomes a standalone `run_task(task)` so both engines share it.

**Files:**
- Modify: `utils/process.py` (add `run_task`; reference existing `process()` at line 107 and `db`)
- Test: `tests/test_run_task_adapter.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_run_task_adapter.py
import types
import utils.process as proc


def test_run_task_calls_process_with_task_and_auto(monkeypatch, db, temp_pe32):
    captured = {}

    def fake_process(target=None, sample_sha256=None, task=None, report=False, auto=False, **kw):
        captured["task_id"] = task.id
        captured["auto"] = auto
        captured["report"] = report

    monkeypatch.setattr(proc, "process", fake_process)
    monkeypatch.setattr(proc, "db", db)

    tid = db.add_path(temp_pe32)
    task = db.view_task(tid)
    proc.run_task(task)

    assert captured["task_id"] == tid
    assert captured["auto"] is True and captured["report"] is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_run_task_adapter.py -v`
Expected: FAIL with `AttributeError: module 'utils.process' has no attribute 'run_task'`

- [ ] **Step 3: Write minimal implementation**

Add to `utils/process.py` (near `process()`), preserving the existing sample-hash logic from `autoprocess`:

```python
def run_task(task, memory_debugging=False, debug=False):
    """Run exactly one completed task to completion (processing -> report).
    Extracted from autoprocess so every engine shares identical per-task setup."""
    sample_hash = ""
    if task.category != "url":
        with db.session.begin():
            sample = db.view_sample(task.sample_id)
            if sample:
                sample_hash = sample.sha256
    process(
        task.target,
        sample_hash,
        report=True,
        auto=True,
        task=task,
        memory_debugging=memory_debugging,
        debug=debug,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_run_task_adapter.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add utils/process.py tests/test_run_task_adapter.py
git commit -m "refactor(processor): extract run_task(task) adapter shared by engines"
```

---

### Task 4: `PebbleEngine` (relocate today's loop) + wire `autoprocess` + `--engine` flag

Move the current pebble pool loop (`utils/process.py` `autoprocess` body, ~lines 430–508, plus `processing_finished`, ~lines 376–407) into `PebbleEngine`, calling injected `task_fn`/`worker_init`/`source` instead of the inline DB/process code. Behavior must be identical to today (including `-mc 0` default).

**Files:**
- Modify: `lib/cuckoo/core/processing_engine/pebble.py` (replace the Task 2 stub)
- Modify: `utils/process.py` (`autoprocess()` → build `TaskSource` + `get_engine`; add `--engine` arg; keep `init_worker`, `process`, `run_task`)
- Test: `tests/test_pebble_engine.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_pebble_engine.py
import threading
import time
from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_REPORTED
from lib.cuckoo.core.processing_engine.pebble import PebbleEngine
from lib.cuckoo.core.processing_engine.source import TaskSource


def test_pebble_engine_processes_one_task(db, temp_pe32, monkeypatch):
    tid = db.add_path(temp_pe32)
    db.set_status(tid, TASK_COMPLETED)

    ran = threading.Event()

    def fake_task_fn(task):
        with db.session.begin():
            db.set_status(task.id, TASK_REPORTED)
        ran.set()

    eng = PebbleEngine(task_fn=fake_task_fn, worker_init=lambda: None,
                       source=TaskSource(db), parallel=2, timeout=30, max_count=1)
    eng.run()
    assert ran.wait(timeout=20)
    assert db.view_task(tid).status == TASK_REPORTED
```

NOTE: `max_count` lets the loop exit after N scheduled tasks for tests (mirror the existing `cfg.cuckoo.max_analysis_count` exit; default 0 = run forever in production).

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_pebble_engine.py -v`
Expected: FAIL with `NotImplementedError` (Task 2 stub) or `TypeError` (no `max_count`).

- [ ] **Step 3: Write minimal implementation**

```python
# lib/cuckoo/core/processing_engine/pebble.py
"""Pebble-pool engine — preserved as the A/B control. Mirrors the historical
autoprocess loop, parameterized behind the engine seam. max_tasks defaults to 0
(no recycle): worker recycling deadlocks in multiprocessing _exit_function while
joining the nested extractor pool — see the redesign spec."""
import logging
import time

import pebble

from lib.cuckoo.core.processing_engine.base import ProcessingEngine

log = logging.getLogger(__name__)


class PebbleEngine(ProcessingEngine):
    def __init__(self, task_fn, worker_init, source, parallel, timeout,
                 max_tasks=0, max_count=0):
        super().__init__(task_fn, worker_init, source, parallel, timeout)
        self.max_tasks = max_tasks
        self.max_count = max_count
        self._pending = {}  # future -> task_id

    def _done(self, future):
        task_id = self._pending.pop(future, None)
        try:
            future.result()
        except Exception:
            log.exception("[%s] pebble: task failed", task_id)
            if task_id is not None:
                self.source.mark_failed(task_id)

    def run(self):
        count = 0
        with pebble.ProcessPool(max_workers=self.parallel, max_tasks=self.max_tasks,
                                initializer=self.worker_init) as pool:
            while not self.max_count or count < self.max_count:
                if len(self._pending) >= self.parallel:
                    time.sleep(1)
                    continue
                tasks = self.source.fetch(limit=self.parallel,
                                          exclude_ids=set(self._pending.values()))
                added = False
                for task in tasks:
                    future = pool.schedule(self.task_fn, args=(task,), timeout=self.timeout)
                    self._pending[future] = task.id
                    future.add_done_callback(self._done)
                    count += 1
                    added = True
                    break
                if not added and not self.max_count:
                    time.sleep(1)
                if not added and self.max_count:
                    break
            # drain
            while self._pending:
                time.sleep(0.2)
```

In `utils/process.py`, replace the body of `autoprocess()` with engine dispatch (keep `memory_limit()`/`free_space_monitor` setup as today), and add the CLI flag:

```python
# autoprocess() body (replace the pebble loop):
from lib.cuckoo.core.processing_engine import get_engine
from lib.cuckoo.core.processing_engine.source import TaskSource

def autoprocess(parallel=1, failed_processing=False, maxtasksperchild=0,
                memory_debugging=False, processing_timeout=300, debug=False,
                disable_memory_limit=False, engine="pebble"):
    if not disable_memory_limit:
        memory_limit()
    log.info("Processing analysis data (engine=%s)", engine)
    source = TaskSource(db, failed_processing=failed_processing)
    eng = get_engine(
        engine,
        task_fn=lambda task: run_task(task, memory_debugging=memory_debugging, debug=debug),
        worker_init=init_worker,
        source=source,
        parallel=parallel,
        timeout=processing_timeout,
    )
    if engine == "pebble":
        eng.max_tasks = maxtasksperchild
    eng.run()
```

```python
# argparse (near the other autoprocess args):
parser.add_argument("--engine", choices=["pebble", "prefork"], default="pebble",
                    help="Processing engine: pebble (default, A/B control) or prefork.")
# main() autoprocess(...) call: add engine=args.engine
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_pebble_engine.py tests/test_processing_engine_registry.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Smoke-test the real CLI (no behavior change)**

Run: `poetry run python utils/process.py --help` — Expected: shows `--engine {pebble,prefork}`.
Run (brief, then Ctrl-C): `poetry run python utils/process.py -p2 auto -pt 900 --engine pebble` — Expected: logs `Processing analysis data (engine=pebble)` and processes as before.

- [ ] **Step 6: Commit**

```bash
git add lib/cuckoo/core/processing_engine/pebble.py utils/process.py tests/test_pebble_engine.py
git commit -m "feat(processor): PebbleEngine behind engine seam + --engine flag (default pebble)"
```

---

## Phase 2 — PreforkEngine

A single-threaded supervisor. All tests inject a fake `task_fn` (sleep/crash/normal) so the real processing pipeline is not needed.

### Task 5: Supervisor scaffolding + concurrency cap + single-threaded invariant

**Files:**
- Create: `lib/cuckoo/core/processing_engine/prefork.py` (replace any stub)
- Test: `tests/test_prefork_engine.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_prefork_engine.py
import os
import threading
import time

from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_FAILED_PROCESSING, TASK_REPORTED
from lib.cuckoo.core.processing_engine.prefork import PreforkEngine
from lib.cuckoo.core.processing_engine.source import TaskSource


def test_single_threaded_invariant_raises_when_extra_thread(db):
    eng = PreforkEngine(task_fn=lambda t: None, worker_init=lambda: None,
                        source=TaskSource(db), parallel=2, timeout=30)
    stop = threading.Event()
    t = threading.Thread(target=stop.wait)
    t.start()
    try:
        import pytest
        with pytest.raises(RuntimeError, match="single-threaded"):
            eng._assert_single_threaded()
    finally:
        stop.set()
        t.join()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_prefork_engine.py -v`
Expected: FAIL with `ModuleNotFoundError`/`AttributeError`.

- [ ] **Step 3: Write minimal implementation**

```python
# lib/cuckoo/core/processing_engine/prefork.py
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_prefork_engine.py -v`
Expected: PASS (1 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cuckoo/core/processing_engine/prefork.py tests/test_prefork_engine.py
git commit -m "feat(processor): PreforkEngine scaffolding + single-threaded invariant"
```

---

### Task 6: Fork-per-task execution + reap + status (child sets / supervisor overrides)

**Files:**
- Modify: `lib/cuckoo/core/processing_engine/prefork.py`
- Test: `tests/test_prefork_engine.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_prefork_engine.py

def test_normal_task_runs_and_status_set_by_child(db, temp_pe32):
    tid = db.add_path(temp_pe32)
    db.set_status(tid, TASK_COMPLETED)

    # child runs this; it must set status itself (child sets, supervisor overrides only on failure)
    def task_fn(task):
        # fresh DB handle in child after fork
        from lib.cuckoo.core.database import Database
        Database().set_status(task.id, TASK_REPORTED)

    eng = PreforkEngine(task_fn=task_fn, worker_init=lambda: None,
                        source=TaskSource(db), parallel=2, timeout=30, max_count=1)
    eng.run()
    assert db.view_task(tid).status == TASK_REPORTED


def test_crashing_task_marked_failed_by_supervisor(db, temp_pe32):
    tid = db.add_path(temp_pe32)
    db.set_status(tid, TASK_COMPLETED)

    def task_fn(task):
        os._exit(3)  # simulate abnormal exit / crash

    eng = PreforkEngine(task_fn=task_fn, worker_init=lambda: None,
                        source=TaskSource(db), parallel=2, timeout=30, max_count=1)
    eng.run()
    assert db.view_task(tid).status == TASK_FAILED_PROCESSING
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_prefork_engine.py -v`
Expected: FAIL (`run`/`_launch`/`_reap` not implemented).

- [ ] **Step 3: Write minimal implementation**

```python
# add methods to PreforkEngine

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
            if not ok:
                log.warning("prefork: task %d (pid %d) abnormal exit status=%d -> FAILED_PROCESSING",
                            child.task_id, pid, status)
                self.source.mark_failed(child.task_id)

    def run(self):
        count = 0
        last_hb = 0.0
        while True:
            self._reap()
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_prefork_engine.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cuckoo/core/processing_engine/prefork.py tests/test_prefork_engine.py
git commit -m "feat(processor): prefork fork-per-task execution + reap + failure status"
```

---

### Task 7: Wall-clock timeout via `killpg` + no-orphan cleanup

**Files:**
- Modify: `lib/cuckoo/core/processing_engine/prefork.py`
- Test: `tests/test_prefork_engine.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_prefork_engine.py

def test_timeout_kills_process_group_no_orphans(db, temp_pe32):
    tid = db.add_path(temp_pe32)
    db.set_status(tid, TASK_COMPLETED)

    marker = "/tmp/prefork_orphan_%d" % os.getpid()

    def task_fn(task):
        # spawn a grandchild that would outlive the worker, then hang
        import subprocess, sys
        subprocess.Popen([sys.executable, "-c",
                          "import time,os;open(%r,'w').close();time.sleep(120)" % marker])
        time.sleep(120)

    eng = PreforkEngine(task_fn=task_fn, worker_init=lambda: None, source=TaskSource(db),
                        parallel=1, timeout=1, term_grace=1, max_count=1, poll_interval=0.1)
    if os.path.exists(marker):
        os.unlink(marker)
    eng.run()

    assert db.view_task(tid).status == TASK_FAILED_PROCESSING
    # grandchild must have been swept by killpg (give it a moment)
    time.sleep(2)
    # nothing holding the marker's process group alive: assert no python sleeping on it
    # (best-effort: the grandchild process should be gone)
    import subprocess
    out = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
    assert out.stdout.strip() == "", "orphaned grandchild survived killpg"
    if os.path.exists(marker):
        os.unlink(marker)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_prefork_engine.py::test_timeout_kills_process_group_no_orphans -v`
Expected: FAIL (timeout enforcement not implemented → test hangs to its own safety or task not failed). If it hangs, that confirms missing enforcement; add enforcement in Step 3.

- [ ] **Step 3: Write minimal implementation**

```python
# add to PreforkEngine

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
            child.kill_deadline = now + self.term_grace

    def _escalate_kills(self):
        now = time.monotonic()
        for child in list(self._inflight.values()):
            if child.timed_out and child.kill_deadline and now > child.kill_deadline:
                try:
                    os.killpg(child.pgid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.kill_deadline = None
```

Wire both into `run()`'s loop, immediately after `self._reap()`:

```python
            self._reap()
            self._enforce_timeouts()
            self._escalate_kills()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_prefork_engine.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add lib/cuckoo/core/processing_engine/prefork.py tests/test_prefork_engine.py
git commit -m "feat(processor): prefork wall-clock timeout via killpg + grace escalation"
```

---

### Task 8: Post-fork child reinit + wire `--engine prefork`

`init_worker()` today is the pebble pool initializer (disposes the SQLAlchemy engine post-fork, resets log handlers, pre-compiles YARA). For prefork it runs in `_child_main` via the injected `worker_init`. Confirm it is fork-safe to call in the child (it already does `db.engine.dispose(close=False)` and resets handlers without lock-acquiring calls).

**Files:**
- Modify: `utils/process.py` (`autoprocess` already passes `worker_init=init_worker` and `engine=args.engine` from Task 4 — verify prefork path constructs cleanly)
- Test: `tests/test_prefork_engine.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_prefork_engine.py

def test_worker_init_called_in_child(db, temp_pe32, tmp_path):
    tid = db.add_path(temp_pe32)
    db.set_status(tid, TASK_COMPLETED)
    flag = str(tmp_path / "winit_ran")

    def worker_init():
        open(flag, "w").close()

    def task_fn(task):
        assert os.path.exists(flag), "worker_init must run before task_fn in child"
        from lib.cuckoo.core.database import Database
        Database().set_status(task.id, TASK_REPORTED)

    eng = PreforkEngine(task_fn=task_fn, worker_init=worker_init, source=TaskSource(db),
                        parallel=1, timeout=30, max_count=1)
    eng.run()
    assert db.view_task(tid).status == TASK_REPORTED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_prefork_engine.py::test_worker_init_called_in_child -v`
Expected: PASS already if Task 6 calls `self.worker_init()` before `self.task_fn(task)` in `_child_main`. If it FAILS, fix ordering in `_child_main`.

- [ ] **Step 3: Verify ordering (no code change expected)**

Confirm `_child_main` calls `self.worker_init()` then `self.task_fn(task)`. If not, reorder.

- [ ] **Step 4: Smoke-test the real prefork CLI against the live DB (read-only-ish)**

Run (brief, then Ctrl-C): `poetry run python utils/process.py -p2 auto -pt 900 --engine prefork`
Expected: logs `Processing analysis data (engine=prefork)`, a `prefork heartbeat: in_flight=...` line, and tasks transition to reported. Verify no `_exit_function`/`join` stacks via `py-spy dump` on a child (should show the task running, not multiprocessing atexit).

- [ ] **Step 5: Commit**

```bash
git add lib/cuckoo/core/processing_engine/prefork.py tests/test_prefork_engine.py
git commit -m "feat(processor): verify post-fork worker_init ordering for prefork children"
```

---

## Phase 3 — Extractor sub-pool + finalize

### Task 9: SPIKE — resolve §4.2(d) extractor sub-pool spawn strategy by measurement

The nested extractor pool in `lib/cuckoo/common/integrations/file_extra_info.py` (`_EXTRACTOR_POOL`) must, under prefork, be: created inside the task child, explicitly `close()`+`join()`d before the child `os._exit()`s, and entirely within the child's process group (so `killpg` sweeps it). The open question is the spawn context: `forkserver` (clean, re-imports per task) vs `fork` from the warm single-threaded child (inherits modules cheaply, must be created before the child spawns threads).

**Files:**
- Create: `docs/superpowers/notes/2026-05-27-extractor-subpool-spike.md` (findings only; no production code)

- [ ] **Step 1: Measure both strategies**

Write a throwaway script that, inside a forked child, builds (a) `pebble.ProcessPool(context=multiprocessing.get_context("forkserver"))` and (b) `...get_context("fork")`, schedules a trivial extractor-like function across `max_workers=6`, and records: pool-create+first-result latency, and whether `killpg` of the child's group leaves any survivors (`pgrep`). Run on a representative extracted-file workload.

- [ ] **Step 2: Record the decision**

Write findings + the chosen context to the notes file, with the latency numbers and the orphan check. Decision criterion: choose the faster strategy that leaves zero survivors after `killpg` and runs cleanly with `os._exit()`.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/notes/2026-05-27-extractor-subpool-spike.md
git commit -m "docs(processor): spike results for extractor sub-pool spawn strategy"
```

---

### Task 10: Make `_EXTRACTOR_POOL` prefork-safe (explicit teardown + process-group membership)

**Files:**
- Modify: `lib/cuckoo/common/integrations/file_extra_info.py` (`_get_extractor_pool`/`generic_file_extractors`, ~lines 436–520)
- Test: `tests/test_extractor_pool_teardown.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_extractor_pool_teardown.py
import os
import time
import multiprocessing as mp


def _busy(_):
    time.sleep(60)


def test_extractor_pool_is_swept_by_killpg(tmp_path):
    """A child that creates the extractor pool and is killpg'd must leave no survivors."""
    marker = str(tmp_path / "epool_child")

    def child():
        os.setsid()
        open(marker, "w").close()
        import pebble
        ctx = mp.get_context("forkserver")  # or the strategy chosen in Task 9
        pool = pebble.ProcessPool(max_workers=2, context=ctx)
        for _ in range(2):
            pool.schedule(_busy, args=(1,), timeout=60)
        time.sleep(60)

    pid = os.fork()
    if pid == 0:
        try:
            child()
        finally:
            os._exit(0)
    while not os.path.exists(marker):
        time.sleep(0.05)
    time.sleep(1)
    os.killpg(pid, 15)
    time.sleep(2)
    import subprocess
    out = subprocess.run(["pgrep", "-g", str(pid)], capture_output=True, text=True)
    assert out.stdout.strip() == "", "extractor sub-pool survived killpg"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `poetry run pytest tests/test_extractor_pool_teardown.py -v`
Expected: PASS or FAIL depending on context choice; if FAIL (survivors), the chosen context/teardown is wrong — adjust per Task 9 findings.

- [ ] **Step 3: Implement teardown + per-call lifecycle**

In `generic_file_extractors`, replace the process-wide cached `_EXTRACTOR_POOL` with a pool created and torn down per call (under prefork the child is ephemeral, so per-task lifetime is correct), using the Task-9 context, and `pool.close(); pool.join()` in a `finally`. Keep the per-future timeouts.

```python
def generic_file_extractors(file, destination_folder, data_dictionary, options, results, duplicated, tests=False):
    ...
    import multiprocessing
    ctx = multiprocessing.get_context("forkserver")  # per Task 9 decision
    pool = pebble.ProcessPool(max_workers=int(integration_conf.general.max_workers), context=ctx)
    try:
        ... # schedule extractors, collect futures, gather results (unchanged logic)
    finally:
        pool.close()
        pool.join()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `poetry run pytest tests/test_extractor_pool_teardown.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add lib/cuckoo/common/integrations/file_extra_info.py tests/test_extractor_pool_teardown.py
git commit -m "fix(extractors): per-call pool with explicit teardown, swept by process-group kill"
```

---

### Task 11: Docs + A/B systemd drop-in + stopgap retirement note

**Files:**
- Create: `docs/superpowers/notes/2026-05-27-processor-engine-ab-runbook.md`
- Modify: `docs/superpowers/specs/2026-05-27-processor-concurrency-redesign-design.md` (mark Phase status)

- [ ] **Step 1: Write the A/B runbook**

Document: how to flip engines (systemd drop-in `ExecStart ... --engine prefork`), the metrics to compare (throughput tasks/min, wedge incidents, peak RSS, orphan count after induced timeouts via `pgrep`), how to roll back (remove drop-in line), and the condition to retire the `-mc 0` stopgap (once `prefork` is the default). **State explicitly that the A/B runs against the production PostgreSQL database — both engines share the same module-level `Database()` (configured `postgresql://...`); the `sqlite://` `db` fixture in `tests/conftest.py` is a unit-test harness only and has no production path.**

- [ ] **Step 2: Update spec status + commit**

```bash
git add docs/superpowers/notes/2026-05-27-processor-engine-ab-runbook.md docs/superpowers/specs/2026-05-27-processor-concurrency-redesign-design.md
git commit -m "docs(processor): A/B runbook + mark redesign implementation status"
```

---

## Self-review notes (author)

- **Spec coverage:** pluggable seam (T1–T4), PebbleEngine control (T4), Prefork supervisor incl. fork-per-task/os._exit/killpg/single-threaded invariant/status (T5–T8), warm-base inheritance (relies on `main()` init before `run()`; T8 smoke-test), extractor sub-pool §4.2(d) (T9–T10), A/B + metrics + heartbeat (T6 heartbeat, T11 runbook). Memory model is design-level (no code).
- **Deferred-by-design:** §4.2(d) spawn context is resolved by the T9 spike before T10 codes it — intentional, not a placeholder.
- **Type consistency:** `ProcessingEngine(task_fn, worker_init, source, parallel, timeout)` used uniformly; `task_fn(task)`, `source.fetch(limit, exclude_ids)`, `source.mark_failed(task_id)` consistent across T1/T4/T5–T8.
- **Risk:** the live `/opt/CAPEv2` tree has many dirty files — every commit step lists explicit paths; never `git add -A`.
