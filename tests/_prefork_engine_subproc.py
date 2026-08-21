"""Subprocess entrypoint for the PreforkEngine behaviour tests.

The pytest process is multi-threaded (other suites leak Mongo clients, native
C-extension pools, etc.), so it can neither satisfy the prefork single-threaded-
before-fork invariant nor safely os.fork(). Running the engine in a fresh
interpreter here gives a guaranteed single-threaded process.

Usage: python tests/_prefork_engine_subproc.py <scenario> <dsn> <tid> <aux>
Exit code 0 = engine ran to completion; the parent asserts on DB state / files.
"""
import os
import sys
import time

# Make the repo root importable when run as a bare script (sys.path[0] is tests/).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

# Neutralise the real disk-space check: PreforkEngine.run() calls
# free_space_monitor(storage/analyses, ...), which sys.exit()s when that path is
# absent (as in test/CI checkouts). Disk policy is not under test here.
import lib.cuckoo.common.cleaners_utils as _cu  # noqa: E402

_cu.free_space_monitor = lambda *a, **k: None

from lib.cuckoo.core.data.task import TASK_REPORTED  # noqa: E402
from lib.cuckoo.core.database import Database, init_database  # noqa: E402
from lib.cuckoo.core.processing_engine.prefork import PreforkEngine  # noqa: E402
from lib.cuckoo.core.processing_engine.source import TaskSource  # noqa: E402

_AUX_ENV = "_PREFORK_AUX"


def _set_reported(task):
    db = Database()
    with db.session.begin():
        db.set_status(task.id, TASK_REPORTED)


def _normal(task):
    _set_reported(task)


def _crash(task):
    os._exit(3)  # abnormal exit -> supervisor marks FAILED_PROCESSING


def _timeout(task):
    # Spawn a grandchild that would outlive the worker, then hang. The grandchild
    # inherits the child's process group (the child os.setsid()s), so killpg sweeps it.
    import subprocess

    marker = os.environ[_AUX_ENV]
    subprocess.Popen([sys.executable, "-c", "import time;open(%r,'w').close();time.sleep(120)" % marker])
    time.sleep(120)


def _worker_init_flag():
    open(os.environ[_AUX_ENV], "w").close()


def _worker_init_task(task):
    assert os.path.exists(os.environ[_AUX_ENV]), "worker_init must run before task_fn in child"
    _set_reported(task)


def main():
    # argv[3] is the task id; the engine fetches tasks from the DB itself, so the
    # helper doesn't use it (it's there for a uniform parent-side call signature).
    scenario, dsn, _tid, aux = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    os.environ[_AUX_ENV] = aux
    init_database(dsn=dsn)
    src = TaskSource(Database())

    common = dict(source=src, max_count=1)
    if scenario == "normal":
        eng = PreforkEngine(task_fn=_normal, worker_init=lambda: None, parallel=2, timeout=30, **common)
    elif scenario == "crash":
        eng = PreforkEngine(task_fn=_crash, worker_init=lambda: None, parallel=2, timeout=30, **common)
    elif scenario == "timeout":
        eng = PreforkEngine(task_fn=_timeout, worker_init=lambda: None, parallel=1, timeout=1,
                            term_grace=1, poll_interval=0.1, **common)
    elif scenario == "worker_init":
        eng = PreforkEngine(task_fn=_worker_init_task, worker_init=_worker_init_flag,
                            parallel=1, timeout=30, **common)
    else:
        print("unknown scenario: %s" % scenario, file=sys.stderr)
        sys.exit(2)

    eng.run()


if __name__ == "__main__":
    main()
