import functools
import os
import pickle

from lib.cuckoo.core.data.task import TASK_COMPLETED
from lib.cuckoo.core.processing_engine.pebble import PebbleEngine
from lib.cuckoo.core.processing_engine.source import TaskSource


# Must be module-level (not a closure) so pickle can serialise it.
def _task_fn_write_sentinel(task):
    """Writes task.id to an env-var-specified sentinel file.

    Runs inside a pebble subprocess.  Uses os.environ to communicate the
    sentinel path because closures are not picklable with stdlib pickle.
    """
    sentinel = os.environ.get("_PEBBLE_TEST_SENTINEL", "")
    if sentinel:
        with open(sentinel, "w") as fh:
            fh.write(str(task.id))


def test_pebble_engine_processes_one_task(db, temp_pe32, tmp_path, monkeypatch):
    """PebbleEngine schedules a TASK_COMPLETED task, calls task_fn in a
    worker subprocess, drains completely, and returns.

    We use a filesystem sentinel to confirm task_fn executed.
    threading.Event cannot cross process boundaries; closures are not
    picklable with stdlib pickle so we pass the path via os.environ."""
    with db.session.begin():
        tid = db.add_path(temp_pe32)
        db.set_status(tid, TASK_COMPLETED)

    # run() calls free_space_monitor(storage/analyses, ...), which sys.exit()s when
    # that path doesn't exist (as in CI). Stub it — disk policy isn't under test here.
    monkeypatch.setattr("lib.cuckoo.common.cleaners_utils.free_space_monitor", lambda *a, **k: None)

    sentinel = str(tmp_path / "ran.txt")
    monkeypatch.setenv("_PEBBLE_TEST_SENTINEL", sentinel)

    eng = PebbleEngine(task_fn=_task_fn_write_sentinel, worker_init=lambda: None,
                       source=TaskSource(db), parallel=2, timeout=30, max_count=1)
    eng.run()

    # run() only returns after all in-flight futures complete (drain guarantee).
    assert eng._pending == {}, "drain loop should leave _pending empty"
    # Confirm task_fn actually executed in the worker subprocess.
    assert os.path.exists(sentinel), "worker did not write sentinel — task_fn never ran"
    assert open(sentinel).read().strip() == str(tid)


def test_autoprocess_task_fn_is_picklable():
    """Regression: pebble dispatches task_fn over multiprocessing pipes; a
    function-scope lambda would crash with 'Can't pickle local object' on the
    first task. functools.partial is picklable; lambdas are not."""
    from utils.process import run_task
    task_fn = functools.partial(run_task, memory_debugging=False, debug=False)
    pickle.dumps(task_fn)  # would raise PicklingError for a lambda
