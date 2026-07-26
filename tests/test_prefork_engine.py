import os
import subprocess
import sys
import threading
import time

import pytest

from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_FAILED_PROCESSING, TASK_REPORTED
from lib.cuckoo.core.database import Database, init_database, reset_database_FOR_TESTING_ONLY
from lib.cuckoo.core.processing_engine.prefork import PreforkEngine
from lib.cuckoo.core.processing_engine.source import TaskSource

_SUBPROC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_prefork_engine_subproc.py")


@pytest.fixture
def db_file(tmp_path):
    """File-backed SQLite fixture needed for fork tests: in-memory sqlite://
    is per-connection so cross-process writes are invisible to the parent.
    Yields ``(db, dsn)`` so the isolated subprocess can open the same file."""
    dsn = f"sqlite:///{tmp_path}/test.db"
    reset_database_FOR_TESTING_ONLY()
    try:
        init_database(dsn=dsn)
        retval = Database()
        yield retval, dsn
    finally:
        reset_database_FOR_TESTING_ONLY()


def _run_engine_subprocess(scenario, dsn, tid, aux="", timeout=60):
    """Run PreforkEngine in a fresh single-threaded interpreter (the pytest process
    is multi-threaded and cannot satisfy the single-threaded-before-fork invariant
    nor safely fork). Returns the CompletedProcess."""
    return subprocess.run(
        [sys.executable, _SUBPROC, scenario, dsn, str(tid), aux],
        capture_output=True, text=True, timeout=timeout,
    )


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


def test_single_threaded_invariant_raises_on_kernel_thread_count(db, monkeypatch):
    """Native C-extension threads (e.g. STPyV8's V8 worker pool) show up in
    /proc/self/task but NOT in threading.active_count(). The supervisor must
    catch them — otherwise it forks from a multi-kernel-thread state."""
    eng = PreforkEngine(task_fn=lambda t: None, worker_init=lambda: None,
                        source=TaskSource(db), parallel=2, timeout=30)

    # Simulate a process with 1 Python thread but several kernel threads
    # (e.g., STPyV8 spawned 16 V8 workers at import; Python sees only main).
    import os as _os
    real_listdir = _os.listdir

    def fake_listdir(path):
        if path == "/proc/self/task":
            return ["1", "2", "3", "4"]  # 4 fake kernel threads
        return real_listdir(path)

    monkeypatch.setattr(os, "listdir", fake_listdir)
    import pytest
    with pytest.raises(RuntimeError, match="single-threaded"):
        eng._assert_single_threaded()


def test_normal_task_runs_and_status_set_by_child(db_file, temp_pe32):
    db, dsn = db_file
    with db.session.begin():
        tid = db.add_path(temp_pe32)
        db.set_status(tid, TASK_COMPLETED)

    r = _run_engine_subprocess("normal", dsn, tid)
    assert r.returncode == 0, r.stderr

    db.session.expire_all()  # subprocess wrote via a separate connection; drop cached rows
    with db.session.begin():
        assert db.view_task(tid).status == TASK_REPORTED


def test_crashing_task_marked_failed_by_supervisor(db_file, temp_pe32):
    db, dsn = db_file
    with db.session.begin():
        tid = db.add_path(temp_pe32)
        db.set_status(tid, TASK_COMPLETED)

    r = _run_engine_subprocess("crash", dsn, tid)
    assert r.returncode == 0, r.stderr

    db.session.expire_all()
    with db.session.begin():
        assert db.view_task(tid).status == TASK_FAILED_PROCESSING


def test_timeout_kills_process_group_no_orphans(db_file, temp_pe32, tmp_path):
    db, dsn = db_file
    with db.session.begin():
        tid = db.add_path(temp_pe32)
        db.set_status(tid, TASK_COMPLETED)

    marker = str(tmp_path / "orphan_marker")
    r = _run_engine_subprocess("timeout", dsn, tid, aux=marker, timeout=60)
    assert r.returncode == 0, r.stderr

    db.session.expire_all()
    with db.session.begin():
        assert db.view_task(tid).status == TASK_FAILED_PROCESSING

    # Sanity: the grandchild must have started (written the marker) or the orphan
    # check below would pass vacuously.
    assert os.path.exists(marker), "grandchild never started — test is vacuous"
    time.sleep(2)  # give any survivor a chance to appear
    out = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
    assert out.stdout.strip() == "", "orphaned grandchild survived killpg"


def test_worker_init_called_in_child(db_file, temp_pe32, tmp_path):
    db, dsn = db_file
    with db.session.begin():
        tid = db.add_path(temp_pe32)
        db.set_status(tid, TASK_COMPLETED)

    flag = str(tmp_path / "winit_flag")
    # The subprocess's task_fn asserts the flag exists before setting status, so a
    # REPORTED result proves worker_init ran before task_fn in the child.
    r = _run_engine_subprocess("worker_init", dsn, tid, aux=flag)
    assert r.returncode == 0, r.stderr

    assert os.path.exists(flag), "worker_init did not run"
    db.session.expire_all()
    with db.session.begin():
        assert db.view_task(tid).status == TASK_REPORTED
