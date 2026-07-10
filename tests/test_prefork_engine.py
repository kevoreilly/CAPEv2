import os
import threading
import time

import pytest

from lib.cuckoo.core.data.task import TASK_COMPLETED, TASK_FAILED_PROCESSING, TASK_REPORTED
from lib.cuckoo.core.database import Database, init_database, reset_database_FOR_TESTING_ONLY
from lib.cuckoo.core.processing_engine.prefork import PreforkEngine
from lib.cuckoo.core.processing_engine.source import TaskSource


@pytest.fixture
def db_file(tmp_path):
    """File-backed SQLite fixture needed for fork tests: in-memory sqlite://
    is per-connection so cross-process writes are invisible to the parent."""
    dsn = f"sqlite:///{tmp_path}/test.db"
    reset_database_FOR_TESTING_ONLY()
    try:
        init_database(dsn=dsn)
        retval = Database()
        yield retval
    finally:
        reset_database_FOR_TESTING_ONLY()


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
    with db_file.session.begin():
        tid = db_file.add_path(temp_pe32)
        db_file.set_status(tid, TASK_COMPLETED)

    # child runs this; it must set status itself (child sets, supervisor overrides only on failure)
    def task_fn(task):
        # fresh DB connection in child (file-backed SQLite so the write is
        # visible to the parent); must be wrapped in a transaction to commit
        from lib.cuckoo.core.database import Database
        db = Database()
        with db.session.begin():
            db.set_status(task.id, TASK_REPORTED)

    eng = PreforkEngine(task_fn=task_fn, worker_init=lambda: None,
                        source=TaskSource(db_file), parallel=2, timeout=30, max_count=1)
    eng.run()
    with db_file.session.begin():
        assert db_file.view_task(tid).status == TASK_REPORTED


def test_crashing_task_marked_failed_by_supervisor(db, temp_pe32):
    with db.session.begin():
        tid = db.add_path(temp_pe32)
        db.set_status(tid, TASK_COMPLETED)

    def task_fn(task):
        os._exit(3)  # simulate abnormal exit / crash

    eng = PreforkEngine(task_fn=task_fn, worker_init=lambda: None,
                        source=TaskSource(db), parallel=2, timeout=30, max_count=1)
    eng.run()
    with db.session.begin():
        assert db.view_task(tid).status == TASK_FAILED_PROCESSING


def test_timeout_kills_process_group_no_orphans(db, temp_pe32):
    with db.session.begin():
        tid = db.add_path(temp_pe32)
        db.set_status(tid, TASK_COMPLETED)

    marker = "/tmp/prefork_orphan_%d" % os.getpid()

    def task_fn(task):
        # spawn a grandchild that would outlive the worker, then hang
        import subprocess
        import sys
        subprocess.Popen([sys.executable, "-c",
                          "import time,os;open(%r,'w').close();time.sleep(120)" % marker])
        time.sleep(120)

    eng = PreforkEngine(task_fn=task_fn, worker_init=lambda: None, source=TaskSource(db),
                        parallel=1, timeout=1, term_grace=1, max_count=1, poll_interval=0.1)
    if os.path.exists(marker):
        os.unlink(marker)
    eng.run()

    with db.session.begin():
        assert db.view_task(tid).status == TASK_FAILED_PROCESSING

    # grandchild must have been swept by killpg (give it a moment)
    time.sleep(2)
    # Sanity: the grandchild must have started and written the marker
    # before being killed; otherwise the pgrep check below would pass vacuously.
    assert os.path.exists(marker), "grandchild never started — test is vacuous"
    import subprocess
    out = subprocess.run(["pgrep", "-f", marker], capture_output=True, text=True)
    assert out.stdout.strip() == "", "orphaned grandchild survived killpg"
    if os.path.exists(marker):
        os.unlink(marker)


def test_worker_init_called_in_child(db_file, temp_pe32):
    with db_file.session.begin():
        tid = db_file.add_path(temp_pe32)
        db_file.set_status(tid, TASK_COMPLETED)
    flag = "/tmp/prefork_winit_ran_%d" % os.getpid()

    def worker_init():
        open(flag, "w").close()

    def task_fn(task):
        assert os.path.exists(flag), "worker_init must run before task_fn in child"
        from lib.cuckoo.core.database import Database
        db = Database()
        with db.session.begin():
            db.set_status(task.id, TASK_REPORTED)

    if os.path.exists(flag):
        os.unlink(flag)
    try:
        eng = PreforkEngine(task_fn=task_fn, worker_init=worker_init, source=TaskSource(db_file),
                            parallel=1, timeout=30, max_count=1)
        eng.run()
        with db_file.session.begin():
            assert db_file.view_task(tid).status == TASK_REPORTED
    finally:
        if os.path.exists(flag):
            os.unlink(flag)
