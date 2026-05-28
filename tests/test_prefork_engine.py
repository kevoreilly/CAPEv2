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
