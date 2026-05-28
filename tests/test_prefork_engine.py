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
