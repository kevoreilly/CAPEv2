"""The supervisor must compile YARA once before the engine forks any workers, so
forked children inherit the compiled ruleset via COW instead of each paying the
~3s recompile (critical for prefork's one-task-per-child model)."""
import lib.cuckoo.core.processing_engine as pe
import lib.cuckoo.core.processing_engine.source as pe_source
import utils.process as process
from lib.cuckoo.common.objects import File


def test_autoprocess_prewarms_yara_before_engine_runs(monkeypatch):
    File.yara_initialized = False
    observed = {}

    def fake_init_yara(cls, *a, **k):
        cls.yara_initialized = True

    monkeypatch.setattr(File, "init_yara", classmethod(fake_init_yara))

    class _FakeEngine:
        max_count = 0
        max_tasks = 0

        def run(self):
            # Record whether YARA was already compiled at the moment the engine
            # (which is what forks workers) starts running.
            observed["yara_ready_at_run"] = File.yara_initialized

    monkeypatch.setattr(pe, "get_engine", lambda *a, **k: _FakeEngine())
    monkeypatch.setattr(pe_source, "TaskSource", lambda *a, **k: object())
    monkeypatch.setattr(process, "memory_limit", lambda *a, **k: None)

    process.autoprocess(engine="prefork", disable_memory_limit=True)

    assert observed.get("yara_ready_at_run") is True, \
        "YARA must be compiled before the engine runs (before any fork)"


def test_init_worker_appends_handlers_without_addHandler_lock(monkeypatch, tmp_path):
    """init_worker runs in forked children; it must append handlers directly
    to log.handlers instead of calling log.addHandler() (which acquires the
    process-wide logging._lock that may have been held across fork), and must
    not crash if a prior test reset _DATABASE to None."""
    from lib.cuckoo.core.database import reset_database_FOR_TESTING_ONLY

    reset_database_FOR_TESTING_ONLY()
    (tmp_path / "log").mkdir(exist_ok=True)
    monkeypatch.setattr(process, "CUCKOO_ROOT", str(tmp_path))
    add_handler_called = []
    monkeypatch.setattr(process.log, "addHandler", lambda h: add_handler_called.append(h))
    orig_handlers = list(process.log.handlers)
    try:
        process.init_worker()
        assert add_handler_called == [], "init_worker must not call log.addHandler()"
        assert len(process.log.handlers) >= 2
    finally:
        for h in process.log.handlers:
            if h not in orig_handlers:
                try:
                    h.close()
                except Exception:
                    pass
        process.log.handlers[:] = orig_handlers


def test_autoprocess_exits_cleanly_on_memory_or_os_error(monkeypatch):
    """MemoryError or OSError in the supervisor loop must log remaining RAM and exit(1)."""
    import pytest

    monkeypatch.setattr(File, "init_yara", classmethod(lambda cls, *a, **k: None))
    monkeypatch.setattr(process, "memory_limit", lambda *a, **k: None)
    monkeypatch.setattr(pe_source, "TaskSource", lambda *a, **k: object())

    class _OOMEngine:
        max_count = 0
        max_tasks = 0

        def run(self):
            raise MemoryError("simulated OOM")

    monkeypatch.setattr(pe, "get_engine", lambda *a, **k: _OOMEngine())

    with pytest.raises(SystemExit) as excinfo:
        process.autoprocess(engine="pebble", disable_memory_limit=True)
    assert excinfo.value.code == 1


def test_autoprocess_single_instance_flock_blocks_second_supervisor(monkeypatch, tmp_path, caplog):
    """A second concurrent autoprocess() supervisor on the same CUCKOO_ROOT must
    exit(1) instead of exceeding CAPE_PARALLEL or double-processing tasks."""
    import logging
    import pytest

    monkeypatch.setattr(process, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(File, "init_yara", classmethod(lambda cls, *a, **k: None))
    monkeypatch.setattr(process, "memory_limit", lambda *a, **k: None)
    monkeypatch.setattr(pe_source, "TaskSource", lambda *a, **k: object())

    nested_exit_code = {}
    recorded_titles = []
    monkeypatch.setattr(process, "setproctitle", lambda t: recorded_titles.append(t))

    class _NestedCheckEngine:
        max_count = 0
        max_tasks = 0

        def run(self):
            recorded_titles.append(("at_run", recorded_titles[-1] if recorded_titles else ""))
            with pytest.raises(SystemExit) as nested_exc:
                process.autoprocess(parallel=1, engine="pebble", disable_memory_limit=True)
            nested_exit_code["code"] = nested_exc.value.code

    monkeypatch.setattr(pe, "get_engine", lambda *a, **k: _NestedCheckEngine())

    with caplog.at_level(logging.INFO):
        process.autoprocess(parallel=2, engine="pebble", disable_memory_limit=True)

    assert nested_exit_code.get("code") == 1
    assert any(
        isinstance(item, tuple) and item[0] == "at_run" and "[supervisor parallel=2]" in item[1]
        for item in recorded_titles
    )
    assert recorded_titles[-1] == process.original_proctitle
    assert "Processing analysis data (engine=pebble, parallel=2)" in caplog.text


def test_autoprocess_forked_child_closes_inherited_lock_fd(monkeypatch, tmp_path):
    """A forked worker child must close its inherited process_auto.lock FD so a
    dying/wedged worker outliving the supervisor cannot block a new supervisor."""
    import fcntl
    import os

    monkeypatch.setattr(process, "CUCKOO_ROOT", str(tmp_path))
    lock_file = process._acquire_autoprocess_lock(str(tmp_path))
    assert lock_file is not None

    r_fd, w_fd = os.pipe()
    ready_r, ready_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(r_fd)
        os.close(ready_r)
        # Child should already have closed _AUTO_LOCK_FD via os.register_at_fork
        os.write(ready_w, b"1")
        os.close(ready_w)
        # Wait until parent tells us to exit
        os.close(w_fd)
        os._exit(0)

    os.close(w_fd)
    os.close(ready_w)
    try:
        assert os.read(ready_r, 1) == b"1"
        # Simulate supervisor releasing its lock while the forked child is still alive
        process._AUTO_LOCK_FD = None
        lock_file.close()

        probe = open(tmp_path / "log" / "process_auto.lock", "r+")
        try:
            # Must not raise BlockingIOError even though the forked child is still alive
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(probe, fcntl.LOCK_UN)
        finally:
            probe.close()
    finally:
        os.close(ready_r)
        os.close(r_fd)
        os.waitpid(pid, 0)

