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
    process-wide logging._lock that may have been held across fork)."""
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

