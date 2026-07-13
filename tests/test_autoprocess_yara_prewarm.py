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
