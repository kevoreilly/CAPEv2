"""Extractor sub-pool lifecycle: per-call (pebble default) vs shared-per-child
(prefork). Under prefork a single pool is reused across every extracted file in
the task child and torn down once; under pebble each call gets a fresh pool that
is closed+joined immediately (avoids the recycle-join deadlock)."""
import os

import lib.cuckoo.common.integrations.file_extra_info as fx
from lib.cuckoo.core.processing_engine.prefork import PreforkEngine


class _FakePool:
    """Records close/join without forking real worker processes."""

    _counter = 0

    def __init__(self):
        _FakePool._counter += 1
        self.id = _FakePool._counter
        self.closed = False
        self.joined = False

    def close(self):
        self.closed = True

    def join(self, timeout=None):
        self.joined = True


def _reset(monkeypatch):
    """Point the pool factory at _FakePool and reset shared state."""
    monkeypatch.setattr(fx, "_new_extractor_pool", lambda: _FakePool())
    monkeypatch.setattr(fx, "_SHARED_EXTRACTOR_POOL", None, raising=False)
    monkeypatch.setattr(fx, "_USE_SHARED_POOL", False, raising=False)


def test_per_call_mode_returns_fresh_pool_each_time(monkeypatch):
    _reset(monkeypatch)
    pool_a, shared_a = fx._acquire_extractor_pool()
    pool_b, shared_b = fx._acquire_extractor_pool()
    assert shared_a is False and shared_b is False
    assert pool_a is not pool_b


def test_shared_mode_reuses_same_pool(monkeypatch):
    _reset(monkeypatch)
    fx.enable_shared_extractor_pool()
    pool_a, shared_a = fx._acquire_extractor_pool()
    pool_b, shared_b = fx._acquire_extractor_pool()
    assert shared_a is True and shared_b is True
    assert pool_a is pool_b


def test_shutdown_closes_and_clears_shared_pool(monkeypatch):
    _reset(monkeypatch)
    fx.enable_shared_extractor_pool()
    pool, _ = fx._acquire_extractor_pool()
    fx.shutdown_shared_extractor_pool()
    assert pool.closed is True
    assert pool.joined is True
    # A subsequent acquire must build a brand-new pool, not reuse the dead one.
    pool_next, _ = fx._acquire_extractor_pool()
    assert pool_next is not pool


def test_shutdown_is_idempotent_when_no_pool(monkeypatch):
    _reset(monkeypatch)
    # No pool created yet, shared mode off: must not raise.
    fx.shutdown_shared_extractor_pool()
    fx.enable_shared_extractor_pool()
    # Enabled but never acquired: still a no-op, no raise.
    fx.shutdown_shared_extractor_pool()


class _Task:
    id = 1
    category = "file"


def test_prefork_child_enables_and_tears_down_shared_pool(tmp_path):
    """The prefork child must (1) opt into the shared extractor pool before
    running the task and (2) tear it down once when the task finishes. Verified
    across a real fork: the child records both observations to marker files."""
    enabled_marker = tmp_path / "enabled"
    closed_marker = tmp_path / "closed"

    def task_fn(task):
        # Runs inside the forked child. Observe that shared mode is already on,
        # then install a fake pool so teardown has something to close.
        enabled_marker.write_text("yes" if fx._USE_SHARED_POOL else "no")

        class _FakeChildPool:
            def close(self):
                closed_marker.write_text("closed")

            def join(self, timeout=None):
                pass

        fx._new_extractor_pool = lambda: _FakeChildPool()
        fx._acquire_extractor_pool()  # store the shared fake pool

    eng = PreforkEngine(task_fn=task_fn, worker_init=lambda: None,
                        source=None, parallel=1, timeout=30)

    pid = os.fork()
    if pid == 0:
        try:
            eng._child_main(_Task())
        finally:
            os._exit(0)
    os.waitpid(pid, 0)

    assert enabled_marker.read_text() == "yes"
    assert closed_marker.read_text() == "closed"
