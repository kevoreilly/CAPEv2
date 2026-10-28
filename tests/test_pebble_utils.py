import threading
import time

from lib.cuckoo.common import pebble_utils


class _BlockingJoinPool:
    """join() never returns: models pebble's unbounded _stop_pool() reap of a
    worker stuck in uninterruptible (D-state) IO."""

    active = True

    def __init__(self):
        self.closed = False
        self.stop_calls = 0
        self.join_calls = 0
        self._never = threading.Event()

    def close(self):
        self.closed = True

    def stop(self):
        self.stop_calls += 1

    def join(self, timeout=None):
        self.join_calls += 1
        self._never.wait()


class _CleanPool:
    active = True

    def __init__(self):
        self.closed = False
        self.stopped = False
        self.join_timeouts = []

    def close(self):
        self.closed = True

    def stop(self):
        self.stopped = True

    def join(self, timeout=None):
        self.join_timeouts.append(timeout)


def test_teardown_returns_within_bound_when_join_blocks_forever():
    pool = _BlockingJoinPool()
    t0 = time.monotonic()
    reaped = pebble_utils.teardown_pool(pool, join_timeout=0.2, stop_join_timeout=0.2)
    elapsed = time.monotonic() - t0

    assert reaped is False
    assert elapsed < 2.0, f"teardown must be wall-clock bounded, took {elapsed:.2f}s"
    assert pool.closed is True
    assert pool.stop_calls == 1, "a wedged pool must be force-stopped"
    # The graceful join() thread is reused after stop(); a second concurrent
    # join() would race pebble's _stop_pool().
    assert pool.join_calls == 1


def test_force_teardown_returns_within_bound_when_join_blocks_forever():
    pool = _BlockingJoinPool()
    t0 = time.monotonic()
    reaped = pebble_utils.teardown_pool(pool, join_timeout=60, stop_join_timeout=0.2, force=True)
    elapsed = time.monotonic() - t0

    assert reaped is False
    assert elapsed < 2.0, f"forced teardown must not wait join_timeout, took {elapsed:.2f}s"
    assert pool.closed is False
    assert pool.stop_calls == 1
    assert pool.join_calls == 1


def test_teardown_clean_pool_is_reaped_without_stop():
    pool = _CleanPool()
    assert pebble_utils.teardown_pool(pool, join_timeout=7, stop_join_timeout=1) is True
    assert pool.closed is True
    assert pool.stopped is False
    assert pool.join_timeouts == [7]


def test_teardown_none_is_noop():
    assert pebble_utils.teardown_pool(None, join_timeout=1, stop_join_timeout=1) is True


def test_is_pool_healthy_none_is_false():
    assert pebble_utils.is_pool_healthy(None) is False


def test_teardown_real_pebble_pool():
    import multiprocessing

    import pebble

    pool = pebble.ProcessPool(max_workers=1, context=multiprocessing.get_context("fork"))
    assert pool.schedule(sum, args=([1, 2],)).result(timeout=30) == 3
    assert pebble_utils.is_pool_healthy(pool) is True
    assert pebble_utils.teardown_pool(pool, join_timeout=10, stop_join_timeout=5) is True
    assert pebble_utils.is_pool_healthy(pool) is False
