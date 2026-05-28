import pytest
from lib.cuckoo.core.processing_engine import get_engine
from lib.cuckoo.core.processing_engine.base import ProcessingEngine


def _noop(*a, **k):
    pass


def test_get_engine_returns_requested_class():
    eng = get_engine("pebble", task_fn=_noop, worker_init=_noop, source=None, parallel=2, timeout=900)
    assert isinstance(eng, ProcessingEngine)


def test_get_engine_unknown_raises():
    with pytest.raises(ValueError):
        get_engine("nope", task_fn=_noop, worker_init=_noop, source=None, parallel=2, timeout=900)
