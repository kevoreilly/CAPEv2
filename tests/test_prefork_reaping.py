"""Timeout/reap state-machine correctness for the prefork supervisor, exercised
with monkeypatched os calls (no real forks): a timed-out child must not be reaped
before its process group is SIGKILL-escalated (else grandchildren orphan), and a
killpg that hits a not-yet-setsid child must fall back to signaling the pid."""
import os
import signal

from lib.cuckoo.core.processing_engine.prefork import PreforkEngine, _Child


class _FakeSource:
    def __init__(self):
        self.failed = []

    def mark_failed(self, task_id):
        self.failed.append(task_id)


def _engine():
    return PreforkEngine(
        task_fn=lambda t: None, worker_init=lambda: None,
        source=_FakeSource(), parallel=2, timeout=10, term_grace=5,
    )


def test_reap_defers_timed_out_child_until_escalated(monkeypatch):
    eng = _engine()
    child = _Child(task_id=1, pid=111, start=0.0, pgid=111)
    child.timed_out = True
    child.kill_deadline = 1e9  # SIGTERM sent, escalation not yet done
    eng._inflight[111] = child

    # waitpid WOULD report it exited; reap must not collect it yet.
    monkeypatch.setattr(os, "waitpid", lambda pid, flags: (pid, 0))
    eng._reap()
    assert 111 in eng._inflight, "timed-out child reaped before SIGKILL escalation -> grandchildren orphan"

    # once escalation clears kill_deadline, reap collects it
    child.kill_deadline = None
    eng._reap()
    assert 111 not in eng._inflight


def test_idle_supervisor_backs_off_polling():
    """Fully idle (nothing in-flight, nothing launched) -> long sleep, not a 0.2s
    hot loop hammering the DB ~5x/sec."""
    eng = PreforkEngine(
        task_fn=lambda t: None, worker_init=lambda: None, source=_FakeSource(),
        parallel=2, timeout=10, poll_interval=0.2, idle_poll_interval=5.0,
    )
    assert eng._sleep_interval(launched=0) == 5.0  # idle -> back off

    # Actively working: launched something OR has in-flight -> tight poll.
    assert eng._sleep_interval(launched=1) == 0.2
    eng._inflight[1] = _Child(task_id=1, pid=1, start=0.0, pgid=1)
    assert eng._sleep_interval(launched=0) == 0.2  # in-flight -> reap promptly


def test_enforce_timeouts_falls_back_to_kill_when_killpg_missing(monkeypatch):
    eng = _engine()
    child = _Child(task_id=2, pid=222, start=0.0, pgid=222)  # start=0 => far past timeout
    eng._inflight[222] = child

    killed = []
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: (_ for _ in ()).throw(ProcessLookupError()))
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))

    eng._enforce_timeouts()

    assert child.timed_out is True
    assert (222, signal.SIGTERM) in killed, "must fall back to os.kill(pid) when killpg raises ProcessLookupError"
    assert child.kill_deadline is not None, "kill_deadline must be set so SIGKILL escalation still runs"


def test_escalate_kills_falls_back_to_kill_when_killpg_missing(monkeypatch):
    eng = _engine()
    child = _Child(task_id=3, pid=333, start=0.0, pgid=333)
    child.timed_out = True
    child.kill_deadline = -1.0  # deadline already passed -> escalate now
    eng._inflight[333] = child

    killed = []
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: (_ for _ in ()).throw(ProcessLookupError()))
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append((pid, sig)))

    eng._escalate_kills()

    assert (333, signal.SIGKILL) in killed, "SIGKILL must fall back to os.kill(pid) when killpg raises ProcessLookupError"
    assert child.kill_deadline is None
