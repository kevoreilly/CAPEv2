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


def test_shutdown_inflight_terminates_and_escalates_remaining_children(monkeypatch):
    """_shutdown_inflight must send SIGTERM to in-flight children, wait for exit
    up to term_grace, escalate remaining children to SIGKILL, and reap them."""
    eng = _engine()
    eng.term_grace = 0.05
    eng.poll_interval = 0.01

    child1 = _Child(task_id=1, pid=101, start=0.0, pgid=101)
    child2 = _Child(task_id=2, pid=102, start=0.0, pgid=102)
    eng._inflight[101] = child1
    eng._inflight[102] = child2

    signaled = []
    monkeypatch.setattr(eng, "_signal_child", lambda child, sig: signaled.append((child.pid, sig)) or True)

    def fake_waitpid(pid, options):
        if pid == 101:
            return 101, 0
        if options == 0 and pid == 102:
            return 102, 0
        return 0, 0

    monkeypatch.setattr(os, "waitpid", fake_waitpid)

    eng._shutdown_inflight()

    assert eng._inflight == {}
    assert (101, signal.SIGTERM) in signaled
    assert (102, signal.SIGTERM) in signaled
    assert (102, signal.SIGKILL) in signaled
    assert (101, signal.SIGKILL) not in signaled


def test_check_webgui_mongo_reuses_single_client_and_closes_on_exit(monkeypatch):
    """check_webgui_mongo must reuse the client returned by connect_to_mongo()
    during index creation/drop (instead of opening a second MongoClient via
    get_mongodb()) and reset _client to None on exit."""
    import dev_utils.mongodb as mdb_mod
    import lib.cuckoo.core.startup as startup

    connect_calls = 0
    closed_calls = 0

    class _FakeCollection:
        def create_index(self, *args, **kwargs):
            return "idx"

        def drop_index(self, *args, **kwargs):
            return None

    class _FakeDB:
        def __getattr__(self, name):
            return _FakeCollection()

    class _FakeClient:
        def __init__(self):
            self._opened = True

        def __getitem__(self, item):
            return _FakeDB()

        def close(self):
            nonlocal closed_calls
            closed_calls += 1

    def _fake_connect():
        nonlocal connect_calls
        connect_calls += 1
        return _FakeClient()

    monkeypatch.setattr(mdb_mod, "_client", None)
    monkeypatch.setattr(mdb_mod, "_results_db", None)
    monkeypatch.setattr(startup.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(mdb_mod.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(mdb_mod, "connect_to_mongo", _fake_connect)

    startup.check_webgui_mongo(exit_on_connection_failure=False)

    assert connect_calls == 1, "check_webgui_mongo should connect only once, not twice"
    assert closed_calls >= 1
    assert mdb_mod._client is None
    assert mdb_mod._results_db is None


def test_reset_mongodb_after_fork_clears_globals_without_close(monkeypatch):
    """_reset_mongodb_after_fork must clear _client and _results_db in child
    without calling client.close() (which would close parent's sockets)."""
    import dev_utils.mongodb as mdb_mod

    closed = False

    class _FakeClient:
        def __init__(self):
            self._opened = True

        def close(self):
            nonlocal closed
            closed = True

    client = _FakeClient()
    monkeypatch.setattr(mdb_mod, "_client", client)
    monkeypatch.setattr(mdb_mod, "_results_db", "fake_db")

    mdb_mod._reset_mongodb_after_fork()

    assert mdb_mod._client is None
    assert mdb_mod._results_db is None
    assert client._opened is False
    assert closed is False, "_reset_mongodb_after_fork must not call client.close()"
