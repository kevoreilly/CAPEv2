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
    eng = PreforkEngine(
        task_fn=lambda t: None, worker_init=lambda: None,
        source=_FakeSource(), parallel=2, timeout=10, term_grace=0,
    )
    eng._inflight[444] = _Child(task_id=4, pid=444, start=0.0, pgid=444)

    signals_sent = []
    reaped = []
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: signals_sent.append((pgid, sig)))
    monkeypatch.setattr(os, "waitpid", lambda pid, flags: (reaped.append((pid, flags)) or (pid, 0)))

    eng._shutdown_inflight()

    assert (444, signal.SIGTERM) in signals_sent
    assert (444, signal.SIGKILL) in signals_sent
    assert reaped == [(444, 0)]
    assert eng._inflight == {}


def test_check_webgui_mongo_closes_clients_before_fork(monkeypatch):
    """check_webgui_mongo must close its temporary MongoClient and call
    close_mongodb() so no PyMongo background monitor threads remain alive when
    PreforkEngine._assert_single_threaded() runs."""
    import dev_utils.mongodb as mdb_mod
    import lib.cuckoo.core.startup as startup

    closed = {"client": False, "module": False}

    class _FakeClient:
        def close(self):
            closed["client"] = True

    monkeypatch.setattr(startup.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(mdb_mod, "connect_to_mongo", lambda: _FakeClient())
    monkeypatch.setattr(mdb_mod, "mongo_create_index", lambda *a, **k: None)
    monkeypatch.setattr(mdb_mod, "close_mongodb", lambda: closed.__setitem__("module", True))

    startup.check_webgui_mongo(exit_on_connection_failure=False)

    assert closed["client"] is True, "check_webgui_mongo leaked temporary MongoClient"
    assert closed["module"] is True, "check_webgui_mongo did not close module-level MongoClient"


def test_get_mongodb_discards_parent_client_after_fork(monkeypatch):
    """When _client was created in a parent process (_client_pid != os.getpid()),
    get_mongodb() must discard the parent client without calling parent_client.close()
    (marking _opened = False) and connect a fresh client for the new PID."""
    import dev_utils.mongodb as mdb_mod

    closed = []

    class _FakeClient:
        def __init__(self, name):
            self.name = name
            self._opened = True

        def __getitem__(self, item):
            return f"db_{self.name}_{item}"

        def close(self):
            closed.append(self.name)

    c1 = _FakeClient("parent")
    c2 = _FakeClient("child")
    created = [c1, c2]

    monkeypatch.setattr(mdb_mod, "_client", None)
    monkeypatch.setattr(mdb_mod, "_results_db", None)
    monkeypatch.setattr(mdb_mod, "_client_pid", None)
    monkeypatch.setattr(mdb_mod.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(mdb_mod, "connect_to_mongo", lambda: created.pop(0))

    monkeypatch.setattr(os, "getpid", lambda: 1000)
    db1 = mdb_mod.get_mongodb()
    assert db1 == f"db_parent_{mdb_mod.mdb}"
    assert mdb_mod._client is c1
    assert mdb_mod._client_pid == 1000

    monkeypatch.setattr(os, "getpid", lambda: 2000)
    db2 = mdb_mod.get_mongodb()

    assert closed == [], "Parent client's close() must NOT be called in child"
    assert c1._opened is False, "Parent client._opened must be set to False to silence ResourceWarning"
    assert db2 == f"db_child_{mdb_mod.mdb}"
    assert mdb_mod._client is c2
    assert mdb_mod._client_pid == 2000

    mdb_mod.close_mongodb()
    assert "child" in closed


def test_reset_mongodb_after_fork_clears_globals_without_close(monkeypatch):
    """_reset_mongodb_after_fork must clear module globals without invoking close()."""
    import dev_utils.mongodb as mdb_mod

    closed = []

    class _FakeClient:
        def __init__(self):
            self._opened = True

        def close(self):
            closed.append(True)

    fake = _FakeClient()
    monkeypatch.setattr(mdb_mod, "_client", fake)
    monkeypatch.setattr(mdb_mod, "_results_db", "fake_db")
    monkeypatch.setattr(mdb_mod, "_client_pid", 1000)

    mdb_mod._reset_mongodb_after_fork()

    assert mdb_mod._client is None
    assert mdb_mod._results_db is None
    assert mdb_mod._client_pid is None
    assert fake._opened is False
    assert closed == [], "_reset_mongodb_after_fork must not call client.close()"


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
    monkeypatch.setattr(mdb_mod, "_client_pid", None)
    monkeypatch.setattr(startup.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(mdb_mod.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(mdb_mod, "connect_to_mongo", _fake_connect)

    startup.check_webgui_mongo(exit_on_connection_failure=False)

    assert connect_calls == 1, "check_webgui_mongo should connect only once, not twice"
    assert closed_calls >= 1
    assert mdb_mod._client is None
    assert mdb_mod._results_db is None
    assert mdb_mod._client_pid is None
