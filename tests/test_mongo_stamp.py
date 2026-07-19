def test_stamp_tenant_context_into_info():
    from modules.reporting.mongodb import stamp_tenant_info

    class T:  # stand-in for a Task row
        user_id, tenant_id, visibility = 7, 10, "tenant"

    info = {"id": 42}
    stamp_tenant_info(info, T())
    assert info["tenant_id"] == 10 and info["user_id"] == 7 and info["visibility"] == "tenant"


def test_stamp_missing_task_fails_closed_private():
    """Finding #1: an unresolved task (deleted/orphan, transient DB error, or the
    distributed main_task_id lookup miss on a worker) must NOT be stamped
    world-visible. Fail CLOSED to private with no owner/tenant so it matches no
    cross-tenant scope (public/tenant/mine) and stays invisible to everyone but
    break-glass. Previously defaulted to 'public' (fail-open leak)."""
    from modules.reporting.mongodb import stamp_tenant_info
    info = {"id": 42}
    stamp_tenant_info(info, None)
    assert info["visibility"] == "private"
    assert info["tenant_id"] is None and info["user_id"] is None



def test_stamp_report_distributed_fails_closed():
    """run()'s distributed branch (main_task_id set) fails closed to private — the
    worker-local task does not carry the submitter's tenancy (dist.py forwards none)."""
    from modules.reporting.mongodb import _stamp_report_for_task
    info = {"id": 5}
    _stamp_report_for_task(info, main_task_id=99, local_task_id=5)
    assert info["visibility"] == "private"
    assert info["tenant_id"] is None and info["user_id"] is None


def test_stamp_report_local_path_uses_local_task(monkeypatch):
    """Non-distributed (no main_task_id): stamp from the LOCAL task's tenancy."""
    from modules.reporting import mongodb as m

    class T:
        user_id, tenant_id, visibility = 7, 10, "tenant"

    monkeypatch.setattr(m, "_task_tenant_ctx", lambda tid: T() if tid == 5 else None)
    info = {"id": 5}
    m._stamp_report_for_task(info, main_task_id=None, local_task_id=5)
    assert info["visibility"] == "tenant" and info["tenant_id"] == 10 and info["user_id"] == 7


def test_is_central_rewritten_id_discriminates_id_space():
    from modules.reporting.mongodb import _is_central_rewritten_id
    assert _is_central_rewritten_id("ui-42") is True
    assert _is_central_rewritten_id("ui-999") is True
    assert _is_central_rewritten_id("local-42") is False   # direct submit -> worker-local id
    assert _is_central_rewritten_id("") is False
    assert _is_central_rewritten_id(None) is False
    assert _is_central_rewritten_id("ui-abc") is False


def test_stamp_report_central_mode_uses_central_ctx(monkeypatch):
    """Central mode + a REWRITTEN (ui-*) id: stamp from the CENTRAL RDS
    (_task_tenant_ctx_central) keyed by the central id, NEVER the worker-local DB."""
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.central_mode as cm

    monkeypatch.setattr(cm, "central_mode_config",
                        lambda: cm.CentralModeConfig(enabled=True, central_database_url="postgresql://x"))

    class Central:
        tenant_id, user_id, visibility = 10, 7, "tenant"

    monkeypatch.setattr(m, "_task_tenant_ctx_central", lambda cid, conn=None: Central() if int(cid) == 42 else None)

    def _boom(_):
        raise AssertionError("must NOT read the worker-local DB for a rewritten ui-* id")
    monkeypatch.setattr(m, "_task_tenant_ctx", _boom)

    info = {"id": 42, "job_id": "ui-42"}
    m._stamp_report_for_task(info, main_task_id=None, local_task_id=42)
    assert info["tenant_id"] == 10 and info["user_id"] == 7 and info["visibility"] == "tenant"


def test_stamp_report_central_direct_submit_uses_local_db_not_central(monkeypatch):
    """HIGH regression: a CENTRAL-mode DIRECT submission (job_id NOT ui-*) keeps its
    WORKER-LOCAL info.id, so it must be resolved against the worker-local DB — resolving
    it against the central RDS would hit a COLLIDING central-id-space row (cross-tenant
    leak). Worker-local task #7 is tenant A; central task #7 is a different tenant B."""
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.central_mode as cm

    monkeypatch.setattr(cm, "central_mode_config",
                        lambda: cm.CentralModeConfig(enabled=True, central_database_url="postgresql://central"))

    class CentralTenantB:
        tenant_id, user_id, visibility = 99, 66, "public"

    class LocalTenantA:
        tenant_id, user_id, visibility = 10, 7, "tenant"

    monkeypatch.setattr(m, "_task_tenant_ctx_central", lambda cid, conn=None: CentralTenantB())  # must NOT be used
    monkeypatch.setattr(m, "_task_tenant_ctx", lambda tid: LocalTenantA() if int(tid) == 7 else None)

    info = {"id": 7, "job_id": "local-7"}   # direct submit: id NOT rewritten
    m._stamp_report_for_task(info, main_task_id=None, local_task_id=7)
    # stamped from the LOCAL row (tenant A), NOT the colliding central row (tenant B)
    assert (info["tenant_id"], info["user_id"], info["visibility"]) == (10, 7, "tenant")


def test_stamp_report_central_mode_fail_closed_when_unresolved(monkeypatch):
    """Central mode but the central task can't be resolved (URL unset / not found) ->
    fail closed to private/unowned, never a wrong-tenant or public stamp."""
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.central_mode as cm

    monkeypatch.setattr(cm, "central_mode_config",
                        lambda: cm.CentralModeConfig(enabled=True, central_database_url=""))
    monkeypatch.setattr(m, "_task_tenant_ctx_central", lambda cid, conn=None: None)  # unresolved

    info = {"id": 42}
    m._stamp_report_for_task(info, main_task_id=None, local_task_id=42)
    assert info["visibility"] == "private" and info["tenant_id"] is None and info["user_id"] is None


def test_task_tenant_ctx_central_none_when_url_unset(monkeypatch):
    """No central_database_url -> no engine -> None (fail-closed), no crash."""
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.central_mode as cm

    monkeypatch.setattr(m, "_CENTRAL_ENGINE", None, raising=False)
    monkeypatch.setattr(m, "_CENTRAL_ENGINE_URL", None, raising=False)
    monkeypatch.setattr(cm, "central_mode_config",
                        lambda: cm.CentralModeConfig(enabled=True, central_database_url=""))
    assert m._task_tenant_ctx_central(42) is None


def test_reconcile_central_uses_central_engine_lock(monkeypatch):
    """Central + ui-* id: the reconcile must take its advisory lock on the CENTRAL engine
    (same Postgres as set_task_visibility on the central node), not the worker-local
    engine — a worker-local lock wouldn't mutually exclude a central-node toggle."""
    from contextlib import contextmanager
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    import lib.cuckoo.common.central_mode as cm
    from lib.cuckoo.common.tenancy import MTConfig
    import lib.cuckoo.core.data.tasking as tasking
    import lib.cuckoo.core.database as dbmod

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    monkeypatch.setattr(cm, "central_mode_config",
                        lambda: cm.CentralModeConfig(enabled=True, central_database_url="postgresql://central"))
    _CENTRAL = object()
    monkeypatch.setattr(m, "_central_lock_engine", lambda: _CENTRAL)  # primary-validated central engine

    class _LocalDB:
        lock_engine = object()  # the WRONG engine to lock on for a central id
    monkeypatch.setattr(dbmod, "Database", lambda: _LocalDB())
    monkeypatch.setattr(m, "_task_tenant_ctx_central", lambda cid, conn=None: None)
    monkeypatch.setattr(m, "mongo_update_one", lambda *a, **k: object(), raising=False)

    seen = {}

    @contextmanager
    def fake_lock(lock_engine, task_id):
        seen["engine"] = lock_engine
        yield
    monkeypatch.setattr(tasking, "task_visibility_lock", fake_lock)

    m._reconcile_report_visibility(main_task_id=None, local_task_id=42, ids_to_delete={42}, job_id="ui-42")
    assert seen["engine"] is _CENTRAL   # locked the central engine, not _LocalDB.lock_engine


class _FakeConn:
    def __init__(self, in_recovery):
        self._r = in_recovery

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, *a, **k):
        r = self._r

        class _Res:
            def scalar(self):
                return r
        return _Res()


def test_central_lock_engine_refuses_standby(monkeypatch):
    """A read replica/standby (pg_is_in_recovery=True) can't serialize with the central
    toggle -> _central_lock_engine returns None (reconcile runs unserialized/fail-closed)."""
    from modules.reporting import mongodb as m

    class _Eng:
        def connect(self):
            return _FakeConn(True)
    monkeypatch.setattr(m, "_central_engine", lambda: _Eng())
    monkeypatch.setattr(m, "_CENTRAL_PRIMARY", None, raising=False)
    monkeypatch.setattr(m, "_CENTRAL_LOCK_WARNED", False, raising=False)
    assert m._central_lock_engine() is None


def test_central_lock_engine_uses_primary(monkeypatch):
    """A writer primary (pg_is_in_recovery=False) is used for the reconcile lock."""
    from modules.reporting import mongodb as m

    class _Eng:
        def connect(self):
            return _FakeConn(False)
    eng = _Eng()
    monkeypatch.setattr(m, "_central_engine", lambda: eng)
    assert m._central_lock_engine() is eng


def test_central_lock_engine_reprobes_after_transient_failure(monkeypatch):
    """A transient probe failure must NOT be cached as a permanent verdict: the next
    reconcile re-probes and serializes again against a recovered primary."""
    from modules.reporting import mongodb as m
    calls = {"n": 0}

    class _Eng:
        def connect(self):
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("transient: RDS restarting")
            return _FakeConn(False)  # healthy primary from the 2nd call on
    eng = _Eng()
    monkeypatch.setattr(m, "_central_engine", lambda: eng)
    monkeypatch.setattr(m, "_CENTRAL_LOCK_WARNED", False, raising=False)
    assert m._central_lock_engine() is None   # the blip: refuse this call
    assert m._central_lock_engine() is eng    # recovered: serialize again (no sticky cache)


def test_central_lock_engine_detects_demotion_to_standby(monkeypatch):
    """An in-place failover (same URL, endpoint now a standby) must be detected — a cached
    True would keep locking a demoted server that excludes nothing on the new primary."""
    from modules.reporting import mongodb as m
    state = {"in_recovery": False}

    class _Eng:
        def connect(self):
            return _FakeConn(state["in_recovery"])
    eng = _Eng()
    monkeypatch.setattr(m, "_central_engine", lambda: eng)
    monkeypatch.setattr(m, "_CENTRAL_LOCK_WARNED", False, raising=False)
    assert m._central_lock_engine() is eng    # primary: serialize
    state["in_recovery"] = True               # demoted in place
    assert m._central_lock_engine() is None    # re-probed: refuse


def test_reconcile_unserialized_central_path_does_not_widen(monkeypatch):
    """Standby (no validated primary lock): the central reconcile must NOT upgrade — a read
    from the lagging standby could re-widen a just-committed private. Leave run()'s stamp."""
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    import lib.cuckoo.common.central_mode as cm
    from lib.cuckoo.common.tenancy import MTConfig
    import lib.cuckoo.core.database as dbmod

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    monkeypatch.setattr(cm, "central_mode_config",
                        lambda: cm.CentralModeConfig(enabled=True, central_database_url="postgresql://standby"))
    monkeypatch.setattr(m, "_central_lock_engine", lambda: None)  # standby -> no primary lock

    class _StaleRow:  # the public->private toggle hasn't replicated to the standby yet
        tenant_id, user_id, visibility = 10, 7, "public"
    monkeypatch.setattr(m, "_task_tenant_ctx_central", lambda cid, conn=None: _StaleRow())

    class _LocalDB:
        lock_engine = None
    monkeypatch.setattr(dbmod, "Database", lambda: _LocalDB())

    seen = {}
    monkeypatch.setattr(m, "mongo_update_one",
                        lambda coll, flt, upd: seen.update(upd["$set"]) or object(), raising=False)

    m._reconcile_report_visibility(main_task_id=None, local_task_id=42, ids_to_delete={42}, job_id="ui-42")
    assert seen == {}   # no upgrade written -> run()'s fail-closed private stamp survives


def test_reconcile_central_url_unset_still_warns(monkeypatch, caplog):
    """A central+MT worker with no central_database_url must still log a warning (the
    diagnostic that reports are staying fail-closed private), not go silent."""
    import logging
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    import lib.cuckoo.common.central_mode as cm
    from lib.cuckoo.common.tenancy import MTConfig
    import lib.cuckoo.core.database as dbmod

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    monkeypatch.setattr(cm, "central_mode_config",
                        lambda: cm.CentralModeConfig(enabled=True, central_database_url=""))
    monkeypatch.setattr(m, "_CENTRAL_ENGINE", None, raising=False)
    monkeypatch.setattr(m, "_CENTRAL_ENGINE_URL", None, raising=False)
    monkeypatch.setattr(m, "_CENTRAL_LOCK_WARNED", False, raising=False)

    class _LocalDB:
        lock_engine = None
    monkeypatch.setattr(dbmod, "Database", lambda: _LocalDB())
    monkeypatch.setattr(m, "mongo_update_one", lambda *a, **k: object(), raising=False)

    with caplog.at_level(logging.WARNING, logger="modules.reporting.mongodb"):
        m._reconcile_report_visibility(main_task_id=None, local_task_id=42, ids_to_delete={42}, job_id="ui-42")
    assert any(r.levelno >= logging.WARNING for r in caplog.records)


def test_reconcile_visibility_noop_when_mt_disabled(monkeypatch):
    """MT off: the report-visibility reconcile must not touch mongo (upstream shape)."""
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    from lib.cuckoo.common.tenancy import MTConfig

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(False, "shared", "", True))
    called = []
    monkeypatch.setattr(m, "mongo_update_one", lambda *a, **k: called.append((a, k)), raising=False)
    m._reconcile_report_visibility(main_task_id=None, local_task_id=5, ids_to_delete={5})
    assert called == []  # no mongo write when MT disabled


def test_reconcile_visibility_restamps_from_sql_under_lock(monkeypatch):
    """MT on: the TOCTOU fix — the reconcile re-reads the AUTHORITATIVE SQL tenancy and
    updates the mongo doc UNDER the per-task advisory lock, so the value written is what
    SQL says NOW (e.g. after a toggle committed post-initial-stamp), not the stale value."""
    from contextlib import contextmanager
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    from lib.cuckoo.common.tenancy import MTConfig
    import lib.cuckoo.core.data.tasking as tasking
    import lib.cuckoo.core.database as dbmod

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))

    # SQL now says 'private' (a toggle committed after run() stamped the report public).
    class NowPrivate:
        user_id, tenant_id, visibility = 7, 10, "private"
    monkeypatch.setattr(m, "_task_tenant_ctx", lambda tid: NowPrivate())

    class _FakeDB:
        lock_engine = None
    monkeypatch.setattr(dbmod, "Database", lambda: _FakeDB())

    events = []

    @contextmanager
    def fake_lock(lock_engine, task_id):
        events.append(("lock", task_id))
        try:
            yield
        finally:
            events.append(("unlock", task_id))
    monkeypatch.setattr(tasking, "task_visibility_lock", fake_lock)

    captured = {}

    def fake_update(coll, flt, upd, **k):
        events.append(("update", flt))
        captured.update(upd)
        return object()  # a successful mongo write (not None)
    monkeypatch.setattr(m, "mongo_update_one", fake_update, raising=False)

    m._reconcile_report_visibility(main_task_id=None, local_task_id=5, ids_to_delete={5, 5})

    # the mongo update ran BETWEEN lock acquire and release
    assert [e[0] for e in events] == ["lock", "update", "unlock"]
    # and it wrote the authoritative (current) SQL tenancy, not a stale value
    assert captured["$set"]["info.visibility"] == "private"
    assert captured["$set"]["info.tenant_id"] == 10 and captured["$set"]["info.user_id"] == 7


def test_reconcile_skips_distributed_path(monkeypatch):
    """Legacy-dist path (main_task_id set): the doc is already fail-closed private and
    the lock/id domain differs from the central toggle, so the reconcile must NOT run
    a mongo write (which could strip tenancy off an unrelated doc via the $in filter)."""
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    from lib.cuckoo.common.tenancy import MTConfig

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    called = []
    monkeypatch.setattr(m, "mongo_update_one", lambda *a, **k: called.append(1), raising=False)
    m._reconcile_report_visibility(main_task_id=99, local_task_id=5, ids_to_delete={5})
    assert called == []  # distributed path is a no-op (stays fail-closed private)


def test_reconcile_write_failure_is_not_silent(monkeypatch, caplog):
    """mongo_update_one returns None when graceful_auto_reconnect exhausts its retries
    (no raise). Since the reconcile is the SOLE corrector of the fail-closed stamp, that
    silent no-op must be logged loudly."""
    import logging
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    from lib.cuckoo.common.tenancy import MTConfig
    import lib.cuckoo.core.database as dbmod

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))

    class NowPrivate:
        user_id, tenant_id, visibility = 7, 10, "private"
    monkeypatch.setattr(m, "_task_tenant_ctx", lambda tid: NowPrivate())

    class _FakeDB:
        lock_engine = None
    monkeypatch.setattr(dbmod, "Database", lambda: _FakeDB())
    monkeypatch.setattr(m, "mongo_update_one", lambda *a, **k: None, raising=False)  # exhausted -> None

    with caplog.at_level(logging.ERROR, logger="modules.reporting.mongodb"):
        m._reconcile_report_visibility(main_task_id=None, local_task_id=5, ids_to_delete={5})

    assert any(r.levelno >= logging.ERROR and "5" in r.getMessage() for r in caplog.records)


def test_reconcile_contains_failure_never_propagates(monkeypatch):
    """The reconcile runs in run()'s finally; an escape would flip a fully-stored report
    to failed_reporting / mask the storage block's exception. A lock-acquire failure
    (e.g. Postgres connection exhaustion) must be contained, not raised."""
    from contextlib import contextmanager
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    from lib.cuckoo.common.tenancy import MTConfig
    import lib.cuckoo.core.data.tasking as tasking
    import lib.cuckoo.core.database as dbmod

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))

    class _FakeDB:
        lock_engine = object()
    monkeypatch.setattr(dbmod, "Database", lambda: _FakeDB())
    monkeypatch.setattr(m, "mongo_update_one", lambda *a, **k: object(), raising=False)

    @contextmanager
    def failing_lock(lock_engine, task_id):
        raise RuntimeError("FATAL: sorry, too many clients already")
        yield
    monkeypatch.setattr(tasking, "task_visibility_lock", failing_lock)

    # must NOT raise (contained + logged)
    m._reconcile_report_visibility(main_task_id=None, local_task_id=5, ids_to_delete={5})


def test_task_visibility_lock_noop_without_engine():
    """task_visibility_lock is a no-op context when lock_engine is None (sqlite / MT off)."""
    from lib.cuckoo.core.data.tasking import task_visibility_lock
    ran = []
    with task_visibility_lock(None, 5):
        ran.append(True)
    assert ran == [True]


def test_task_visibility_lock_yields_lock_connection(monkeypatch):
    """task_visibility_lock yields the pinned advisory-lock connection so the caller can run
    its writer-primary re-check + tenancy re-read on the SAME backend that holds the lock."""
    import lib.cuckoo.core.data.tasking as tk

    sentinel = object()
    monkeypatch.setattr(tk, "_advisory_lock", lambda eng, key: sentinel)
    monkeypatch.setattr(tk, "_advisory_unlock", lambda conn, key: None)
    with tk.task_visibility_lock(object(), 9) as conn:
        assert conn is sentinel


class _RecoveryConn:
    """A pinned advisory-lock connection stub: answers pg_advisory_lock/unlock AND the
    in-lock pg_is_in_recovery() re-check with the configured recovery state."""

    def __init__(self, in_recovery):
        self._r = in_recovery

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, *a, **k):
        r = self._r

        class _Res:
            def scalar(self_inner):
                return r
        return _Res()

    def close(self):
        pass

    def invalidate(self):
        pass


def test_reconcile_central_revalidates_primary_on_lock_connection(monkeypatch):
    """Bind the writer-primary verdict to the SAME connection that holds the advisory lock.
    In-place failover between the pre-lock probe and the lock (or a multi-host URL): the
    probe connection is the old primary (connect #1), but the lock connection lands on a
    demoted, lagging standby (connect #2) whose stale 'public' would re-widen the committed
    private doc. The under-lock re-probe must catch it and skip fail-closed."""
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    import lib.cuckoo.common.central_mode as cm
    from lib.cuckoo.common.tenancy import MTConfig
    import lib.cuckoo.core.database as dbmod

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    monkeypatch.setattr(cm, "central_mode_config",
                        lambda: cm.CentralModeConfig(enabled=True, central_database_url="postgresql://writer"))

    state = {"connects": 0}

    class _Eng:
        def connect(self):
            state["connects"] += 1
            # connect #1 = _central_lock_engine()'s pre-lock probe: old primary.
            # connects #2+ = demoted in place right after: every new NullPool connection
            # is a lagging hot standby (pg_advisory_lock still acquires there, locally).
            return _RecoveryConn(state["connects"] > 1)
    monkeypatch.setattr(m, "_central_engine", lambda: _Eng())
    monkeypatch.setattr(m, "_CENTRAL_LOCK_WARNED", False, raising=False)

    class _StaleRow:  # replication-lag-stale: the public->private toggle hasn't shipped
        tenant_id, user_id, visibility = 10, 7, "public"
    monkeypatch.setattr(m, "_task_tenant_ctx_central", lambda cid, conn=None: _StaleRow())

    class _LocalDB:
        lock_engine = None
    monkeypatch.setattr(dbmod, "Database", lambda: _LocalDB())

    seen = {}
    monkeypatch.setattr(m, "mongo_update_one",
                        lambda coll, flt, upd: seen.update(upd["$set"]) or object(), raising=False)

    m._reconcile_report_visibility(main_task_id=None, local_task_id=42, ids_to_delete={42}, job_id="ui-42")
    assert seen == {}  # under-lock re-probe saw the standby -> skipped -> no re-widen


def test_reconcile_central_reads_tenancy_on_lock_connection(monkeypatch):
    """On the primary path the under-lock tenancy re-read must run on the SAME pinned
    connection that holds the advisory lock (probe + lock + read share one backend), and
    write the authoritative primary value."""
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    import lib.cuckoo.common.central_mode as cm
    from lib.cuckoo.common.tenancy import MTConfig
    import lib.cuckoo.core.database as dbmod

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    monkeypatch.setattr(cm, "central_mode_config",
                        lambda: cm.CentralModeConfig(enabled=True, central_database_url="postgresql://writer"))

    the_conn = _RecoveryConn(False)  # a writer primary

    class _Eng:
        def connect(self):
            return the_conn
    eng = _Eng()
    monkeypatch.setattr(m, "_central_lock_engine", lambda: eng)

    class _Row:
        tenant_id, user_id, visibility = 3, 4, "private"
    captured = {}

    def _read(cid, conn=None):
        captured["conn"] = conn
        return _Row()
    monkeypatch.setattr(m, "_task_tenant_ctx_central", _read)

    class _LocalDB:
        lock_engine = None
    monkeypatch.setattr(dbmod, "Database", lambda: _LocalDB())

    seen = {}
    monkeypatch.setattr(m, "mongo_update_one",
                        lambda coll, flt, upd: seen.update(upd["$set"]) or object(), raising=False)

    m._reconcile_report_visibility(main_task_id=None, local_task_id=42, ids_to_delete={42}, job_id="ui-42")
    assert captured["conn"] is the_conn          # read bound to the pinned lock connection
    assert seen["info.visibility"] == "private"  # authoritative primary value written


def test_reconcile_central_no_primary_logs_per_task(monkeypatch, caplog):
    """When there is no validated writer-primary lock the reconcile skips the upgrade — and
    logs a PER-TASK line (not just the once-per-process warn) so operators can enumerate the
    stranded fail-closed-private central docs from logs."""
    import logging
    from modules.reporting import mongodb as m
    import lib.cuckoo.common.tenancy as t
    import lib.cuckoo.common.central_mode as cm
    from lib.cuckoo.common.tenancy import MTConfig
    import lib.cuckoo.core.database as dbmod

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    monkeypatch.setattr(cm, "central_mode_config",
                        lambda: cm.CentralModeConfig(enabled=True, central_database_url="postgresql://standby"))
    monkeypatch.setattr(m, "_central_lock_engine", lambda: None)  # no validated primary

    class _LocalDB:
        lock_engine = None
    monkeypatch.setattr(dbmod, "Database", lambda: _LocalDB())
    called = []
    monkeypatch.setattr(m, "mongo_update_one", lambda *a, **k: called.append(1) or object(), raising=False)

    with caplog.at_level(logging.WARNING, logger="modules.reporting.mongodb"):
        m._reconcile_report_visibility(main_task_id=None, local_task_id=77, ids_to_delete={77}, job_id="ui-77")
    assert called == []  # skipped, no widen
    assert any("77" in r.getMessage() for r in caplog.records)  # per-task diagnostic


def test_connection_in_recovery_none_safe_and_fail_closed(monkeypatch):
    """_connection_in_recovery: None conn -> False (no-op path); a probe error -> True
    (fail closed, can't confirm primary on the lock connection)."""
    from modules.reporting import mongodb as m

    assert m._connection_in_recovery(None) is False
    assert m._connection_in_recovery(_RecoveryConn(True)) is True
    assert m._connection_in_recovery(_RecoveryConn(False)) is False

    class _BoomConn:
        def execute(self, *a, **k):
            raise RuntimeError("connection reset")
    monkeypatch.setattr(m, "_CENTRAL_LOCK_WARNED", False, raising=False)
    assert m._connection_in_recovery(_BoomConn()) is True  # probe error -> fail closed


def test_reconcile_write_filter_central_uses_job_id():
    """Reconcile tenancy stamp: central bridged -> unique info.job_id (a colliding worker-local doc
    sharing an info.id across lock domains must not be relabeled); single-node / no job_id -> info.id $in."""
    from modules.reporting.mongodb import _reconcile_write_filter
    assert _reconcile_write_filter(True, "ui-42", [42]) == {"info.job_id": "ui-42"}
    assert _reconcile_write_filter(False, "local-7", [7]) == {"info.id": {"$in": [7]}}   # single-node/direct
    assert _reconcile_write_filter(True, None, [9]) == {"info.id": {"$in": [9]}}          # no job_id -> fallback
