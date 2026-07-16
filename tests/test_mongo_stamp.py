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

    monkeypatch.setattr(m, "_task_tenant_ctx_central", lambda cid: Central() if int(cid) == 42 else None)

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

    monkeypatch.setattr(m, "_task_tenant_ctx_central", lambda cid: CentralTenantB())  # must NOT be used
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
    monkeypatch.setattr(m, "_task_tenant_ctx_central", lambda cid: None)  # unresolved

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
    monkeypatch.setattr(m, "_central_engine", lambda: _CENTRAL)

    class _LocalDB:
        lock_engine = object()  # the WRONG engine to lock on for a central id
    monkeypatch.setattr(dbmod, "Database", lambda: _LocalDB())
    monkeypatch.setattr(m, "_task_tenant_ctx_central", lambda cid: None)
    monkeypatch.setattr(m, "mongo_update_one", lambda *a, **k: object(), raising=False)

    seen = {}

    @contextmanager
    def fake_lock(lock_engine, task_id):
        seen["engine"] = lock_engine
        yield
    monkeypatch.setattr(tasking, "task_visibility_lock", fake_lock)

    m._reconcile_report_visibility(main_task_id=None, local_task_id=42, ids_to_delete={42}, job_id="ui-42")
    assert seen["engine"] is _CENTRAL   # locked the central engine, not _LocalDB.lock_engine


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
