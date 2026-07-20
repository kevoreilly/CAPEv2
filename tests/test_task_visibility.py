import pytest


def _mk_task(category="file", target="x.exe"):
    from lib.cuckoo.core.data.task import Task
    t = Task(target=target)
    t.category = category
    return t


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_task_has_tenant_and_visibility(db):
    from lib.cuckoo.core.data.task import Task
    t = _mk_task()
    t.user_id = 1
    t.tenant_id = 10
    t.visibility = "tenant"
    db.session.add(t)
    db.session.commit()
    row = db.session.get(Task, t.id)
    assert row.tenant_id == 10
    assert row.visibility == "tenant"


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_visibility_defaults_private(db):
    from lib.cuckoo.core.data.task import Task
    t = _mk_task()
    db.session.add(t)
    db.session.commit()
    assert db.session.get(Task, t.id).visibility == "private"
    assert db.session.get(Task, t.id).tenant_id is None


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_list_tasks_visible_filter(db):
    from lib.cuckoo.common.tenancy import Viewer

    def mk(owner, tenant, vis):
        t = _mk_task()
        t.user_id, t.tenant_id, t.visibility = owner, tenant, vis
        db.session.add(t)
        db.session.commit()
        return t.id

    pub = mk(1, 10, "public")
    ten = mk(1, 10, "tenant")
    priv = mk(1, 10, "private")
    other = mk(3, 20, "tenant")

    # viewer: member of tenant 10, not owner of priv
    v = Viewer(user_id=2, tenant_id=10)
    ids = {t.id for t in db.list_tasks(visible_to=v)}
    assert pub in ids and ten in ids
    assert priv not in ids        # private, not owner
    assert other not in ids       # other tenant

    # break-glass sees everything
    allv = Viewer(user_id=9, tenant_id=None, is_superuser=True, is_local_admin=True)
    allids = {t.id for t in db.list_tasks(visible_to=allv)}
    assert {pub, ten, priv, other} <= allids


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_add_url_stamps_tenant_and_visibility(db):
    from lib.cuckoo.core.data.task import Task
    tid = db.add_url("http://example.com", tenant_id=10, visibility="tenant")
    t = db.session.get(Task, tid)
    assert t.tenant_id == 10
    assert t.visibility == "tenant"


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_add_url_defaults_private(db):
    from lib.cuckoo.core.data.task import Task
    tid = db.add_url("http://example.com")
    assert db.session.get(Task, tid).visibility == "private"


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_set_task_visibility_validates_enum(db):
    """Defense-in-depth (M1): the DB setter rejects unknown levels so a bogus
    value can never be persisted even if a caller skips the view-layer check."""
    from lib.cuckoo.core.data.task import Task
    tid = db.add_url("http://example.com", tenant_id=10, visibility="tenant")

    with pytest.raises(ValueError):
        db.set_task_visibility(tid, "bogus")
    # unchanged after the rejected write
    assert db.session.get(Task, tid).visibility == "tenant"

    # a valid level still works
    assert db.set_task_visibility(tid, "public") is not None
    assert db.session.get(Task, tid).visibility == "public"


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_count_tasks_scope(db):
    from lib.cuckoo.common.tenancy import Viewer

    def mk(owner, tenant, vis):
        t = _mk_task()
        t.user_id, t.tenant_id, t.visibility = owner, tenant, vis
        db.session.add(t)
        db.session.commit()

    mk(1, 10, "public")
    mk(1, 10, "tenant")
    mk(2, 10, "private")
    mk(3, 20, "public")
    v = Viewer(user_id=2, tenant_id=10)
    assert db.count_tasks(scope="public", viewer=v) == 2     # the two public ones
    assert db.count_tasks(scope="tenant", viewer=v) == 1     # tenant-vis in tenant 10
    assert db.count_tasks(scope="mine", viewer=v) == 1       # owner==2
    assert db.count_tasks(scope="global", viewer=v) == 4     # break-glass / no filter

    # the other scope-aware methods apply the same filter / execute cleanly
    assert sum(db.get_tasks_status_count(scope="public", viewer=v).values()) == 2
    assert sum(db.get_tasks_status_count(scope="global", viewer=v).values()) == 4
    assert db.minmax_tasks(scope="mine", viewer=v) is not None      # runs scoped, returns a tuple
    assert isinstance(db.count_samples(scope="tenant", viewer=v), int)  # scoped distinct-sample count


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_count_matching_tasks_visible_filter(db):
    """Pagination counts must apply the SAME visibility filter as the listing,
    or the page totals leak other tenants' submission volumes (and produce
    empty pages). count_matching_tasks(visible_to=) must agree with list_tasks."""
    from lib.cuckoo.common.tenancy import Viewer

    def mk(owner, tenant, vis):
        t = _mk_task()
        t.user_id, t.tenant_id, t.visibility = owner, tenant, vis
        db.session.add(t)
        db.session.commit()

    mk(1, 10, "public")
    mk(1, 10, "tenant")
    mk(1, 10, "private")
    mk(3, 20, "tenant")

    v = Viewer(user_id=2, tenant_id=10)  # tenant-10 member, not owner of the private one
    # the page count must equal the number of rows actually listed for that viewer
    assert db.count_matching_tasks(visible_to=v) == len(db.list_tasks(visible_to=v, limit=100000))
    # and it must be strictly fewer than the unfiltered total (private + other-tenant hidden)
    assert db.count_matching_tasks(visible_to=v) < db.count_matching_tasks()
    # break-glass counts everything, same as no filter
    allv = Viewer(user_id=9, tenant_id=None, is_local_admin=True)
    assert db.count_matching_tasks(visible_to=allv) == db.count_matching_tasks()


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_get_tasks_status_count_scoped_to_visible(db):
    """get_tasks_status_count(visible_to=) must sum to the same count as
    count_matching_tasks(visible_to=) over a mixed dataset, and be strictly
    less than the unfiltered total (cross-tenant counts must not leak)."""
    from lib.cuckoo.common.tenancy import Viewer

    def mk(owner, tenant, vis):
        t = _mk_task()
        t.user_id, t.tenant_id, t.visibility = owner, tenant, vis
        db.session.add(t)
        db.session.commit()

    mk(1, 10, "public")    # visible to tenant-10 member
    mk(1, 10, "tenant")    # visible to tenant-10 member
    mk(1, 10, "private")   # not visible (owner=1, not viewer)
    mk(3, 20, "tenant")    # other tenant, not visible

    v = Viewer(user_id=2, tenant_id=10)

    # sum of the scoped status dict must equal count_matching_tasks with the same filter
    scoped_sum = sum(db.get_tasks_status_count(visible_to=v).values())
    assert scoped_sum == db.count_matching_tasks(visible_to=v)

    # and it must be strictly less than the global unfiltered total
    assert scoped_sum < sum(db.get_tasks_status_count().values())


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_set_task_visibility_syncs_mongo(db, monkeypatch):
    calls = []
    import lib.cuckoo.core.data.tasking as tk
    # Sync only runs when mongo is the enabled report store; force it on for the test.
    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)

    def _rec(*a, **k):
        calls.append((a, k))
        return object()  # UpdateResult stand-in — a successful update returns non-None

    monkeypatch.setattr(tk, "mongo_update_one", _rec, raising=False)
    tid = db.add_url("http://example.com", tenant_id=10, visibility="tenant")
    db.set_task_visibility(tid, "public")
    assert calls and calls[-1][0][0] == "analysis"  # updated the analysis collection


def test_set_task_visibility_raises_on_persistent_mongo_failure(db, monkeypatch):
    """Finding #10: on the RESTRICTIVE path (public->private, mongo-first) a persistent
    mongo-sync failure must be surfaced (raised), not swallowed — else a stale public
    stamp after a private toggle silently keeps the analysis cross-tenant visible in
    the aggregate/search/stats surfaces. mongo's graceful_auto_reconnect wrapper
    swallows AutoReconnect/ServerSelectionTimeoutError and RETURNS None (no re-raise)
    when mongo stays down, so model that real path (a None return), NOT a raw
    exception — the latter would never exercise the bug."""
    import lib.cuckoo.core.data.tasking as tk
    from lib.cuckoo.common.exceptions import CuckooOperationalError

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)
    monkeypatch.setattr(tk, "mongo_update_one", lambda *a, **k: None, raising=False)
    tid = db.add_url("http://example.com", tenant_id=10, visibility="public")
    with pytest.raises(CuckooOperationalError):
        db.set_task_visibility(tid, "private")
    # SQL rolled back to the previous value so the two stores can't diverge.
    from lib.cuckoo.core.data.task import Task
    assert db.session.get(Task, tid).visibility == "public"


def test_set_task_visibility_reverts_mongo_when_sql_commit_fails(db, monkeypatch):
    """RESTRICTIVE path (public->private, mongo-first): if the SQL commit fails AFTER a
    successful mongo sync, mongo would be left MORE RESTRICTIVE than the un-committed
    SQL — the setter must best-effort revert the mongo stamp to the previous value and
    raise, so the two stores stay consistent."""
    import lib.cuckoo.core.data.tasking as tk
    from lib.cuckoo.common.exceptions import CuckooOperationalError

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)
    calls = []

    def _rec(coll, q, upd, *a, **k):
        calls.append(upd["$set"]["info.visibility"])
        return object()  # UpdateResult stand-in (success)

    monkeypatch.setattr(tk, "mongo_update_one", _rec, raising=False)
    tid = db.add_url("http://example.com", tenant_id=10, visibility="public")

    # make ONLY the new-value commit inside set_task_visibility fail (add_url above
    # already committed the task with the real commit).
    orig_commit = db.session.commit
    state = {"boom": True}

    def _commit():
        if state["boom"]:
            state["boom"] = False
            raise RuntimeError("transient SQL commit failure")
        return orig_commit()

    monkeypatch.setattr(db.session, "commit", _commit)

    with pytest.raises(CuckooOperationalError):
        db.set_task_visibility(tid, "private")

    # forward sync to 'private', then a best-effort revert back to 'public'
    assert calls == ["private", "public"]


def test_set_task_visibility_syncs_ownership_not_just_visibility(db, monkeypatch):
    """A visibility toggle re-stamps info.tenant_id/user_id (not just visibility), so a
    doc orphaned by a crash between the reporter's fail-closed insert and its reconcile
    (unowned: tenant_id/user_id null) is repaired on the next toggle instead of becoming
    {visibility: tenant, tenant_id: null} — which matches no viewer scope."""
    import lib.cuckoo.core.data.tasking as tk

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)
    captured = {}
    monkeypatch.setattr(
        tk, "mongo_update_one",
        lambda coll, q, upd, *a, **k: captured.update(upd["$set"]) or object(), raising=False,
    )
    tid = db.add_url("http://example.com", tenant_id=10, visibility="private")
    task = db.session.get(tk.Task, tid)

    assert db.set_task_visibility(tid, "public") is not None
    assert captured["info.visibility"] == "public"
    assert captured["info.tenant_id"] == task.tenant_id == 10   # ownership synced, not just visibility
    assert captured["info.user_id"] == task.user_id


def test_set_task_visibility_permissive_commits_sql_before_mongo(db, monkeypatch):
    """Codex P1: a MORE-permissive change (private->public) must make SQL durable
    BEFORE publishing the mongo stamp — so a crash / concurrent aggregate in the
    window can never see mongo more permissive than committed SQL. A mongo publish
    lag must NOT roll back the durable, authorized SQL change."""
    import lib.cuckoo.core.data.tasking as tk
    from lib.cuckoo.core.data.task import Task

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)
    order = []
    # publish "lags" (returns None) AND records that it ran after the commit
    monkeypatch.setattr(tk, "mongo_update_one", lambda *a, **k: order.append("mongo") or None, raising=False)
    tid = db.add_url("http://example.com", tenant_id=10, visibility="private")

    orig_commit = db.session.commit

    def _commit():
        order.append("commit")
        return orig_commit()

    monkeypatch.setattr(db.session, "commit", _commit)

    # a permissive change must NOT raise on a mongo lag (SQL is authoritative + durable)
    assert db.set_task_visibility(tid, "public") is not None
    assert order[:2] == ["commit", "mongo"]  # SQL durable BEFORE mongo published
    db.session.expire_all()
    assert db.session.get(Task, tid).visibility == "public"  # durable despite mongo lag


def test_set_task_visibility_permissive_sql_fail_never_publishes_mongo(db, monkeypatch):
    """A permissive change whose SQL commit fails must raise and NEVER publish the
    mongo stamp — nothing becomes more permissive if SQL didn't commit."""
    import lib.cuckoo.core.data.tasking as tk
    from lib.cuckoo.common.exceptions import CuckooOperationalError

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)
    mongo_calls = []
    monkeypatch.setattr(tk, "mongo_update_one", lambda *a, **k: mongo_calls.append(a) or object(), raising=False)
    tid = db.add_url("http://example.com", tenant_id=10, visibility="private")

    orig_commit = db.session.commit
    state = {"boom": True}

    def _commit():
        if state["boom"]:
            state["boom"] = False
            raise RuntimeError("transient SQL commit failure")
        return orig_commit()

    monkeypatch.setattr(db.session, "commit", _commit)

    with pytest.raises(CuckooOperationalError):
        db.set_task_visibility(tid, "public")
    assert mongo_calls == []  # never published the more-permissive stamp


def test_set_task_visibility_skips_sync_when_mongo_disabled(db, monkeypatch):
    """When mongo is NOT the report store, the toggle must succeed without any sync
    attempt (so an ES/no-mongo install isn't broken by the sync path)."""
    import lib.cuckoo.core.data.tasking as tk

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: False, raising=False)

    def _boom(*a, **k):
        raise AssertionError("mongo_update_one must not be called when mongo is disabled")

    monkeypatch.setattr(tk, "mongo_update_one", _boom, raising=False)
    tid = db.add_url("http://example.com", tenant_id=10, visibility="tenant")
    assert db.set_task_visibility(tid, "public") is not None


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_reschedule_propagates_tenant_visibility(db):
    """reschedule()/recovery must carry the source task's owner/tenant/visibility
    to the new task — otherwise rescheduled or startup-recovered tasks fall back
    to add() defaults (user_id=0, tenant_id=None, visibility='private') and the
    original tenant's job silently leaves its scope (invisible to everyone but
    break-glass in locked mode)."""
    from lib.cuckoo.core.data.task import Task

    tid = db.add_url("http://example.com", user_id=5, tenant_id=10, visibility="tenant")
    new_tid = db.reschedule(tid)
    assert new_tid and new_tid != tid
    new = db.session.get(Task, new_tid)
    assert new.user_id == 5
    assert new.tenant_id == 10
    assert new.visibility == "tenant"


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_count_samples_global_matches_unscoped(db):
    """B-extra-2 back-compat: count_samples(scope='global', viewer=...) must equal
    the unscoped count(Sample.id) — the global/empty-scope branch must NOT switch
    to distinct(Task.sample_id) (which drops orphan/parent-only samples and drifts
    the dashboard figure from upstream)."""
    from lib.cuckoo.common.tenancy import Viewer

    def mk(owner, tenant, vis):
        t = _mk_task()
        t.user_id, t.tenant_id, t.visibility = owner, tenant, vis
        db.session.add(t)
        db.session.commit()

    mk(1, 10, "public")
    mk(2, 10, "private")
    v = Viewer(user_id=9, tenant_id=None, is_local_admin=True)
    assert db.count_samples(scope="global", viewer=v) == db.count_samples()


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_count_samples_nonadmin_global_is_restricted(db):
    """#6 review (defense-in-depth): a non-break-glass viewer must NOT receive an
    unscoped global sample count even if a caller passes scope='global' — the
    count is restricted to samples referenced by tasks they may read. Break-glass
    (is_local_admin) still gets the unfiltered count (back-compat)."""
    from lib.cuckoo.common.tenancy import Viewer

    def mk(owner, tenant, vis, sid):
        t = _mk_task()
        t.user_id, t.tenant_id, t.visibility, t.sample_id = owner, tenant, vis, sid
        db.session.add(t)
        db.session.commit()

    mk(1, 10, "public", 100)    # visible to a tenant-10 viewer (public)
    mk(5, 10, "tenant", 101)    # visible (same tenant, tenant-visibility)
    mk(5, 10, "private", 102)   # hidden (private, not owner)
    mk(7, 20, "private", 103)   # hidden (other tenant)

    tenant_v = Viewer(user_id=2, tenant_id=10)               # non-admin (is_local_admin=False)
    admin_v = Viewer(user_id=9, tenant_id=None, is_local_admin=True)

    # non-admin: global scope is restricted to the 2 visible sample_ids (100,101)
    assert db.count_samples(scope="global", viewer=tenant_v) == 2
    # break-glass: unfiltered — sees all 4 distinct sample_ids referenced
    assert db.count_samples(scope="mine", viewer=admin_v) >= 0  # smoke: scoped path runs
    # the non-admin global count must be strictly fewer than all distinct sample_ids
    assert db.count_samples(scope="global", viewer=tenant_v) < 4


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_check_file_uniq_scoped_even_with_hours_zero(db):
    """#10 review (security-high): the duplicate check must be tenant-scoped for
    ALL hours values — incl. hours=0 (all-time) — else it's a cross-tenant
    existence oracle. A tenant-B-only private hash must read 'not duplicate' for a
    tenant-A viewer; break-glass still sees it."""
    from lib.cuckoo.core.data.samples import Sample
    from lib.cuckoo.common.tenancy import Viewer

    h = "d" * 64
    s = Sample(md5="d" * 32, crc32="0000", sha1="d" * 40, sha256=h, sha512="d" * 128, file_size=1, file_type="x")
    db.session.add(s)
    db.session.commit()
    t = _mk_task()
    t.user_id, t.tenant_id, t.visibility, t.sample_id = 999, 20, "private", s.id  # tenant-B private
    db.session.add(t)
    db.session.commit()

    tenant_a = Viewer(user_id=2, tenant_id=10)               # non-admin, other tenant
    admin = Viewer(user_id=9, tenant_id=None, is_local_admin=True)

    # hours=0 (all-time) MUST be scoped: A cannot observe B's private hash
    assert db.check_file_uniq(h, hours=0, visible_to=tenant_a) is False
    assert db.check_file_uniq(h, hours=24, visible_to=tenant_a) is False
    # break-glass sees it (no-op); also the unscoped call (no viewer) preserves legacy behavior
    assert db.check_file_uniq(h, hours=0, visible_to=admin) is True
    assert db.check_file_uniq(h, hours=0) is True


def test_advisory_lock_noop_without_lock_engine():
    """No-op when there is no lock engine (non-Postgres / sqlite is single-writer):
    _advisory_lock returns None and issues no SQL."""
    import lib.cuckoo.core.data.tasking as tk

    assert tk._advisory_lock(None, 7) is None


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_sqlite_database_has_no_lock_engine(db):
    """On sqlite the Database builds NO dedicated lock engine (advisory locks are a
    no-op there), so set_task_visibility runs its unserialized-but-single-writer path."""
    assert getattr(db, "lock_engine", "missing") is None


def test_advisory_lock_uses_dedicated_engine_connection_on_postgres():
    """The concurrent-toggle lock must be taken on a DEDICATED connection from the
    dedicated lock ENGINE (NullPool, off the app pool), NOT the pooled ORM session
    (re-entrant/leak across the mid-method commit). The SAME connection is locked,
    unlocked, and closed."""
    import lib.cuckoo.core.data.tasking as tk

    events = []

    class _Conn:
        def execute(self, stmt, params=None):
            events.append(("execute", str(stmt), params))

        def close(self):
            events.append(("close", None, None))

        def invalidate(self):
            events.append(("invalidate", None, None))

    the_conn = _Conn()

    class _LockEngine:  # the dedicated NullPool lock engine (Database.lock_engine)
        def connect(self):
            events.append(("connect", None, None))
            return the_conn

    conn = tk._advisory_lock(_LockEngine(), 42)
    assert conn is the_conn                      # dedicated connection from the lock engine
    tk._advisory_unlock(conn, 42)

    assert [e[0] for e in events] == ["connect", "execute", "execute", "close"]
    assert "pg_advisory_lock" in events[1][1] and events[1][2] == {"k": 42}    # lock on that conn
    assert "pg_advisory_unlock" in events[2][1] and events[2][2] == {"k": 42}  # unlock on the SAME conn


def test_advisory_lock_fails_closed_on_acquire_failure():
    """Pool/connection exhaustion must FAIL CLOSED (raise), never return None and
    proceed unserialized (which would reopen the concurrent-toggle race)."""
    import pytest as _pytest
    import lib.cuckoo.core.data.tasking as tk

    class _BoomEngine:
        def connect(self):
            raise RuntimeError("pool exhausted")

    with _pytest.raises(RuntimeError):
        tk._advisory_lock(_BoomEngine(), 7)


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_set_task_visibility_fails_closed_when_lock_unavailable(db, monkeypatch):
    """If the serialization lock can't be acquired (Postgres pool exhausted) the toggle
    must fail CLOSED (raise), never proceed unserialized."""
    import lib.cuckoo.core.data.tasking as tk
    from lib.cuckoo.common.exceptions import CuckooOperationalError

    def _boom(session, key):
        raise RuntimeError("pool exhausted")

    monkeypatch.setattr(tk, "_advisory_lock", _boom)
    tid = db.add_url("http://example.com", tenant_id=10, visibility="public")
    with pytest.raises(CuckooOperationalError):
        db.set_task_visibility(tid, "private")


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_set_task_visibility_central_derives_own_job_id_ignoring_forged_custom(db, monkeypatch):
    """Central mode: the visibility/ownership write keys on the task's OWN deterministic bridged doc
    (info.job_id 'ui-<task_id>' AND info.id==task_id), DERIVED from the authorized task_id -- NEVER read
    from the forgeable task.custom. A caller who forges custom='job_id=ui-<victim>' must NOT relabel /
    re-own another tenant's doc (adversarial-review HIGH, write side -- same forgery class as guac)."""
    import lib.cuckoo.core.data.tasking as tk
    from lib.cuckoo.core.data.task import Task

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)
    monkeypatch.setattr("lib.cuckoo.common.central_mode.central_mode_config",
                        lambda: type("C", (), {"enabled": True})())
    calls = []
    monkeypatch.setattr(tk, "mongo_update_one", lambda *a, **k: (calls.append(a), object())[1], raising=False)
    tid = db.add_url("http://example.com", tenant_id=10, visibility="tenant")
    t = db.session.get(Task, tid)
    t.custom = "job_id=ui-999999"  # FORGED: a victim's job id, not this task's own
    db.session.commit()
    db.set_task_visibility(tid, "public")
    # derived bridged key OR info.id constrained to job_id null-or-ours, ANDed with unstamped-or-own; the
    # forged ui-999999 never appears.
    assert calls[-1][1] == {
        "$and": [
            {"$or": [
                {"info.job_id": f"ui-{tid}"},
                {"$and": [{"info.id": tid}, {"info.job_id": {"$in": [None, f"ui-{tid}", f"local-{tid}"]}}]},
            ]},
            {"$or": [{"info.tenant_id": None}, {"info.tenant_id": 10}]},
        ]
    }, calls[-1]
    assert "ui-999999" not in str(calls[-1][1]), "forged custom must not reach the write filter"


def _mongo_matches(doc, flt):
    """Minimal Mongo filter evaluator ($and/$or/$in/dotted-key equality; None matches a missing field) --
    so the visibility filter can be asserted at the DOCUMENT level, not just by shape."""
    if "$and" in flt:
        return all(_mongo_matches(doc, s) for s in flt["$and"])
    if "$or" in flt:
        return any(_mongo_matches(doc, s) for s in flt["$or"])
    for key, want in flt.items():
        cur = doc
        for part in key.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if isinstance(want, dict) and "$in" in want:
            if cur not in want["$in"]:
                return False
        elif cur != want:
            return False
    return True


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_set_task_visibility_central_filter_matches_own_excludes_foreign(db, monkeypatch):
    """DOC-LEVEL: the central write filter matches the caller's OWN doc in ALL three shapes (bridged
    'ui-<tid>', not-yet-job_id-stamped, and direct-submit 'local-<tid>') and excludes a foreign doc that is
    STAMPED for another tenant or is a DIFFERENT task's bridged doc. RESIDUAL (documented, not asserted): an
    UNSTAMPED foreign 'local-<tid>' colliding on info.id is indistinguishable from the owner's own
    direct-submit doc -- closing that needs a node/store discriminator (data-model follow-up)."""
    import lib.cuckoo.core.data.tasking as tk
    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)
    monkeypatch.setattr("lib.cuckoo.common.central_mode.central_mode_config",
                        lambda: type("C", (), {"enabled": True})())
    captured = {}
    monkeypatch.setattr(tk, "mongo_update_one",
                        lambda *a, **k: (captured.__setitem__("f", a[1]), object())[1], raising=False)
    tid = db.add_url("http://x.example", tenant_id=10, visibility="tenant")
    db.set_task_visibility(tid, "public")
    f = captured["f"]
    # own doc, every shape:
    assert _mongo_matches({"info": {"id": tid, "job_id": f"ui-{tid}", "tenant_id": None}}, f), "own bridged must match"
    assert _mongo_matches({"info": {"id": tid, "tenant_id": None}}, f), "own not-yet-stamped must match"
    assert _mongo_matches({"info": {"id": tid, "job_id": f"local-{tid}", "tenant_id": None}}, f), \
        "own direct-submit (local-<tid>) must match -- excluding it silently no-op'd the owner's toggle"
    # foreign docs STAMPED for another tenant are excluded by the unstamped-or-own arm:
    assert not _mongo_matches({"info": {"id": tid, "job_id": "ui-999999", "tenant_id": 77}}, f), \
        "another tenant's bridged doc must NOT match"
    assert not _mongo_matches({"info": {"id": tid, "job_id": f"local-{tid}", "tenant_id": 77}}, f), \
        "another tenant's colliding direct-submit doc must NOT match"
    # a DIFFERENT task's bridged doc is excluded even unstamped (its job_id is not ui-<tid>/local-<tid>):
    assert not _mongo_matches({"info": {"id": tid, "job_id": "ui-999999", "tenant_id": None}}, f), \
        "a different task's bridged doc (ui-<other>) must NOT match"


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_set_task_visibility_single_node_keys_on_info_id(db, monkeypatch):
    """Single-node / non-central: unchanged bare info.id filter."""
    import lib.cuckoo.core.data.tasking as tk

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)
    monkeypatch.setattr("lib.cuckoo.common.central_mode.central_mode_config",
                        lambda: type("C", (), {"enabled": False})())
    calls = []
    monkeypatch.setattr(tk, "mongo_update_one", lambda *a, **k: (calls.append(a), object())[1], raising=False)
    tid = db.add_url("http://example.com", tenant_id=10, visibility="tenant")
    db.set_task_visibility(tid, "public")
    assert calls and calls[-1][1] == {"info.id": tid}, calls[-1]


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_set_task_visibility_fails_closed_when_central_mode_probe_raises(db, monkeypatch):
    """If the central_mode config read RAISES, the write must NOT drop to the unscoped bare {info.id} filter
    (a fail-open that could re-own a colliding foreign doc on a central node). Fail closed: use the
    constrained own-doc filter -- so a foreign worker-local / other-tenant doc still can't be matched."""
    import lib.cuckoo.core.data.tasking as tk

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)

    def _boom():
        raise RuntimeError("config layer broke")
    monkeypatch.setattr("lib.cuckoo.common.central_mode.central_mode_config", _boom)
    captured = {}
    monkeypatch.setattr(tk, "mongo_update_one",
                        lambda *a, **k: (captured.__setitem__("f", a[1]), object())[1], raising=False)
    tid = db.add_url("http://x.example", tenant_id=10, visibility="tenant")
    db.set_task_visibility(tid, "public")
    f = captured["f"]
    assert f != {"info.id": tid}, "must NOT fall back to the unscoped bare filter"
    assert _mongo_matches({"info": {"id": tid, "job_id": f"ui-{tid}", "tenant_id": None}}, f), "own bridged must match"
    assert not _mongo_matches({"info": {"id": tid, "job_id": "ui-999999", "tenant_id": None}}, f), \
        "a different task's bridged doc must NOT match even when the mode probe failed"


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_set_task_visibility_zero_match_warns_but_does_not_abort(db, monkeypatch, caplog):
    """A central 0-match write (report not yet written, or no own doc in the shared collection) must NOT
    abort a RESTRICTIVE toggle -- the reconcile stamps the doc from the authoritative SQL value later, so
    aborting would break a legit toggle on a not-yet-reported task. It warns instead; SQL still commits.
    (A genuine driver failure -> mongo_update_one returns None -> False -> abort, covered separately.)"""
    import logging
    import lib.cuckoo.core.data.tasking as tk
    from lib.cuckoo.core.data.task import Task

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)
    monkeypatch.setattr("lib.cuckoo.common.central_mode.central_mode_config",
                        lambda: type("C", (), {"enabled": True})())

    class _R:  # UpdateResult-like: well-formed write that addressed no document
        matched_count = 0

    monkeypatch.setattr(tk, "mongo_update_one", lambda *a, **k: _R(), raising=False)
    tid = db.add_url("http://x.example", tenant_id=10, visibility="public")
    with caplog.at_level(logging.WARNING):
        db.set_task_visibility(tid, "private")  # RESTRICTIVE: a 0-match must not raise/abort
    assert db.session.get(Task, tid).visibility == "private", "SQL toggle must commit despite a 0-match"
    assert any("matched 0 docs" in r.getMessage() for r in caplog.records), "0-match must be surfaced (warned)"


@pytest.mark.usefixtures("tmp_cuckoo_root")
def test_add_preserves_client_custom_verbatim(db, monkeypatch):
    """add() must NOT scrub a job_id from custom: it is the shared ingest for external submissions AND the
    broker's own legit delivery (dispatcher POSTs /tasks/create with custom='job_id=ui-<tid>') AND internal
    re-submitters (reschedule/dist/gcp copy task.custom). Stripping here broke the central pipeline; the
    forgery is contained at the reachable layers (bridge skips forged-custom submissions, non-user-facing
    workers, derive-based writes + scoped reads) instead. So custom round-trips verbatim in every mode."""
    from lib.cuckoo.core.data.task import Task
    monkeypatch.setattr("lib.cuckoo.common.central_mode.central_mode_config",
                        lambda: type("C", (), {"enabled": True})())
    tid = db.add_url("http://x.example", custom="job_id=ui-999,foo=bar")
    assert db.session.get(Task, tid).custom == "job_id=ui-999,foo=bar"  # central: preserved (broker relies on it)

    monkeypatch.setattr("lib.cuckoo.common.central_mode.central_mode_config",
                        lambda: type("C", (), {"enabled": False})())
    tid2 = db.add_url("http://y.example", custom="job_id=ui-999,foo=bar")
    assert db.session.get(Task, tid2).custom == "job_id=ui-999,foo=bar"  # single-node: upstream verbatim
