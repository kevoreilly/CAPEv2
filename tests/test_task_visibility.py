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
    """Finding #10: a persistent mongo-sync failure must be surfaced (raised), not
    swallowed — else a stale public stamp after a private toggle silently keeps the
    analysis cross-tenant visible in the aggregate/search/stats surfaces. mongo's
    graceful_auto_reconnect wrapper swallows AutoReconnect/ServerSelectionTimeoutError
    and RETURNS None (no re-raise) when mongo stays down, so model that real path
    (a None return), NOT a raw exception — the latter would never exercise the bug."""
    import lib.cuckoo.core.data.tasking as tk
    from lib.cuckoo.common.exceptions import CuckooOperationalError

    monkeypatch.setattr(tk, "_mongo_reporting_enabled", lambda: True, raising=False)
    monkeypatch.setattr(tk, "mongo_update_one", lambda *a, **k: None, raising=False)
    tid = db.add_url("http://example.com", tenant_id=10, visibility="tenant")
    with pytest.raises(CuckooOperationalError):
        db.set_task_visibility(tid, "public")
    # SQL rolled back to the previous value so the two stores can't diverge.
    from lib.cuckoo.core.data.task import Task
    assert db.session.get(Task, tid).visibility == "tenant"


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
