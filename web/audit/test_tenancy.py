"""Tenancy authorization for the audit app's destructive/mutating surfaces (the fourth task-delete
surface the can_delete model must cover): the CAPE-task delete is gated on can_delete_task, and the
mutating endpoints are never exposed anonymously via ANON_VIEW. Import audit.views INSIDE each test so a
module-load hiccup fails only that test, not collection."""
import pytest
from django.contrib.auth.models import User


class _FakeRun:
    def __init__(self, cape_task_id, status):
        self.cape_task_id = cape_task_id
        self.status = status


class _FakeCapeTask:
    def __init__(self, status):
        self.status = status


@pytest.mark.django_db
def test_inner_unqueue_test_missing_task_no_500(cape_db, monkeypatch):
    """A dangling cape_task_id whose CAPE row is already gone returns None -- not a bodiless 500 from
    `.status` on the None that db.view_task returns."""
    import audit.views as av
    from lib.cuckoo.core.data.audit_data import TEST_QUEUED

    deleted = []
    monkeypatch.setattr(av.db, "view_task", lambda tid: None)
    monkeypatch.setattr(av.db, "delete_task", lambda tid: deleted.append(tid), raising=False)
    run = _FakeRun(cape_task_id=42, status=TEST_QUEUED)
    assert av.inner_unqueue_test(run) is None
    assert deleted == []


@pytest.mark.django_db
def test_inner_unqueue_test_gated_on_can_delete(cape_db, monkeypatch):
    """The CAPE-task delete is gated on can_delete_task: a caller who may not delete it gets None,
    db.delete_task is never called, and the run keeps its queued linkage. An authorized caller deletes."""
    import audit.views as av
    from lib.cuckoo.core.data.audit_data import TEST_QUEUED
    from lib.cuckoo.core.data.task import TASK_PENDING

    deleted = []
    monkeypatch.setattr(av.db, "view_task", lambda tid: _FakeCapeTask(TASK_PENDING))
    monkeypatch.setattr(av.db, "delete_task", lambda tid: deleted.append(tid), raising=False)
    monkeypatch.setattr(av, "can_delete_task", lambda u, t: False, raising=False)
    run = _FakeRun(cape_task_id=42, status=TEST_QUEUED)
    u = User.objects.create_user("au_ng", "au_ng@x.com", "x")

    assert av.inner_unqueue_test(run, u) is None
    assert deleted == []                 # not deleted -- caller not authorized
    assert run.cape_task_id == 42        # linkage untouched (nothing purged)

    # sanity: an authorized caller DOES delete + clears the linkage
    monkeypatch.setattr(av, "can_delete_task", lambda u, t: True, raising=False)
    assert av.inner_unqueue_test(run, u) == 42
    assert deleted == [42]


@pytest.mark.django_db
def test_caller_can_delete_session_gate(cape_db, monkeypatch):
    """_caller_can_delete_session (the delete_test_session gate) is False as soon as ONE run's CAPE task
    is not deletable by the caller -- so the purge (rmtree of every run's analysis dir) is refused."""
    import audit.views as av

    class _Session:
        runs = [_FakeRun(cape_task_id=7, status="x"), _FakeRun(cape_task_id=None, status="x")]

    monkeypatch.setattr(av.db, "view_task", lambda tid: _FakeCapeTask("reported"))
    u = User.objects.create_user("au_sess", "au_sess@x.com", "x")

    monkeypatch.setattr(av, "can_delete_task", lambda u, t: False, raising=False)
    assert av._caller_can_delete_session(u, _Session()) is False   # blocked on the un-deletable run

    monkeypatch.setattr(av, "can_delete_task", lambda u, t: True, raising=False)
    assert av._caller_can_delete_session(u, _Session()) is True    # all runs deletable -> allowed


def test_anon_view_never_exposes_mutating_audit_endpoints():
    """ANON_VIEW must not serve destructive/mutating audit endpoints without login: every one is listed
    in anon_not_viewable_func_list (empty before this fix -> ANON_VIEW returned the raw view)."""
    import audit.views as av

    for name in ("create_test_session", "reload_available_tests", "delete_test_session",
                 "queue_test", "queue_all_tests", "unqueue_test", "unqueue_all_tests", "update_task_config"):
        assert name in av.anon_not_viewable_func_list, name


@pytest.mark.django_db
def test_inner_unqueue_test_user_none_denied(cape_db, monkeypatch):
    """A missing caller identity (user is None) FAILS CLOSED: even a TASK_PENDING run's CAPE task is NOT
    deleted and its linkage is untouched. RED against the old fail-open default that skipped the gate when
    user was None (a stray no-user call could then silently delete)."""
    import audit.views as av
    from lib.cuckoo.core.data.audit_data import TEST_QUEUED
    from lib.cuckoo.core.data.task import TASK_PENDING

    deleted = []
    monkeypatch.setattr(av.db, "view_task", lambda tid: _FakeCapeTask(TASK_PENDING))
    monkeypatch.setattr(av.db, "delete_task", lambda tid: deleted.append(tid), raising=False)

    run = _FakeRun(cape_task_id=42, status=TEST_QUEUED)
    assert av.inner_unqueue_test(run) is None      # user defaults to None -> denied
    assert deleted == []                           # nothing deleted
    assert run.cape_task_id == 42                  # linkage intact


@pytest.mark.django_db
def test_inner_unqueue_test_non_pending_task_not_deleted(cape_db, monkeypatch):
    """An authorized caller whose CAPE task is NOT TASK_PENDING (already running/reported) must fall through
    to None WITHOUT deleting or clearing linkage -- the queued-but-already-started safety guard."""
    import audit.views as av
    from lib.cuckoo.core.data.audit_data import TEST_QUEUED

    deleted = []
    monkeypatch.setattr(av.db, "view_task", lambda tid: _FakeCapeTask("running"))  # != TASK_PENDING
    monkeypatch.setattr(av.db, "delete_task", lambda tid: deleted.append(tid), raising=False)
    monkeypatch.setattr(av, "can_delete_task", lambda u, t: True, raising=False)
    u = User.objects.create_user("au_np", "au_np@x.com", "x")

    run = _FakeRun(cape_task_id=42, status=TEST_QUEUED)
    assert av.inner_unqueue_test(run, u) is None
    assert deleted == []                          # non-pending task not deleted
    assert run.cape_task_id == 42                 # linkage intact


@pytest.mark.django_db
def test_inner_unqueue_test_skips_non_queued_run(cape_db, monkeypatch):
    """A run whose status is not TEST_QUEUED short-circuits at the outer guard -- never touching
    view_task / can_delete_task / delete_task."""
    import audit.views as av

    def _must_not(*a, **k):
        raise AssertionError("non-queued run must not reach the DB / authz path")
    monkeypatch.setattr(av.db, "view_task", _must_not)
    monkeypatch.setattr(av.db, "delete_task", _must_not, raising=False)
    monkeypatch.setattr(av, "can_delete_task", _must_not, raising=False)
    u = User.objects.create_user("au_nq", "au_nq@x.com", "x")

    run = _FakeRun(cape_task_id=42, status="running")   # not TEST_QUEUED
    assert av.inner_unqueue_test(run, u) is None


@pytest.mark.django_db
def test_caller_can_delete_session_no_live_task_fails_closed_under_mt(cape_db, mt_enabled, monkeypatch):
    """A session with NO authorization-bearing (live-task) run -- all runs unqueued (cape_task_id=None) or
    dangling (view_task->None) -- must FAIL CLOSED under MT to a break-glass box admin, not fall through to
    allow-any-authenticated-user. A freshly-created, not-yet-queued session is the COMMON all-task-less
    state. RED against the old vacuous-True loop. The caller here is a plain non-staff, non-admin user."""
    import audit.views as av

    class _Sess:
        def __init__(self, runs):
            self.runs = runs

    u = User.objects.create_user("au_fc", "au_fc@x.com", "x")  # tenant-less, non-staff -> not box-admin

    # all UNQUEUED (cape_task_id=None) -> view_task must never be consulted
    def _no_view(*a, **k):
        raise AssertionError("view_task must not be consulted for a task-less run")
    monkeypatch.setattr(av.db, "view_task", _no_view, raising=False)
    assert av._caller_can_delete_session(u, _Sess([_FakeRun(None, "x"), _FakeRun(None, "x")])) is False

    # all DANGLING (rows gone) -> still fail closed
    monkeypatch.setattr(av.db, "view_task", lambda tid: None, raising=False)
    assert av._caller_can_delete_session(u, _Sess([_FakeRun(101, "x"), _FakeRun(102, "x")])) is False


@pytest.mark.django_db
def test_caller_can_delete_session_no_live_task_allows_box_admin(cape_db, mt_enabled, monkeypatch):
    """The break-glass exception: a box admin (viewer.is_local_admin) MAY purge a task-less/dangling
    session under MT -- the fail-closed default lets the legitimate operator through."""
    import audit.views as av

    class _Sess:
        def __init__(self, runs):
            self.runs = runs

    monkeypatch.setattr(av.db, "view_task", lambda tid: None, raising=False)
    monkeypatch.setattr(av, "viewer_for", lambda u: type("V", (), {"is_local_admin": True})(), raising=False)
    u = User.objects.create_user("au_ba", "au_ba@x.com", "x")
    assert av._caller_can_delete_session(u, _Sess([_FakeRun(None, "x")])) is True


@pytest.mark.django_db
def test_caller_can_delete_session_no_live_task_allows_when_mt_off(cape_db, monkeypatch):
    """MT off -> single shared trust domain: a task-less session is deletable (no regression vs upstream,
    which had no audit authz at all)."""
    import audit.views as av

    class _Sess:
        def __init__(self, runs):
            self.runs = runs

    monkeypatch.setattr(av, "multitenancy_config", lambda: type("C", (), {"enabled": False})(), raising=False)
    monkeypatch.setattr(av.db, "view_task", lambda tid: None, raising=False)
    u = User.objects.create_user("au_off", "au_off@x.com", "x")
    assert av._caller_can_delete_session(u, _Sess([_FakeRun(None, "x")])) is True
