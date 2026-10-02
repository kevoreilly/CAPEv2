import pytest
from django.contrib.auth.models import User

pytest_plugins = ("mt_test_fixtures",)  # fixtures live in web/mt_test_fixtures.py (not a conftest,
# which would shadow tests/conftest.py under pythonpath=web + --import-mode=append)



@pytest.mark.django_db
def test_submit_form_no_visibility_control_when_mt_off(cape_db, client):
    """MT DISABLED (default): the submit page must be upstream byte-for-byte, i.e.
    NO new Visibility <select> is rendered. The view leaves visibility_levels empty
    so the template "{% if visibility_levels %}" block collapses. (submission_scope
    ignores any submitted 'visibility' value when MT is off, so rendering the
    control would be a pure UI deviation.)"""
    u = User.objects.create_user("a", "a@x.com", "x")
    client.force_login(u)
    try:
        from django.urls import reverse
        url = reverse("submission")
    except Exception:
        url = "/submit/"
    r = client.get(url)
    assert r.status_code == 200
    assert b'name="visibility"' not in r.content


@pytest.mark.django_db
def test_submit_form_renders_visibility_control_when_mt_on(cape_db, mt_enabled, client):
    """MT ENABLED: the Visibility <select> IS rendered."""
    u = User.objects.create_user("aon", "aon@x.com", "x")
    client.force_login(u)
    try:
        from django.urls import reverse
        url = reverse("submission")
    except Exception:
        url = "/submit/"
    r = client.get(url)
    assert r.status_code == 200
    assert b'name="visibility"' in r.content


class _Rec(dict):
    """A perform_search record shaped like the real Mongo/ES search result."""


def _mk_records():
    return [
        {"info": {"id": 1}, "target": {"file": {"sha256": "a" * 64}}},
        {"info": {"id": 2}, "target": {"file": {"sha256": "b" * 64}}},
    ]


@pytest.mark.django_db
def test_scope_existent_noop_when_mt_off(cape_db, monkeypatch, rf):
    """MT DISABLED: _scope_existent must return the search records verbatim WITHOUT
    ever calling db.view_task — so a record whose SQL Task was purged is still shown
    (upstream byte-for-byte)."""
    import submission.views as sv

    def _boom(*a, **k):
        raise AssertionError("db.view_task must not be called when MT is off")

    monkeypatch.setattr(sv.db, "view_task", _boom)
    records = _mk_records()
    req = rf.get("/submit/")
    req.user = User.objects.create_user("se_off", "se_off@x.com", "x")
    out = sv._scope_existent(req, records)
    assert out == records  # verbatim, purged-Task records retained
    # None-safe passthrough
    assert sv._scope_existent(req, None) == []


@pytest.mark.django_db
def test_scope_existent_drops_unviewable_when_mt_on(cape_db, mt_enabled, monkeypatch, rf):
    """MT ENABLED: _scope_existent filters out records the requester may not view AND
    records whose SQL Task was purged (vt is None). Isolation stays intact."""
    import submission.views as sv
    from lib.cuckoo.common.tenancy import Job, PUBLIC, PRIVATE

    # id 1 -> public task (viewable); id 2 -> private task owned by someone else (hidden)
    tasks = {
        1: Job(owner_id=999, tenant_id=None, visibility=PUBLIC),
        2: Job(owner_id=999, tenant_id=None, visibility=PRIVATE),
    }
    monkeypatch.setattr(sv.db, "view_task", lambda rid: tasks.get(int(rid)))

    def _can_view(user, vt):
        from lib.cuckoo.common.tenancy import Viewer, can_read
        return can_read(Viewer(user_id=1, tenant_id=None), vt)

    monkeypatch.setattr(sv, "can_view_task", _can_view)

    req = rf.get("/submit/")
    req.user = User.objects.create_user("se_on", "se_on@x.com", "x")
    out = sv._scope_existent(req, _mk_records())
    ids = [(r.get("info") or {}).get("id") for r in out]
    assert ids == [1]  # public kept, private dropped


@pytest.mark.django_db
def test_scope_existent_drops_purged_task_when_mt_on(cape_db, mt_enabled, monkeypatch, rf):
    """MT ENABLED: a record whose SQL Task was purged (view_task -> None) is dropped."""
    import submission.views as sv

    monkeypatch.setattr(sv.db, "view_task", lambda rid: None)
    monkeypatch.setattr(sv, "can_view_task", lambda u, vt: True)
    req = rf.get("/submit/")
    req.user = User.objects.create_user("se_purge", "se_purge@x.com", "x")
    assert sv._scope_existent(req, _mk_records()) == []


@pytest.mark.django_db
def test_submit_form_tenant_option_matches_membership(cape_db, mt_enabled, client):
    """The submit form must offer the 'tenant' visibility option iff the user has a
    tenant — matching submission_scope (which honors explicit 'tenant' for a tenant
    member and rejects it for a tenant-less user). Prevents UI/API divergence."""
    from users.models import Tenant, UserProfile
    try:
        from django.urls import reverse
        url = reverse("submission")
    except Exception:
        url = "/submit/"

    # tenant-less user -> no 'tenant' option
    tl = User.objects.create_user("tl2", "tl2@x.com", "x")
    client.force_login(tl)
    assert b'value="tenant"' not in client.get(url).content

    # tenant member -> 'tenant' option present
    t = Tenant.objects.create(slug="acmez", name="AcmeZ")
    tu = User.objects.create_user("tu2", "tu2@x.com", "x")
    p = UserProfile.objects.get(user=tu)
    p.tenant = t
    p.save()
    client.force_login(User.objects.get(pk=tu.pk))
    assert b'value="tenant"' in client.get(url).content


class PublicRunningTask:
    id = 1
    user_id = 999          # owned by someone else
    tenant_id = 10
    visibility = "public"  # a read-only viewer CAN see it
    status = "running"
    machine = "m1"


@pytest.mark.django_db
def test_remote_session_denies_readonly_viewer(cape_db, mt_enabled, monkeypatch, client):
    """remote_session mints the live-VM guac session_data (keyboard/mouse/frame-
    buffer control). A read-only VIEWER of a PUBLIC task (can_view=True but NOT a
    manager) must be denied — live-VM control follows can_manage_task, not read
    visibility."""
    import submission.views as sv

    monkeypatch.setattr(sv.db, "view_task", lambda *a, **k: PublicRunningTask())
    client.force_login(User.objects.create_user("rs", "rs@x.com", "x"))  # tenant-less, non-owner

    try:
        from django.urls import reverse
        url = reverse("remote_session", kwargs={"task_id": 1})
    except Exception:
        url = "/remote_session/1/"
    r = client.get(url)
    # manage-denied -> the generic error page (error.html), never the live-session
    # page. (The message apostrophe is HTML-escaped, so match escape-safe substrings.)
    assert b"ERROR :-(" in r.content          # error.html marker
    assert b"seem to exist" in r.content       # "...task doesn't seem to exist."
    assert b"session_data" not in r.content    # no live-VM token handed to a non-manager


@pytest.mark.django_db
def test_submit_form_tenantless_locked_default_is_private(cape_db, mt_enabled, monkeypatch, client):
    """A tenant-less user in locked mode must see 'private' preselected (not public):
    the form default must match submission_scope's fail-closed downgrade AND be a
    level that's actually offered — else the browser submits the first option (public)
    on an unchanged form, silently creating a public job."""
    import submission.views as sv
    from lib.cuckoo.common.tenancy import MTConfig

    monkeypatch.setattr(sv, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    client.force_login(User.objects.create_user("tll", "tll@x.com", "x"))  # tenant-less
    try:
        from django.urls import reverse
        url = reverse("submission")
    except Exception:
        url = "/submit/"
    content = client.get(url).content
    assert b'value="tenant"' not in content            # tenant not offered to a tenant-less user
    assert b'value="private" selected' in content       # private preselected (not public)
