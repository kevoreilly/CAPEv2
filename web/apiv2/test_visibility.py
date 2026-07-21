import ast
import re

import pytest
from django.contrib.auth.models import User

pytest_plugins = ("mt_test_fixtures",)  # fixtures live in web/mt_test_fixtures.py (not a conftest,
# which would shadow tests/conftest.py under pythonpath=web + --import-mode=append)


# A view "enforces visibility" if its source references any of these — a read
# guard, the artifact preamble, the list filter, the web decorator, or a
# management guard (for mutation endpoints).
GUARD_MARKERS = (
    "_deny_if_hidden", "_deny_task", "_deny_manage", "_resolve_task_id", "visible_to",
    "require_task_visibility", "require_task_manage", "require_task_delete", "can_view_task",
    "can_manage_task", "can_delete_task", "can_toggle_task",
    # scope-filtering primitives for aggregate / mongo surfaces (dashboard,
    # statistics, hunt, compare): restrict an aggregation to the viewer's
    # entitled scopes instead of gating a single task_id. viewer_scope is the
    # central-mode facade over entitled_scope_filter (hunt() uses it post-#3105).
    "scope_match", "entitled_scope_filter", "viewer_scope",
)

# Routed task_id views that legitimately need NO per-task visibility guard.
# SECURITY ALLOWLIST — keep tiny; every entry needs a real justification.
ALLOWLIST = set()


# URL capture-group names that identify a single task/analysis — any of these in
# a route means the view resolves tenant-scoped data and needs a guard. Note:
# `sample_id` is intentionally excluded — sample/hash-addressed routes are owned
# by the hash gate (test_hash_routed_view_enforces_visibility, which knows about
# _deny_by_hash); putting it here would double-flag those under the task gate.
ID_GROUPS = ("task_id", "analysis_number", "left_id", "right_id")


def _routed_task_views(urls_module, alias="views"):
    """{view_name} for every (live, non-commented) URL routed via ``<alias>.NAME``
    whose pattern captures one of ID_GROUPS. ``alias`` lets us scan the root
    urlconf (web/web/urls.py), where analysis views are referenced as
    ``analysis_views.NAME``. The negative lookbehind stops ``views.`` from also
    matching inside ``analysis_views.`` when scanning with alias="views"."""
    text = "\n".join(
        ln for ln in open(urls_module.__file__).read().splitlines() if not ln.lstrip().startswith("#")
    )
    out = set()
    pat = r"(?:re_path|path)\((.*?)(?<![\w.])" + re.escape(alias) + r"\.([a-zA-Z_]+)"
    for m in re.finditer(pat, text, re.S):
        pattern_span, name = m.group(1), m.group(2)
        if any(g in pattern_span for g in ID_GROUPS):
            out.add(name)
    return out


def _func_source(views_module, name):
    """Source of a top-level function INCLUDING its decorators (ast's
    get_source_segment on a FunctionDef starts at `def`, dropping decorators —
    we need them, since the visibility guard can be a decorator)."""
    text = open(views_module.__file__).read()
    lines = text.splitlines()
    tree = ast.parse(text)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            start = node.lineno
            if node.decorator_list:
                start = min(d.lineno for d in node.decorator_list)
            return "\n".join(lines[start - 1: node.end_lineno])
    return None


def _all_task_views():
    import apiv2.views
    import apiv2.urls
    import analysis.views
    import analysis.urls
    import compare.views
    import compare.urls
    import guac.views
    import guac.urls
    from web import urls as web_urls

    # (urls module, views module the matched names resolve to, alias used there).
    # The root urlconf (web.urls) routes file/filereport/vtupload/full_memory*
    # into analysis.views under the `analysis_views` alias — historically unscanned.
    specs = (
        (apiv2.urls, apiv2.views, "views"),
        (analysis.urls, analysis.views, "views"),
        (compare.urls, compare.views, "views"),
        (guac.urls, guac.views, "views"),
        (web_urls, analysis.views, "analysis_views"),
    )
    cases = []
    for urls_mod, views_mod, alias in specs:
        for name in sorted(_routed_task_views(urls_mod, alias)):
            cases.append((views_mod.__name__, views_mod, name))
    return cases


_CASES = _all_task_views()


@pytest.mark.parametrize("modname,views_mod,name", _CASES, ids=[f"{m}:{n}" for m, _, n in _CASES])
def test_routed_task_view_enforces_visibility(modname, views_mod, name):
    """SECURITY GATE: every routed view that takes task_id must enforce a
    visibility/management guard, across BOTH apiv2 and analysis. Fails the build
    if a task-scoped endpoint ships without a guard (the original gate only
    checked a hardcoded apiv2 list and missed the entire analysis surface)."""
    if name in ALLOWLIST:
        pytest.skip(f"{name} explicitly allowlisted")
    src = _func_source(views_mod, name)
    if src is None:
        pytest.skip(f"{name} not found in {modname}")
    assert any(m in src for m in GUARD_MARKERS), \
        f"{modname}.{name} takes task_id but references no guard {GUARD_MARKERS} — cross-tenant leak risk"


# Aggregate/feed views that return per-task data WITHOUT a task_id in their
# route, so the routed-task_id gate above can't see them. Each must still filter
# its output by the caller's visibility. Add any new cross-task feed here — they
# may live in EITHER apiv2.views or analysis.views (e.g. `pending`).
AGGREGATE_TASK_FEEDS = ("tasks_rollingsuri", "pending", "hunt", "search")


@pytest.mark.parametrize("name", AGGREGATE_TASK_FEEDS)
def test_aggregate_feed_filters_by_viewer(name):
    """SECURITY GATE (aggregate): a feed that emits data for many tasks at once
    must reference a visibility guard, or it leaks cross-tenant task data/ids
    (the routed-task_id gate cannot catch these — no task_id in the route).
    Scans BOTH apiv2.views and analysis.views since feeds live in either."""
    import apiv2.views
    import analysis.views

    src = _func_source(apiv2.views, name) or _func_source(analysis.views, name)
    assert src is not None, f"{name} not found in apiv2.views or analysis.views"
    assert any(m in src for m in GUARD_MARKERS), \
        f"{name} returns cross-task data but references no guard {GUARD_MARKERS} — cross-tenant leak"


# Mutating endpoints that take task ids from the request BODY (not the URL), so
# neither the routed-id gate nor the aggregate gate can see them. Each must gate
# every targeted id through a management guard or one tenant can delete/modify
# another tenant's tasks.
BODY_KEYED_MUTATIONS = (
    ("apiv2.views", "tasks_delete_many"),
    ("analysis.views", "tag_tasks"),
)


@pytest.mark.parametrize("modname,name", BODY_KEYED_MUTATIONS)
def test_body_keyed_mutation_enforces_manage(modname, name):
    """SECURITY GATE (body-keyed mutation): a POST view that mutates tasks by
    ids supplied in the request body must reference a management/visibility
    guard, or one tenant can act on another tenant's tasks."""
    import importlib

    mod = importlib.import_module(modname)
    src = _func_source(mod, name)
    assert src is not None, f"{name} not found in {modname}"
    assert any(m in src for m in GUARD_MARKERS), \
        f"{modname}.{name} mutates tasks by body ids but references no guard {GUARD_MARKERS} — cross-tenant integrity risk"


# Endpoints that emit the base64 session_data used to mint a Guacamole live-VM
# session, or otherwise gate a remote-desktop tunnel into a running analysis VM.
# Each must gate the task — a tunnel into another tenant's live malware VM is the
# highest-severity leak class.
GUAC_SESSION_VIEWS = (
    ("submission.views", "status"),
    ("submission.views", "remote_session"),
)


@pytest.mark.parametrize("modname,name", GUAC_SESSION_VIEWS)
def test_guac_session_view_enforces_visibility(modname, name):
    """SECURITY GATE (live-VM tunnel): a view that emits a guac session token
    must gate the task, or a cross-tenant user can open a keyboard/mouse/frame-
    buffer tunnel into another tenant's running VM."""
    import importlib

    mod = importlib.import_module(modname)
    src = _func_source(mod, name)
    assert src is not None, f"{name} not found in {modname}"
    assert any(m in src for m in GUARD_MARKERS), \
        f"{modname}.{name} emits a guac session token but references no guard {GUARD_MARKERS} — cross-tenant live-VM tunnel risk"


def test_guac_websocket_consumer_rechecks_visibility():
    """SECURITY GATE (websocket): the guac tunnel consumer is not URL-routed, so
    the routed gates can't see it. Opening the tunnel is live-VM control (a task
    ACTION), so it must re-check MANAGE rights (defense in depth behind the
    manage-gated mint), not mere read visibility."""
    import guac.consumers

    src = open(guac.consumers.__file__).read()
    assert "can_manage_task" in src, \
        "guac websocket consumer must re-check manage rights (can_manage_task) — defense-in-depth for the live-VM tunnel"


class FakeTask:
    def __init__(self, user_id, tenant_id, visibility):
        self.id = 1
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.visibility = visibility


class FakeReq:
    def __init__(self, user):
        self.user = user


@pytest.mark.django_db
def test_deny_if_hidden_blocks_cross_tenant_private(mt_enabled):
    import apiv2.views as views

    other = User.objects.create_user("b", "b@x.com", "x")  # tenant None, not owner
    resp = views._deny_if_hidden(FakeReq(other), FakeTask(user_id=999, tenant_id=10, visibility="private"))
    assert resp is not None
    # indistinguishable from "not found" (H3): hidden task must NOT 403 (that
    # would confirm the task exists) — it returns the same generic 404 as a
    # missing task so other tenants' task IDs can't be enumerated.
    assert resp.status_code == 404


def _force_mt_off(monkeypatch):
    """Deterministically disable MT for the apiv2 deny helpers (the facade
    delegates to users.tenancy.multitenancy_config at call time)."""
    import users.tenancy as ut
    from lib.cuckoo.common.tenancy import MTConfig
    monkeypatch.setattr(ut, "multitenancy_config", lambda: MTConfig(False, "shared", "", True))


@pytest.mark.django_db
def test_deny_if_hidden_missing_task_mt_on(mt_enabled):
    """Under MT a MISSING task returns the SAME generic 404 as a hidden task, so
    another tenant's task ids can't be enumerated by status code."""
    import apiv2.views as views
    other = User.objects.create_user("b", "b@x.com", "x")
    resp = views._deny_if_hidden(FakeReq(other), None)
    assert resp is not None and resp.status_code == 404


@pytest.mark.django_db
def test_deny_if_hidden_missing_task_mt_off_defers(monkeypatch):
    """With MT DISABLED there is no isolation to enforce, so the gate must NOT turn
    a missing task into a 404 — it defers (None) to the caller's own missing-task
    handling. This preserves upstream's default-install contract (e.g. reprocess of
    a nonexistent task returns 200 with an error body — the CI regression this
    fixes: tests/web/test_apiv2.py::ReprocessTask.test_task_does_not_exist)."""
    import apiv2.views as views
    _force_mt_off(monkeypatch)
    other = User.objects.create_user("b", "b@x.com", "x")
    assert views._deny_if_hidden(FakeReq(other), None) is None


@pytest.mark.django_db
def test_deny_manage_missing_task_mt_on(cape_db, mt_enabled, monkeypatch):
    """_deny_manage mirrors _deny_if_hidden for a missing task: generic 404 under MT.
    (cape_db initializes the CAPE db singleton that views.db.view_task binds to —
    same fixture the other views.db-patching tests in this file use.)"""
    import apiv2.views as views
    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: None)
    other = User.objects.create_user("b", "b@x.com", "x")
    resp = views._deny_manage(FakeReq(other), 1)
    assert resp is not None and resp.status_code == 404


@pytest.mark.django_db
def test_deny_manage_missing_task_mt_off_defers(cape_db, monkeypatch):
    """_deny_manage defers (None) on a missing task when MT is off — same
    default-install back-compat as _deny_if_hidden."""
    import apiv2.views as views
    _force_mt_off(monkeypatch)
    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: None)
    other = User.objects.create_user("b", "b@x.com", "x")
    assert views._deny_manage(FakeReq(other), 1) is None


@pytest.mark.django_db
def test_deny_if_hidden_owner_allowed():
    import apiv2.views as views
    owner = User.objects.create_user("o", "o@x.com", "x")
    # owner of a private job -> allowed (None == no denial)
    assert views._deny_if_hidden(FakeReq(owner), FakeTask(user_id=owner.id, tenant_id=10, visibility="private")) is None


@pytest.mark.django_db
def test_deny_if_hidden_public_allowed():
    import apiv2.views as views
    other = User.objects.create_user("b", "b@x.com", "x")
    assert views._deny_if_hidden(FakeReq(other), FakeTask(user_id=999, tenant_id=10, visibility="public")) is None


@pytest.mark.django_db
def test_toggle_visibility_authz_and_indistinguishability(cape_db, mt_enabled, monkeypatch):
    from rest_framework.test import APIClient
    from users.models import Tenant, UserProfile
    import apiv2.views as views

    ten = Tenant.objects.create(slug="t10", name="T10")

    def _in_tenant(username):
        u = User.objects.create_user(username, f"{username}@x.com", "x")
        p = UserProfile.objects.get(user=u)
        p.tenant = ten
        p.save()
        return User.objects.get(pk=u.pk)  # fresh, so request.user.userprofile is current

    owner = _in_tenant("o")
    member = _in_tenant("m")                                   # same tenant, not owner/admin
    outsider = User.objects.create_user("b", "b@x.com", "x")   # no tenant -> can't see tenant job

    state = {"vis": "tenant"}

    class T:
        id = 1

        def __init__(self):
            self.user_id = owner.id
            self.tenant_id = ten.id

        @property
        def visibility(self):
            return state["vis"]

    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: T())
    monkeypatch.setattr(views.db, "set_task_visibility",
                        lambda tid, vis: state.__setitem__("vis", vis), raising=False)

    c = APIClient()

    # owner toggles their own job
    c.force_authenticate(user=owner)
    r = c.patch("/apiv2/tasks/visibility/1/", {"visibility": "public"}, format="json")
    assert r.status_code == 200, r.content
    assert state["vis"] == "public"

    # invalid visibility -> 400 (owner can already see it, so revealing this leaks nothing)
    r = c.patch("/apiv2/tasks/visibility/1/", {"visibility": "bogus"}, format="json")
    assert r.status_code == 400 and r.json().get("error") is True
    state["vis"] = "tenant"  # reset for the deny cases

    # same-tenant member CAN read the tenant job but isn't owner/admin -> 403 (no leak)
    c.force_authenticate(user=member)
    r = c.patch("/apiv2/tasks/visibility/1/", {"visibility": "public"}, format="json")
    assert r.status_code == 403
    assert state["vis"] == "tenant"  # unchanged

    # outsider can't even SEE the tenant job -> indistinguishable 404 (no enumeration oracle)
    c.force_authenticate(user=outsider)
    r = c.patch("/apiv2/tasks/visibility/1/", {"visibility": "public"}, format="json")
    assert r.status_code == 404
    assert state["vis"] == "tenant"  # unchanged


# Views that resolve/serve a sample or file by hash or sample_id (NOT routed by
# task_id, so the routed-task_id gate above can't see them). Each must reference
# _deny_by_hash (or _deny_task for a task-id variant) or it leaks samples/metadata
# across tenants.
HASH_SERVING_VIEWS = ("file", "files_view")


@pytest.mark.parametrize("name", HASH_SERVING_VIEWS)
def test_hash_addressed_view_enforces_visibility(name):
    """SECURITY GATE: hash-addressed sample/file/metadata views must reference a
    visibility guard (_deny_by_hash / _deny_task), or they leak across tenants."""
    import apiv2.views as views
    src = _func_source(views, name)
    assert src is not None, f"{name} not found in apiv2.views"
    assert ("_deny_by_hash" in src) or ("_deny_task" in src), \
        f"apiv2.{name} serves by hash/sample but references no _deny_by_hash/_deny_task guard"


def _hash_routed_views(urls_module):
    """Return the set of view names for every (live, non-commented) URL whose
    pattern captures a hash or sample-id group: md5, sha1, sha256, or sample_id.
    Mirrors _routed_task_views but for hash/sample-id groups instead of task_id."""
    HASH_GROUPS = ("md5", "sha1", "sha256", "sample_id")
    text = "\n".join(
        ln for ln in open(urls_module.__file__).read().splitlines() if not ln.lstrip().startswith("#")
    )
    out = set()
    for m in re.finditer(r"(?:re_path|path)\((.*?views\.([a-zA-Z_]+))", text, re.S):
        pattern_span, name = m.group(1), m.group(2)
        if any(f"(?P<{g}>" in pattern_span or f"<{g}>" in pattern_span for g in HASH_GROUPS):
            out.add(name)
    return out


def _all_hash_views():
    import apiv2.urls
    import apiv2.views
    discovered = _hash_routed_views(apiv2.urls)
    # Explicitly pin tasks_search (it filters via visible_to= in list_tasks,
    # which is in GUARD_MARKERS) so it remains covered even if its URL pattern
    # changes to a non-hash-group form in the future.
    names = discovered | {"tasks_search"}
    return [(apiv2.views, n) for n in sorted(names)]


_HASH_CASES = _all_hash_views()


HASH_GUARD_MARKERS = GUARD_MARKERS + ("_deny_by_hash",)


@pytest.mark.parametrize("views_mod,name", _HASH_CASES, ids=[n for _, n in _HASH_CASES])
def test_hash_routed_view_enforces_visibility(views_mod, name):
    """SECURITY GATE (auto-discover): every view whose URL pattern captures a
    hash or sample-id group must reference a visibility guard from GUARD_MARKERS
    or _deny_by_hash, or it leaks cross-tenant sample/task metadata. tasks_search
    is pinned here regardless of future URL-pattern changes."""
    src = _func_source(views_mod, name)
    if src is None:
        pytest.skip(f"{name} not found in {views_mod.__name__}")
    assert any(m in src for m in HASH_GUARD_MARKERS), (
        f"{views_mod.__name__}.{name} is hash/sample-id routed but references "
        f"no guard {HASH_GUARD_MARKERS} — cross-tenant leak risk"
    )


def test_hash_routed_discovery_catches_unguarded(tmp_path, monkeypatch):
    """Negative regression: confirm _hash_routed_views would flag a
    fictitious unguarded view if one were added to urls.py."""
    fake_urls = tmp_path / "fake_urls.py"
    # A URL that captures sha256 but calls a view with no guard
    fake_urls.write_text(
        'from apiv2 import views\n'
        'urlpatterns = [\n'
        '    __import__("django.urls", fromlist=["re_path"]).re_path(\n'
        '        r"^unguarded/(?P<sha256>[a-fA-F\\d]{64})/$", views.cuckoo_status\n'
        '    ),\n'
        ']\n'
    )
    import importlib.util
    spec = importlib.util.spec_from_file_location("fake_urls", fake_urls)
    fake_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fake_mod)
    discovered = _hash_routed_views(fake_mod)
    assert "cuckoo_status" in discovered, (
        "_hash_routed_views failed to detect a sha256-routed unguarded view"
    )


@pytest.mark.django_db
def test_tasks_delete_many_skips_unmanageable_cross_tenant(cape_db, mt_enabled, monkeypatch):
    """A tenant-less user POSTing another tenant's private task id to the bulk-
    delete endpoint must NOT delete it (the worst confirmed critical)."""
    import types
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskdelete={"enabled": True}))  # bypass freeze
    monkeypatch.setattr(views.db, "view_task",
                        lambda tid: FakeTask(user_id=999, tenant_id=10, visibility="private"))
    monkeypatch.setattr(views.db, "delete_task", lambda tid: deleted.append(tid) or True)
    monkeypatch.setattr(views, "mongo_delete_data", lambda *a, **k: None, raising=False)

    u = User.objects.create_user("dm", "dm@x.com", "x")  # tenant-less -> can't manage
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "1"})
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert deleted == []                       # cross-tenant task NOT deleted
    assert resp.data.get(1) == "not exists"    # indistinguishable from missing


def _dm_stub(monkeypatch, deleted):
    """Common stubs for the bulk-delete happy path: a manageable, non-running task whose SQL delete
    succeeds. view_task returns a REAL task so `deleted` is mutation-detecting (not vacuous)."""
    import types
    import apiv2.views as views
    _t = FakeTask(user_id=1, tenant_id=None, visibility="public")
    _t.status = "reported"  # not TASK_RUNNING
    # happy path: [taskdelete] enabled so the authed-non-staff freeze gate doesn't short-circuit
    # (freeze has its own dedicated tests). Callers that test the freeze override apiconf after this.
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskdelete={"enabled": True}))
    monkeypatch.setattr(views, "can_manage_task", lambda u, t: True, raising=False)
    monkeypatch.setattr(views, "can_delete_task", lambda u, t: True, raising=False)  # delete paths gate on this
    monkeypatch.setattr(views.db, "view_task", lambda tid: _t)
    monkeypatch.setattr(views.db, "delete_task", lambda tid: deleted.append(tid) or True)
    monkeypatch.setattr(views.db, "session",
                        types.SimpleNamespace(commit=lambda: None, rollback=lambda: None), raising=False)
    monkeypatch.setattr(views, "delete_folder", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(views, "central_delete_analysis", lambda *a, **k: None, raising=False)


@pytest.mark.django_db
def test_tasks_delete_many_reports_malformed_id_without_dropping_batch(cape_db, monkeypatch):
    """A malformed id is reported per-id (200 + error) and does NOT reject the batch or 500 mid-way --
    the valid ids are still reclaimed. Guards against the all-or-nothing whole-batch leak (neither dist.py
    nor go-fetcher inspects a 4xx). view_task returns a real task so `deleted` is RED against the old
    all-or-nothing 400 (which reclaimed nothing)."""
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _dm_stub(monkeypatch, deleted)
    u = User.objects.create_user("mid", "mid@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "10,oops,11"})
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert resp.status_code == 200                   # no all-or-nothing 4xx
    assert sorted(deleted) == [10, 11]               # valid ids STILL reclaimed
    assert "oops" in resp.data.get("invalid_ids", [])  # reported in a LIST, not a top-level key
    assert resp.data.get("status") == "partial_error"  # covers the _invalid status contract
    assert resp.data.get("error") is True            # surfaced, not a silent OK


@pytest.mark.django_db
def test_tasks_delete_many_out_of_range_id_is_invalid_not_500(cape_db, monkeypatch):
    """A digit-only but out-of-range id (> 2**31-1, beyond Task.id's 32-bit range) is reported as invalid,
    not passed to view_task where the driver would raise a bodiless 500 mid-batch after earlier deletes
    already committed. Keeps the validate-before-delete invariant."""
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _dm_stub(monkeypatch, deleted)
    u = User.objects.create_user("oor", "oor@x.com", "x")
    _huge = "9" * 4301  # > CPython's 4300-digit int(str) cap -> int() would itself raise ValueError -> 500
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "10,2147483648,%s,11" % _huge})
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert resp.status_code == 200                            # not a 500 (neither out-of-range nor >4300 digits)
    assert sorted(deleted) == [10, 11]                        # in-range ids reclaimed
    _inv = resp.data.get("invalid_ids", [])
    assert "2147483648" in _inv and _huge in _inv            # both reported, never hit view_task or int()-raise


@pytest.mark.django_db
def test_tasks_delete_many_zero_padded_id_accepted(cape_db, monkeypatch):
    """A left-zero-padded id (e.g. %011d) is a valid in-range id, not rejected: strip leading zeros
    before the length/magnitude gate."""
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _dm_stub(monkeypatch, deleted)
    u = User.objects.create_user("zp", "zp@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "00000000001,000010"})
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert resp.status_code == 200
    assert sorted(deleted) == [1, 10]                        # padded ids resolved, not reported invalid
    assert resp.data.get("invalid_ids") is None
    assert resp.data.get("status") == "OK"


@pytest.mark.django_db
def test_tasks_delete_many_repeated_form_keys(cape_db, monkeypatch):
    """Repeated form ids= keys (ids=10&ids=11&ids=12) are all honored via getlist, not truncated to
    the last value."""
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _dm_stub(monkeypatch, deleted)
    u = User.objects.create_user("rk", "rk@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": ["10", "11", "12"]})
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert resp.status_code == 200
    assert sorted(deleted) == [10, 11, 12]                   # all three, not just the last


@pytest.mark.django_db
def test_tasks_delete_many_gates_on_can_delete_not_can_manage(cape_db, monkeypatch):
    """The delete path authorizes via can_delete_task (stricter for public jobs), NOT can_manage_task:
    a caller who may manage a public task but not delete it is refused."""
    import types
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _t = FakeTask(user_id=1, tenant_id=10, visibility="public")
    _t.status = "reported"
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskdelete={"enabled": True}))
    monkeypatch.setattr(views.db, "view_task", lambda tid: _t)
    monkeypatch.setattr(views.db, "delete_task", lambda tid: deleted.append(tid) or True)
    monkeypatch.setattr(views, "can_manage_task", lambda u, t: True, raising=False)   # manage WOULD allow
    monkeypatch.setattr(views, "can_delete_task", lambda u, t: False, raising=False)  # delete denies

    u = User.objects.create_user("cd", "cd@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "5"})
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert deleted == []                                     # gated by can_delete_task (deny), not can_manage
    assert resp.data.get(5) == "not exists"


@pytest.mark.django_db
def test_tasks_delete_many_reads_json_body(cape_db, monkeypatch):
    """ids sourced from request.data so a JSON-bodied caller isn't a silent no-op (request.POST is
    empty for application/json -> would answer 200 having deleted nothing)."""
    import json as _json
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _dm_stub(monkeypatch, deleted)
    u = User.objects.create_user("js", "js@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/",
                                   data=_json.dumps({"ids": "101,102"}), content_type="application/json")
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert resp.status_code == 200
    assert sorted(deleted) == [101, 102]             # JSON body honored, not a silent no-op
    assert resp.data.get("status") == "OK"           # clean-batch status contract covered


@pytest.mark.django_db
def test_tasks_delete_many_json_delete_mongo_opt_out_honored(cape_db, monkeypatch):
    """A JSON caller's delete_mongo=false RETAIN opt-out must be honored: delete_mongo is read from the
    SAME body as ids (request.data), not request.POST (empty for application/json -> would default True
    and irreversibly erase the report the caller asked to keep)."""
    import json as _json
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted, wiped = [], []
    _dm_stub(monkeypatch, deleted)
    monkeypatch.setattr(views, "central_delete_analysis",
                        lambda req, tid, **k: wiped.append(tid) or None, raising=False)
    u = User.objects.create_user("jmo", "jmo@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/",
                                   data=_json.dumps({"ids": "101,102", "delete_mongo": False}),
                                   content_type="application/json")
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert resp.status_code == 200
    assert sorted(deleted) == [101, 102]             # SQL rows deleted
    assert wiped == []                               # reports RETAINED (opt-out honored, not erased)


@pytest.mark.django_db
def test_tasks_delete_many_json_array_body_is_ids_not_500(cape_db, monkeypatch):
    """A top-level JSON array body ([10,11]) is treated as the ids list, not an AttributeError 500 on
    request.data.get (request.data is a list, which has no .get)."""
    import json as _json
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _dm_stub(monkeypatch, deleted)
    u = User.objects.create_user("jarr", "jarr@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/",
                                   data=_json.dumps([10, 11]), content_type="application/json")
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert resp.status_code == 200                   # not a 500
    assert sorted(deleted) == [10, 11]


@pytest.mark.django_db
def test_tasks_delete_many_invalid_token_does_not_clobber_envelope(cape_db, monkeypatch):
    """Tokens spelled like reserved envelope keys ('status'/'error') are reported in the invalid_ids LIST
    and must NOT overwrite the summary keys."""
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _dm_stub(monkeypatch, deleted)
    u = User.objects.create_user("clob", "clob@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "10,status,error,11"})
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert sorted(deleted) == [10, 11]                       # valid ids still reclaimed
    assert set(resp.data.get("invalid_ids", [])) == {"status", "error"}  # both reported, not swallowed
    assert resp.data.get("status") == "partial_error"        # envelope intact (not clobbered by a token)
    assert resp.data.get("error") is True


@pytest.mark.django_db
def test_tasks_delete_many_missing_ids_is_noop(cape_db, monkeypatch):
    """Absent/empty ids -> clean no-op: NOTHING deleted (capture proves it), not the old int('') 500."""
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _dm_stub(monkeypatch, deleted)  # view_task returns a deletable task, so an empty-ids delete would be caught
    u = User.objects.create_user("noid", "noid@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {})
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert resp.status_code == 200
    assert deleted == []                             # nothing deleted on empty ids
    assert resp.data.get("status") == "OK"           # clean-batch status contract covered


@pytest.mark.django_db
def test_tasks_delete_many_freeze_gates_authed_nonstaff_not_anon(cape_db, monkeypatch):
    """[taskdelete] disabled freezes an authenticated non-staff caller (403) but NOT the anonymous
    stock/dist worker-cleanup path (which must keep reclaiming disk)."""
    import types
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _dm_stub(monkeypatch, deleted)
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskdelete={"enabled": False}))  # after _dm_stub

    # authenticated non-staff -> frozen
    u = User.objects.create_user("fz", "fz@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "10"})
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)
    assert resp.status_code == 403
    assert deleted == []

    # anonymous (no auth = the stock/dist path) -> NOT frozen, reclamation proceeds
    deleted.clear()
    req_anon = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "10"})
    resp_anon = views.tasks_delete_many(req_anon)
    assert resp_anon.status_code == 200
    assert deleted == [10]


@pytest.mark.django_db
def test_tasks_delete_many_freeze_bypassed_by_staff_and_when_enabled(cape_db, monkeypatch):
    """Staff bypass the freeze, and an authed non-staff caller is allowed when [taskdelete] is enabled."""
    import types
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    _dm_stub(monkeypatch, deleted)
    # staff + disabled -> bypass
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskdelete={"enabled": False}))
    staff = User.objects.create_user("stf", "stf@x.com", "x")
    staff.is_staff = True
    staff.save()
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "10"})
    force_authenticate(req, user=staff)
    assert views.tasks_delete_many(req).status_code == 200
    assert deleted == [10]
    # non-staff + ENABLED -> allowed
    deleted.clear()
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskdelete={"enabled": True}))
    u = User.objects.create_user("en", "en@x.com", "x")
    req2 = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "11"})
    force_authenticate(req2, user=u)
    assert views.tasks_delete_many(req2).status_code == 200
    assert deleted == [11]


@pytest.mark.django_db
def test_tasks_delete_rejects_negative_range_no_mass_delete(cape_db, monkeypatch):
    """/tasks/delete/-5/ must 400, NOT expand to range(0,6) and mass-delete tasks 1-5
    (the force_int('')==0 footgun)."""
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
    monkeypatch.setattr(views.db, "delete_task", lambda tid: deleted.append(tid) or True)
    u = User.objects.create_user("td1", "td1@x.com", "x")  # staff bypasses the gate
    u.is_staff = True
    u.save()
    req = APIRequestFactory().get("/apiv2/tasks/delete/-5/")
    force_authenticate(req, user=u)
    resp = views.tasks_delete(req, "-5")
    assert resp.status_code == 400
    assert deleted == []                             # no mass delete


@pytest.mark.django_db
def test_tasks_delete_rejects_multi_hyphen_no_500(cape_db, monkeypatch):
    """/tasks/delete/1-2-3/ must 400, not 500 (ValueError: too many values to unpack)."""
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    u = User.objects.create_user("td2", "td2@x.com", "x")
    u.is_staff = True
    u.save()
    req = APIRequestFactory().get("/apiv2/tasks/delete/1-2-3/")
    force_authenticate(req, user=u)
    resp = views.tasks_delete(req, "1-2-3")
    assert resp.status_code == 400


@pytest.mark.django_db
def test_tasks_delete_many_empty_delete_mongo_retains(cape_db, monkeypatch):
    """A present-but-EMPTY delete_mongo RETAINS the Mongo report (upstream bool("")=False
    back-compat) -- NOT a 400 and NOT a delete. The explicit-string parse still fixes the
    original bug where a real "False" was coerced truthy and wrongly deleted."""
    import types
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    _t = FakeTask(user_id=1, tenant_id=None, visibility="public")
    _t.status = "reported"                     # not TASK_RUNNING
    called = []
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskdelete={"enabled": True}))  # bypass freeze
    monkeypatch.setattr(views, "can_manage_task", lambda u, t: True, raising=False)
    monkeypatch.setattr(views.db, "view_task", lambda tid: _t)
    monkeypatch.setattr(views.db, "delete_task", lambda tid: True)
    monkeypatch.setattr(views.db, "session",
                        types.SimpleNamespace(commit=lambda: None, rollback=lambda: None), raising=False)
    monkeypatch.setattr(views, "delete_folder", lambda *a, **k: None, raising=False)
    monkeypatch.setattr(views, "central_delete_analysis",
                        lambda *a, **k: called.append(a) or None, raising=False)

    u = User.objects.create_user("emr", "emr@x.com", "x")
    req = APIRequestFactory().post("/apiv2/tasks/delete_many/", {"ids": "1", "delete_mongo": ""})
    force_authenticate(req, user=u)
    resp = views.tasks_delete_many(req)

    assert resp.status_code != 400             # empty no longer rejected (back-compat)
    assert resp.data.get(1) == "deleted"       # task deleted
    assert called == []                        # report RETAINED: central_delete_analysis NOT called


@pytest.mark.django_db
def test_ext_tasks_search_drops_cross_tenant_rows(cape_db, mt_enabled, monkeypatch):
    """ext_tasks_search batch-filters perform_search rows through
    list_tasks(visible_to=viewer) in ONE query: a report row for a task the caller
    can't see (foreign/private) must be dropped from the response. Locks the N+1 ->
    batch rewrite so it can't regress into a cross-tenant leak."""
    import types
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    class _T:
        def __init__(self, i):
            self.id = i

    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(extendedtasksearch={"enabled": True}))
    monkeypatch.setattr(views, "repconf", types.SimpleNamespace(mongodb=types.SimpleNamespace(enabled=True)), raising=False)
    monkeypatch.setattr(views, "es_as_db", False, raising=False)
    monkeypatch.setattr(views, "perform_search", lambda *a, **k: [{"info": {"id": 2}}, {"info": {"id": 3}}])
    # only task 2 is visible to this viewer; task 3 (foreign/private) is not
    monkeypatch.setattr(views.db, "list_tasks", lambda *a, **k: [_T(2)])

    req = APIRequestFactory().post("/apiv2/tasks/extendedsearch/", {"option": "malscore", "argument": "5"})
    u = User.objects.create_user("ext", "ext@x.com", "x")  # tenant-less, non-admin
    force_authenticate(req, user=u)
    req.user = u
    resp = views.ext_tasks_search(req)
    ids = [r["info"]["id"] for r in resp.data.get("data", [])]
    assert ids == [2]  # foreign task 3 dropped by the batch visibility filter


# --- missing-task regression: the MT gate deleted upstream's `if not task:` guard
# in these 3 endpoints; with MT off _deny_* defers on a missing task, so without
# the restored guard they fall through to task.to_dict()/task.guest -> HTTP 500.
# MT off MUST reproduce upstream's 200 error body; MT on stays the generic 404.
def _apiget(views, u, path):
    from rest_framework.test import APIRequestFactory, force_authenticate
    req = APIRequestFactory().get(path)
    force_authenticate(req, user=u)
    req.user = u
    return req


@pytest.mark.django_db
def test_tasks_view_missing_mt_off_restores_upstream(cape_db, monkeypatch):
    import types
    import apiv2.views as views
    _force_mt_off(monkeypatch)
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskview={"enabled": True}))
    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: None)
    u = User.objects.create_user("tv_off", "tv_off@x.com", "x")
    resp = views.tasks_view(_apiget(views, u, "/apiv2/tasks/view/999/"), 999)
    assert resp.status_code == 200
    assert resp.data == {"error": True, "error_value": "Task not found in database"}


@pytest.mark.django_db
def test_tasks_view_missing_mt_on_generic_404(cape_db, mt_enabled, monkeypatch):
    import types
    import apiv2.views as views
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskview={"enabled": True}))
    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: None)
    u = User.objects.create_user("tv_on", "tv_on@x.com", "x")
    resp = views.tasks_view(_apiget(views, u, "/apiv2/tasks/view/999/"), 999)
    assert resp.status_code == 404


@pytest.mark.django_db
def test_tasks_status_missing_mt_off_restores_upstream(cape_db, monkeypatch):
    import types
    import apiv2.views as views
    _force_mt_off(monkeypatch)
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskstatus={"enabled": True}))
    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: None)
    u = User.objects.create_user("ts_off", "ts_off@x.com", "x")
    resp = views.tasks_status(_apiget(views, u, "/apiv2/tasks/status/999/"), 999)
    assert resp.status_code == 200
    assert resp.data == {"error": True, "error_value": "Task does not exist"}


@pytest.mark.django_db
def test_tasks_status_missing_mt_on_generic_404(cape_db, mt_enabled, monkeypatch):
    import types
    import apiv2.views as views
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskstatus={"enabled": True}))
    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: None)
    u = User.objects.create_user("ts_on", "ts_on@x.com", "x")
    resp = views.tasks_status(_apiget(views, u, "/apiv2/tasks/status/999/"), 999)
    assert resp.status_code == 404


def _apipost(views, u, path):
    from rest_framework.test import APIRequestFactory, force_authenticate
    req = APIRequestFactory().post(path)  # tasks_file_stream is @api_view(["POST"])
    force_authenticate(req, user=u)
    req.user = u
    return req


@pytest.mark.django_db
def test_tasks_file_stream_missing_mt_off_restores_upstream(cape_db, monkeypatch):
    import types
    import apiv2.views as views
    _force_mt_off(monkeypatch)
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskstatus={"enabled": True}))
    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: None)
    u = User.objects.create_user("fs_off", "fs_off@x.com", "x")
    resp = views.tasks_file_stream(_apipost(views, u, "/apiv2/tasks/get/stream/999/"), 999)
    assert resp.status_code == 200
    assert resp.data == {"error": True, "error_value": "Task does not exist"}


@pytest.mark.django_db
def test_tasks_file_stream_missing_mt_on_generic_404(cape_db, mt_enabled, monkeypatch):
    import types
    import apiv2.views as views
    monkeypatch.setattr(views, "apiconf", types.SimpleNamespace(taskstatus={"enabled": True}))
    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: None)
    u = User.objects.create_user("fs_on", "fs_on@x.com", "x")
    resp = views.tasks_file_stream(_apipost(views, u, "/apiv2/tasks/get/stream/999/"), 999)
    assert resp.status_code == 404


def test_every_perform_search_caller_passes_viewer():
    """SECURITY GATE: perform_search() is unscoped by default (no tenant filter
    at the mongo/ES layer). Every web caller MUST pass viewer= so the query is
    tenant-scoped — otherwise it leaks cross-tenant task ids / hashes / detections
    / artifact paths (this is exactly how the capeyarazipall + report-existent_tasks
    leaks happened). Fails the build if any caller omits viewer=."""
    import ast
    import importlib

    offenders = []
    for modname in ("analysis.views", "apiv2.views", "submission.views"):
        mod = importlib.import_module(modname)
        tree = ast.parse(open(mod.__file__).read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "perform_search":
                if "viewer" not in {kw.arg for kw in node.keywords}:
                    offenders.append(f"{modname}:{node.lineno}")
    assert not offenders, f"perform_search() called without viewer= (cross-tenant leak risk) at: {offenders}"


def test_viewer_scope_match_locked_vs_disabled(monkeypatch):
    """The systemic perform_search scope helper: a locked-mode tenant viewer gets
    a public/tenant/mine $or; break-glass and MT-disabled get None (no filter).
    _viewer_scope_match reads lib.cuckoo.common.tenancy.multitenancy_config at
    call time, so patch THAT (not users.tenancy's copy)."""
    from lib.cuckoo.common import web_utils
    from lib.cuckoo.common.tenancy import Viewer, MTConfig
    import lib.cuckoo.common.tenancy as t

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    v = Viewer(user_id=2, tenant_id=10)              # locked, non-admin
    f = web_utils._viewer_scope_match(v)
    assert "$or" in f
    assert {"info.visibility": "public"} in f["$or"]
    assert {"info.tenant_id": 10, "info.visibility": "tenant"} in f["$or"]
    assert {"info.user_id": 2} in f["$or"]

    # break-glass -> no filter
    assert web_utils._viewer_scope_match(Viewer(user_id=9, tenant_id=None, is_local_admin=True)) is None
    # MT disabled -> no filter
    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(False, "shared", "", True))
    assert web_utils._viewer_scope_match(v) is None
    # no viewer -> no filter
    assert web_utils._viewer_scope_match(None) is None


def test_viewer_scope_es_filter_locked_vs_disabled(monkeypatch):
    """ES analogue of the scope helper: locked-mode tenant viewer gets a
    public/own-tenant/mine bool-should; break-glass / disabled / None -> no
    filter (so the ES search branches are scoped the same as the mongo ones)."""
    from lib.cuckoo.common import web_utils
    from lib.cuckoo.common.tenancy import Viewer, MTConfig
    import lib.cuckoo.common.tenancy as t

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    v = Viewer(user_id=2, tenant_id=10)
    f = web_utils._viewer_scope_es_filter(v)
    shoulds = f["bool"]["should"]
    assert {"term": {"info.visibility": "public"}} in shoulds
    assert {"term": {"info.user_id": 2}} in shoulds
    assert any(c.get("bool", {}).get("filter") == [{"term": {"info.tenant_id": 10}}, {"term": {"info.visibility": "tenant"}}] for c in shoulds)
    assert f["bool"]["minimum_should_match"] == 1

    # anon/tenant-less in locked mode -> public only (never global)
    anon = web_utils._viewer_scope_es_filter(Viewer(user_id=None, tenant_id=None))
    assert anon["bool"]["should"] == [{"term": {"info.visibility": "public"}}]

    # break-glass / disabled / None -> no filter
    assert web_utils._viewer_scope_es_filter(Viewer(user_id=9, tenant_id=None, is_local_admin=True)) is None
    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(False, "shared", "", True))
    assert web_utils._viewer_scope_es_filter(v) is None
    assert web_utils._viewer_scope_es_filter(None) is None


# Multi-doc mongo pivots (mongo_aggregate / mongo_find) can span tenants — unlike
# task_id-keyed mongo_find_one / es.search reads gated by the view decorator. Each
# web view issuing one MUST be reviewed to be tenant-scoped; a NEW caller trips
# the gate below so a *secondary* unscoped cross-task query (the leak class behind
# report()/existent_tasks and the compare/hunt pivots) can't land silently. The
# marker gates can't catch this — they pass as long as ANY guard string appears in
# the function, even when a second query in the same function is unscoped.
# perform_search pivots are covered by test_every_perform_search_caller_passes_viewer.
CROSS_TASK_MONGO_PIVOTS = {"mongo_aggregate", "mongo_find"}
REVIEWED_MONGO_PIVOTS = {
    "analysis.views:index": "mongo_find by info.id $in IDs from list_tasks(visible_to=) — scoped upstream",
    "analysis.views:search_behavior": "mongo_find('calls', _id $in) — ObjectIds from the gated task's own behavior doc",
    "analysis.views:report": "mongo_aggregate $match info.id == the can_view_task-gated task_id",
    "analysis.views:hunt": "mongo_aggregate $facet pinned by entitled_scope_filter()",
    "apiv2.views:tasks_rollingsuri": "mongo_find then batch list_tasks(visible_to=) membership (+ is_local_admin fast-path)",
    "compare.views:left": "mongo_find md5-pivot AND-ed with entitled_scope_filter()",
    "compare.views:hash": "mongo_find md5-pivot AND-ed with entitled_scope_filter()",
}


def _functions_calling(modname, names):
    import ast
    import importlib

    mod = importlib.import_module(modname)
    with open(mod.__file__, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    out = set()
    # Include async views — an async def issuing an unscoped pivot must not bypass the gate.
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        for node in ast.walk(fn):
            if isinstance(node, ast.Call):
                nm = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if nm in names:
                    out.add(f"{modname}:{fn.name}")
    return out


def test_cross_task_mongo_pivots_are_reviewed():
    """SECURITY GATE: every web view issuing a multi-doc mongo pivot
    (mongo_aggregate/mongo_find) must be in REVIEWED_MONGO_PIVOTS — i.e. proven
    tenant-scoped. A new (or newly-added) pivot trips this gate so a secondary
    unscoped cross-task query can't ship without review. Closes the marker-gate
    blind spot that let report()'s existent_tasks pivot leak while its primary
    read was gated."""
    # Import directly (no silent skip): a module that can't be scanned is a
    # coverage hole, not a pass — the gate must fail loudly rather than miss a
    # module's pivots. These all import in the test env (same set the routed gate
    # scans via _all_task_views()).
    found = set()
    for modname in ("analysis.views", "apiv2.views", "compare.views", "dashboard.views", "submission.views", "guac.views"):
        found |= _functions_calling(modname, CROSS_TASK_MONGO_PIVOTS)

    unreviewed = sorted(found - set(REVIEWED_MONGO_PIVOTS))
    assert not unreviewed, (
        f"Unreviewed cross-task mongo pivot(s): {unreviewed}. A multi-doc "
        f"mongo_aggregate/mongo_find can span tenants — verify it is tenant-scoped "
        f"(scope_match / entitled_scope_filter / per-row can_view_task / task_id-keyed "
        f"after a gate) and add it to REVIEWED_MONGO_PIVOTS with the reason."
    )
    # Keep the allowlist tight: drop entries whose function no longer exists.
    stale = sorted(set(REVIEWED_MONGO_PIVOTS) - found)
    assert not stale, f"Stale REVIEWED_MONGO_PIVOTS entries (function gone): {stale}"


# By-hash access to the global content-addressed sample store (storage/binaries
# + db.sample_path_by_hash) is shared across tenants, so it MUST go through the
# visible-task boundary (tenancy.can_view_sample / _deny_by_hash / sample_path_
# by_hash(visible_to=)). A web view that resolves a sample by attacker-supplied
# hash WITHOUT one of those markers streams another tenant's bytes (the deep-hunt
# capeyarazipall + resubmit + download-services criticals). This gate trips on any
# such function lacking a by-hash guard.
BYHASH_RESOLVERS = ("sample_path_by_hash",)            # call markers
BYHASH_GUARDS = ("can_view_sample", "_deny_by_hash", "visible_to")


def test_byhash_sample_resolution_is_gated():
    """SECURITY GATE: any web view that resolves a sample by hash (calls
    sample_path_by_hash, or builds a storage/binaries/<hash> path) must reference
    a by-hash entitlement guard (can_view_sample / _deny_by_hash / visible_to).
    Locks the deep-hunt byte-exfil fixes so a new by-hash surface can't ship
    ungated."""
    import ast
    import importlib

    offenders = []
    for modname in ("analysis.views", "apiv2.views", "submission.views", "compare.views"):
        mod = importlib.import_module(modname)
        with open(mod.__file__, encoding="utf-8") as fh:
            src = fh.read()
        tree = ast.parse(src)
        lines = src.splitlines()
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            body = "\n".join(lines[fn.lineno - 1: fn.end_lineno])
            resolves_byhash = any(r in body for r in BYHASH_RESOLVERS) or (
                '"binaries"' in body or "'binaries'" in body
            )
            if resolves_byhash and not any(g in body for g in BYHASH_GUARDS):
                offenders.append(f"{modname}:{fn.name}")
    assert not offenders, (
        f"By-hash sample resolution without an entitlement guard {BYHASH_GUARDS}: "
        f"{offenders}. Gate via can_view_sample / _deny_by_hash / sample_path_by_hash(visible_to=) "
        f"— an attacker-supplied hash must not stream another tenant's sample bytes."
    )


@pytest.mark.django_db
def test_resolve_task_id_regates_recovery_rtid_pivot(cape_db, mt_enabled, monkeypatch):
    """rtid wrong-object regression: after a Recovery_<N> pivot to a DIFFERENT task,
    _resolve_task_id must re-gate visibility on the RESOLVED id — the initial
    _deny_if_hidden only authorized the original task, so serving the resolved
    task's artifacts without a re-check leaks another tenant's bytes."""
    import types
    import apiv2.views as av
    from django.contrib.auth.models import User
    from django.test import RequestFactory

    class OwnTask:      # original id 5 — public, readable by anyone
        id = 5
        user_id = 0
        tenant_id = 10
        visibility = "public"

    class ForeignTask:  # rtid 6 — another tenant's private analysis
        id = 6
        user_id = 999
        tenant_id = 20
        visibility = "private"

    monkeypatch.setattr(av, "apiconf", types.SimpleNamespace())  # enabled_key -> None -> skip gate
    monkeypatch.setattr(av.db, "view_task", lambda tid, *a, **k: OwnTask() if int(tid) == 5 else ForeignTask())
    monkeypatch.setattr(av, "validate_task", lambda tid, *a, **k: {"error": False, "rtid": 6, "tlp": ""})

    req = RequestFactory().get("/x")
    req.user = User.objects.create_user("rtid_neg", "rtid_neg@x.com", "x")  # tenant-less, non-admin
    resolved, err = av._resolve_task_id(req, 5, "taskpcap")
    assert resolved is None and err is not None  # denied on the resolved foreign id


@pytest.mark.django_db
def test_resolve_task_id_allows_readable_rtid_pivot(cape_db, mt_enabled, monkeypatch):
    """Positive control: a Recovery pivot to a task the requester CAN read resolves
    normally (the re-gate must not block legitimate recovery)."""
    import types
    import apiv2.views as av
    from django.contrib.auth.models import User
    from django.test import RequestFactory

    class OwnTask:
        id = 5
        user_id = 0
        tenant_id = 10
        visibility = "public"

    class OwnTask2:
        id = 6
        user_id = 0
        tenant_id = 10
        visibility = "public"

    monkeypatch.setattr(av, "apiconf", types.SimpleNamespace())
    monkeypatch.setattr(av.db, "view_task", lambda tid, *a, **k: OwnTask() if int(tid) == 5 else OwnTask2())
    monkeypatch.setattr(av, "validate_task", lambda tid, *a, **k: {"error": False, "rtid": 6, "tlp": ""})

    req = RequestFactory().get("/x")
    req.user = User.objects.create_user("rtid_pos", "rtid_pos@x.com", "x")
    resolved, err = av._resolve_task_id(req, 5, "taskpcap")
    assert resolved == 6 and err is None


@pytest.mark.django_db
def test_tasks_view_regates_recovery_pivot(cape_db, mt_enabled, monkeypatch):
    """rtid wrong-object (tasks_view INLINE pivot, separate from _resolve_task_id):
    a TASK_RECOVERED task whose `custom` points Recovery_<N> at another tenant's
    task must NOT serve that task's data — re-gate on the resolved id."""
    import types
    import apiv2.views as av
    from django.contrib.auth.models import User
    from rest_framework.test import APIRequestFactory, force_authenticate

    class OwnRecovered:      # id 5 — public + readable; recovers to id 6
        id = 5
        user_id = 0
        tenant_id = 10
        visibility = "public"
        status = av.TASK_RECOVERED
        custom = "Recovery_6"
        guest = None
        errors = []
        sample_id = None

        def to_dict(self):
            return {"category": "file", "target": "/tmp/own"}

    class ForeignTask:      # id 6 — another tenant's private analysis
        id = 6
        user_id = 999
        tenant_id = 20
        visibility = "private"
        status = av.TASK_RECOVERED
        custom = None
        guest = None
        errors = []
        sample_id = None

        def to_dict(self):
            return {"category": "file", "target": "/tmp/secret"}

    monkeypatch.setattr(av, "apiconf", types.SimpleNamespace(taskview={"enabled": True}))
    monkeypatch.setattr(av.db, "view_task", lambda tid, **k: OwnRecovered() if int(tid) == 5 else ForeignTask())

    req = APIRequestFactory().get("/apiv2/tasks/view/5/")
    u = User.objects.create_user("tv_neg", "tv_neg@x.com", "x")  # tenant-less, non-admin
    force_authenticate(req, user=u)
    req.user = u
    resp = av.tasks_view(req, 5)
    assert resp.status_code == 404  # denied on the resolved foreign task, not served


def test_visibility_endpoint_opts_into_session_auth():
    """Codex: the report-page visibility toggle authenticates with a browser
    session; SessionAuthentication is dropped from the DRF default in SSO mode, so
    the endpoint must opt back into it (while keeping API-token auth)."""
    import apiv2.views as av
    from rest_framework.authentication import SessionAuthentication

    cls = getattr(av.tasks_set_visibility, "cls", None)
    assert cls is not None, "tasks_set_visibility should be a DRF @api_view"
    assert SessionAuthentication in cls.authentication_classes, \
        "visibility toggle must accept browser session auth (SSO drops it from the default)"


@pytest.mark.django_db
def test_toggle_visibility_rejects_tenant_for_tenantless_task(cape_db, mt_enabled, monkeypatch):
    """A task with tenant_id=None cannot be 'tenant'-visible (can_read's tenant branch
    needs a non-null job tenant) — the toggle API must reject that transition with a
    400 rather than persist an owner/break-glass-only invisible state."""
    from rest_framework.test import APIClient
    import apiv2.views as views

    owner = User.objects.create_user("ownt", "ownt@x.com", "x")  # tenant-less owner
    state = {"vis": "private"}

    class T:
        id = 1

        def __init__(self):
            self.user_id = owner.id
            self.tenant_id = None

        @property
        def visibility(self):
            return state["vis"]

    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: T())
    monkeypatch.setattr(views.db, "set_task_visibility",
                        lambda tid, vis: state.__setitem__("vis", vis), raising=False)

    c = APIClient()
    c.force_authenticate(user=owner)
    r = c.patch("/apiv2/tasks/visibility/1/", {"visibility": "tenant"}, format="json")
    assert r.status_code == 400 and r.json().get("error") is True
    assert state["vis"] == "private"  # unchanged — set_task_visibility never invoked with tenant

    # sanity: the owner can still set public/private on their tenantless task
    r = c.patch("/apiv2/tasks/visibility/1/", {"visibility": "public"}, format="json")
    assert r.status_code == 200, r.content
    assert state["vis"] == "public"


@pytest.mark.django_db
def test_toggle_visibility_rejected_when_mt_disabled(cape_db, monkeypatch):
    """Visibility is an MT feature: with MT disabled the toggle endpoint must reject
    (400) and never write — with MT off every principal is is_local_admin, so
    can_toggle would otherwise authorize a write whose value could become a backfill
    landmine (hide/expose legacy analyses) if MT is later enabled."""
    from rest_framework.test import APIClient
    import apiv2.views as views
    import users.tenancy as ut
    from lib.cuckoo.common.tenancy import MTConfig

    # force MT OFF deterministically (the facade delegates to users.tenancy)
    monkeypatch.setattr(ut, "multitenancy_config", lambda: MTConfig(False, "shared", "", True))

    wrote = {"set": False}
    monkeypatch.setattr(views.db, "set_task_visibility",
                        lambda *a, **k: wrote.__setitem__("set", True), raising=False)

    class T:
        id = 1
        user_id = 1
        tenant_id = None
        visibility = "public"

    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: T())

    u = User.objects.create_user("mtoff", "mtoff@x.com", "x")
    c = APIClient()
    c.force_authenticate(user=u)
    r = c.patch("/apiv2/tasks/visibility/1/", {"visibility": "private"}, format="json")
    assert r.status_code == 400 and r.json().get("error") is True
    assert wrote["set"] is False  # never wrote SQL/mongo while MT off


# ---------------------------------------------------------------------------
# Finding (1): ext_tasks_search — the batch record filter must NOT drop records
# whose info.id has no live SQL Task row when MT is off / break-glass. A
# non-admin (MT on) still drops rows outside the visible set.
# ---------------------------------------------------------------------------


class _Viewer:
    def __init__(self, is_local_admin):
        self.is_local_admin = is_local_admin


class _RowTask:
    def __init__(self, tid):
        self.id = tid


def _run_ext_search_filter(monkeypatch, viewer, mongo_records, visible_ids):
    """Drive ext_tasks_search's post-perform_search record loop in isolation:
    stub apiconf (enabled), perform_search (returns mongo_records), viewer_for,
    the SQL visibility query (list_tasks -> rows with visible_ids), and force the
    mongo (not ES) branch. Returns the resp['data'] list the view would emit."""
    import apiv2.views as views
    from rest_framework.test import APIClient

    # enabled endpoint + valid term/value so we reach the records branch
    monkeypatch.setattr(views.apiconf, "extendedtasksearch",
                        {"enabled": True}, raising=False)
    monkeypatch.setattr(views, "es_as_db", False, raising=False)

    class _Mongo:
        enabled = True

    class _RepConf:
        mongodb = _Mongo()

    monkeypatch.setattr(views, "repconf", _RepConf(), raising=False)
    monkeypatch.setattr(views, "viewer_for", lambda user: viewer, raising=False)
    monkeypatch.setattr(views, "perform_search",
                        lambda *a, **k: mongo_records, raising=False)
    # SQL visibility resolution — only the "visible" ids come back as rows
    monkeypatch.setattr(
        views.db, "list_tasks",
        lambda *a, **k: [_RowTask(t) for t in visible_ids], raising=False,
    )
    # "malscore" is a valid term that skips the tags/options/ids preamble
    c = APIClient()
    u = User.objects.create_user("extsearch", "extsearch@x.com", "x")
    c.force_authenticate(user=u)
    r = c.post("/apiv2/tasks/extendedsearch/",
               {"option": "malscore", "argument": "5"}, format="json")
    assert r.status_code == 200, r.content
    return r.json()


@pytest.mark.django_db
def test_ext_search_mt_off_keeps_records_without_sql_row(cape_db, monkeypatch):
    """MT off / break-glass (is_local_admin): every record is returned even when
    NO record's info.id maps to a live SQL Task row (list_tasks -> []). This is
    the upstream default-install behavior; the new MT drop must be a no-op."""
    records = [{"info": {"id": 111}}, {"info": {"id": 222}}]
    out = _run_ext_search_filter(monkeypatch, _Viewer(True), records, visible_ids=[])
    assert out.get("error") is False
    assert out["data"] == records  # nothing dropped despite empty SQL visible set


@pytest.mark.django_db
def test_ext_search_mt_on_drops_invisible_records(cape_db, monkeypatch):
    """MT on, non-admin viewer: records whose info.id is not in the caller's
    visible set are dropped; visible ones are kept."""
    records = [{"info": {"id": 111}}, {"info": {"id": 222}}]
    out = _run_ext_search_filter(monkeypatch, _Viewer(False), records, visible_ids=[111])
    assert out.get("error") is False
    assert out["data"] == [{"info": {"id": 111}}]  # 222 not visible -> dropped


# ---------------------------------------------------------------------------
# Finding (2): task_x_hours — MT off must reproduce upstream's reversed-bounds
# (always-empty) query verbatim; only MT on uses the corrected 24h window.
# ---------------------------------------------------------------------------


# NOTE on task_x_hours + `datetime`: the view uses `datetime.datetime.now()`,
# but apiv2/views.py imports only `from datetime import datetime` (a pre-existing
# quirk carried verbatim from upstream base into BOTH the MT-off and MT-on
# branches). To exercise the BEHAVIORAL difference between the two branches
# (reversed-bounds + (date, samples) tuple-unpack for MT-off vs corrected-bounds
# + per-Task can_view count for MT-on) without tripping that name resolution, the
# tests inject a shim exposing `.datetime`/`.timedelta` and capture the between()
# bounds so we can assert which query the branch built.


class _FakeQuery:
    def __init__(self, recorder, rows):
        self._recorder = recorder
        self._rows = rows

    def filter(self, criterion):
        return self

    def all(self):
        return self._rows


class _FakeSession:
    def __init__(self, recorder, rows):
        self._recorder = recorder
        self._rows = rows

    def query(self, *a, **k):
        return _FakeQuery(self._recorder, self._rows)

    def close(self):
        self._recorder["closed"] = True


def _install_datetime_shim(monkeypatch, views, recorder):
    """Capture the Task.added_on.between() bounds order so tests can prove reversed
    (MT-off/upstream) vs corrected (MT-on). Uses the REAL datetime (NO shim): the
    view must call the imported names datetime.now()/timedelta() directly — a
    regression to the datetime.datetime.now() typo would raise here (module imports
    `from datetime import datetime`), instead of being masked by a fake module."""
    class _Col:
        def between(self, lo, hi):
            recorder["bounds"] = (lo, hi)
            return object()  # opaque criterion

    monkeypatch.setattr(views.Task, "added_on", _Col(), raising=False)


@pytest.mark.django_db
def test_task_x_hours_mt_off_uses_reversed_bounds_and_tuple_unpack(cape_db, monkeypatch, mt_disabled):
    """MT disabled => upstream verbatim: reversed between(now, now-1day) bounds
    AND `for date, samples in res` tuple-unpack. Feed (date, count) 2-tuples so
    the upstream unpack succeeds and the result matches upstream's shape; assert
    the bounds are REVERSED (lo > hi) — i.e. NOT the corrected MT-on window."""
    import datetime as _dt
    import apiv2.views as views
    from rest_framework.test import APIClient

    rec = {}
    _install_datetime_shim(monkeypatch, views, rec)
    d1 = _dt.datetime(2026, 1, 1, 12, 0, 0)
    # upstream shape: rows are (date, samples) tuples
    monkeypatch.setattr(views.db, "Session",
                        lambda *a, **k: _FakeSession(rec, [(d1, 3)]), raising=False)

    u = User.objects.create_user("txh_off", "txh_off@x.com", "x")
    c = APIClient()
    c.force_authenticate(user=u)
    r = c.get("/apiv2/tasks/stats/")
    assert r.status_code == 200, r.content
    body = r.json()
    assert body["error"] is False
    # upstream setdefault(date, samples) -> the raw `samples` value, NOT a count
    assert list(body["stats"].values()) == [3]
    # reversed bounds (upstream bug preserved): lo (now) > hi (now - 1 day)
    lo, hi = rec["bounds"]
    assert lo > hi
    assert rec.get("closed") is True


@pytest.mark.django_db
def test_task_x_hours_mt_off_tuple_unpack_rejects_plain_task(cape_db, monkeypatch, mt_disabled):
    """Extra proof the MT-off branch is upstream verbatim: it unpacks each row as
    `for date, samples in res`. A single Task object (the MT-on row shape) is not
    a 2-tuple, so the upstream unpack raises -> 500. This distinguishes the branch
    from the new per-Task count loop."""
    import apiv2.views as views
    from rest_framework.test import APIClient

    rec = {}
    _install_datetime_shim(monkeypatch, views, rec)

    class _NotATuple:
        added_on = None  # single object, NOT iterable into (date, samples)

    monkeypatch.setattr(views.db, "Session",
                        lambda *a, **k: _FakeSession(rec, [_NotATuple()]), raising=False)

    u = User.objects.create_user("txh_off2", "txh_off2@x.com", "x")
    # raise_request_exception=False so the unhandled unpack TypeError surfaces as a
    # 500 response instead of the test client re-raising it.
    c = APIClient(raise_request_exception=False)
    c.force_authenticate(user=u)
    r = c.get("/apiv2/tasks/stats/")
    assert r.status_code == 500


@pytest.mark.django_db
def test_task_x_hours_mt_on_corrected_bounds_and_visibility_count(cape_db, monkeypatch, mt_enabled):
    """MT enabled => corrected 24h window (lo < hi) AND the new Python path that
    iterates single Task objects, counting one per bucket, filtered by
    can_view_task. Invisible tasks are skipped."""
    import datetime as _dt
    import apiv2.views as views
    from rest_framework.test import APIClient

    rec = {}
    _install_datetime_shim(monkeypatch, views, rec)

    class _T:
        def __init__(self, tid, view):
            self.id = tid
            self._view = view
            self.added_on = _dt.datetime(2026, 1, 1, 12, 0, 0)

    rows = [_T(1, True), _T(2, False), _T(3, True)]
    monkeypatch.setattr(views.db, "Session",
                        lambda *a, **k: _FakeSession(rec, rows), raising=False)
    monkeypatch.setattr(views, "can_view_task",
                        lambda user, t: t._view, raising=False)

    u = User.objects.create_user("txh_on", "txh_on@x.com", "x")
    c = APIClient()
    c.force_authenticate(user=u)
    r = c.get("/apiv2/tasks/stats/")
    assert r.status_code == 200, r.content
    body = r.json()
    assert body["error"] is False
    # 2 visible tasks in the same minute bucket -> count 2 (invisible skipped).
    assert sum(body["stats"].values()) == 2
    # corrected bounds (MT-on): lo (now - 1 day) < hi (now)
    lo, hi = rec["bounds"]
    assert lo < hi


# ---------------------------------------------------------------------------
# Finding (3): _strip_mt_task_fields — Task.to_dict() now carries tenant_id +
# visibility. MT off => strip (upstream-identical output). MT on => preserved.
# ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_strip_mt_task_fields_mt_off_removes_keys(monkeypatch, mt_disabled):
    import apiv2.views as views
    d = {"id": 1, "target": "x", "tenant_id": 7, "visibility": "private"}
    out = views._strip_mt_task_fields(d)
    assert "tenant_id" not in out
    assert "visibility" not in out
    assert out["id"] == 1 and out["target"] == "x"


@pytest.mark.django_db
def test_strip_mt_task_fields_mt_on_preserves_keys(monkeypatch, mt_enabled):
    import apiv2.views as views
    d = {"id": 1, "target": "x", "tenant_id": 7, "visibility": "private"}
    out = views._strip_mt_task_fields(d)
    assert out["tenant_id"] == 7
    assert out["visibility"] == "private"


@pytest.mark.django_db
def test_strip_mt_sample_fields_drops_source_url_when_mt_on(mt_enabled):
    """The global (hash-deduped, ownerless) samples row's source_url is the FIRST
    registrant's provenance -> strip it from hash-addressed / embedded sample responses
    under MT so it can't leak to a tenant that later submits the same file."""
    import apiv2.views as views
    d = {"id": 1, "sha256": "a" * 64, "source_url": "https://intranet.bcorp/loader.bin"}
    out = views._strip_mt_sample_fields(dict(d))
    assert "source_url" not in out           # cross-tenant provenance stripped
    assert out["sha256"] == "a" * 64          # intrinsic file fields kept


def test_strip_mt_sample_fields_keeps_source_url_when_mt_off(monkeypatch):
    """MT off (single-tenant): no cross-tenant concern -> upstream output verbatim."""
    import apiv2.views as views
    _force_mt_off(monkeypatch)
    d = {"id": 1, "source_url": "https://x"}
    assert views._strip_mt_sample_fields(dict(d))["source_url"] == "https://x"


@pytest.mark.django_db
def test_tasks_view_response_strips_mt_keys_when_off(cape_db, monkeypatch, mt_disabled):
    """End-to-end: tasks_view must not leak tenant_id/visibility on a default
    (MT-off) install; with MT on it does."""
    from rest_framework.test import APIClient
    import apiv2.views as views

    class _Task:
        def __init__(self):
            self.id = 1
            self.category = "file"
            self.guest = None
            self.sample_id = None
            self.errors = []
            self.status = "reported"
            self.custom = None

        def to_dict(self):
            return {
                "id": 1,
                "category": "file",
                "target": "/tmp/a.bin",
                "status": "reported",
                "tenant_id": 5,
                "visibility": "private",
            }

    monkeypatch.setattr(views.apiconf, "taskview", {"enabled": True}, raising=False)
    monkeypatch.setattr(views.db, "view_task", lambda *a, **k: _Task(), raising=False)

    class _Mongo:
        enabled = False

    class _RepConf:
        mongodb = _Mongo()

    monkeypatch.setattr(views, "repconf", _RepConf(), raising=False)
    monkeypatch.setattr(views, "es_as_db", False, raising=False)

    u = User.objects.create_user("tv_off", "tv_off@x.com", "x")
    c = APIClient()
    c.force_authenticate(user=u)
    r = c.get("/apiv2/tasks/view/1/")
    assert r.status_code == 200, r.content
    data = r.json()["data"]
    assert "tenant_id" not in data
    assert "visibility" not in data
