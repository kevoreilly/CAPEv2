import ast
import re

import pytest
from django.contrib.auth.models import User

# A view "enforces visibility" if its source references any of these — a read
# guard, the artifact preamble, the list filter, the web decorator, or a
# management guard (for mutation endpoints).
GUARD_MARKERS = (
    "_deny_if_hidden", "_deny_task", "_deny_manage", "_resolve_task_id", "visible_to",
    "require_task_visibility", "require_task_manage", "can_view_task", "can_manage_task",
    "can_toggle_task",
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
    the routed gates can't see it. It must re-check task visibility (defense in
    depth behind the mint-time gate)."""
    import guac.consumers

    src = open(guac.consumers.__file__).read()
    assert "can_view_task" in src, \
        "guac websocket consumer must re-check task visibility (can_view_task) — defense-in-depth for the live-VM tunnel"


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


@pytest.mark.django_db
def test_deny_if_hidden_missing_task():
    import apiv2.views as views
    other = User.objects.create_user("b", "b@x.com", "x")
    assert views._deny_if_hidden(FakeReq(other), None) is not None  # not found


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
    from rest_framework.test import APIRequestFactory, force_authenticate
    import apiv2.views as views

    deleted = []
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
    "apiv2.views:tasks_rollingsuri": "mongo_find then per-row can_view_task (+ is_local_admin fast-path)",
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
