"""Production wiring of lib.tenancy: exercised as Django builds it, not with injected resolvers."""

import types

import pytest

import lib.tenancy.policy as policy
from lib.tenancy.acl import ensure_acl_schema, set_task_acl
from lib.tenancy.middleware import TenancyMiddleware
from lib.tenancy.policy import PRIVATE, ViewerContext


def _status(resp):
    if resp is None:
        return None
    if isinstance(resp, dict):
        return resp.get("status_code")
    return resp.status_code


def _viewer(user_id, tenant_id):
    return ViewerContext(
        user_id=user_id,
        tenant_id=tenant_id,
        is_superuser=False,
        is_tenant_admin=False,
        is_local_admin=False,
        is_authenticated=True,
        tenant_ids=(tenant_id,),
        admin_tenant_ids=(),
    )


@pytest.fixture(autouse=True)
def _clear_tenancy_context():
    # Tests call process_view directly, without __call__'s per-request reset.
    from lib.tenancy.context import set_current_entitlements, set_current_viewer

    yield
    set_current_viewer(None)
    set_current_entitlements(None)


@pytest.fixture
def mt_enabled(monkeypatch):
    real = policy.multitenancy_config

    class _Cfg:
        enabled = True

        def __getattr__(self, name):
            return getattr(real(), name)

    monkeypatch.setattr(policy, "multitenancy_config", lambda: _Cfg())


@pytest.fixture
def private_task(db, temp_pe32, mt_enabled):
    """A task owned by user 7 in tenant 1, visibility private."""
    task_id = db.add_path(str(temp_pe32), user_id=7)
    ensure_acl_schema(db.engine)
    with db.session.begin():
        set_task_acl(db.session, task_id, user_id=7, tenant_id=1, visibility=PRIVATE)
    sha256 = db.view_task(task_id).sample.sha256
    return task_id, sha256


def _mw(viewer):
    # Constructed exactly as Django does for a MIDDLEWARE entry: get_response only,
    # plus a fixed viewer so the test does not depend on auth plumbing.
    return TenancyMiddleware(lambda request: None, viewer_resolver=lambda user: viewer)


def _req(path):
    return types.SimpleNamespace(path=path, method="GET", user=object(), viewer=None, entitlements=None)


def _view():
    pass


def test_middleware_built_by_django_has_production_resolvers():
    mw = TenancyMiddleware(lambda request: None)
    assert mw.task_scope_resolver is not None
    assert mw.sample_access_checker is not None


@pytest.mark.parametrize(
    "path,kwargs_for",
    [
        ("/apiv2/tasks/get/pcap/{tid}/", lambda tid, h: {"task_id": tid}),
        ("/full_memory/{tid}/", lambda tid, h: {"analysis_number": str(tid)}),
        ("/compare/1/{tid}/", lambda tid, h: {"left_id": tid, "right_id": tid}),
        ("/apiv2/files/get/task/{tid}/", lambda tid, h: {"stype": "task", "value": str(tid)}),
        ("/apiv2/files/get/sha256/{h}/", lambda tid, h: {"stype": "sha256", "value": h}),
        ("/submit/resubmit/{tid}/{h}/", lambda tid, h: {"resubmit_hash": h}),
    ],
)
def test_foreign_tenant_is_denied_and_owner_is_allowed(private_task, path, kwargs_for):
    task_id, sha256 = private_task
    kwargs = kwargs_for(task_id, sha256)
    url = path.format(tid=task_id, h=sha256)

    outsider = _mw(_viewer(user_id=8, tenant_id=2))
    assert _status(outsider.process_view(_req(url), _view, (), dict(kwargs))) == 404

    owner = _mw(_viewer(user_id=7, tenant_id=1))
    assert owner.process_view(_req(url), _view, (), dict(kwargs)) is None


def test_unresolvable_scope_fails_closed(private_task):
    def boom(task_id):
        raise RuntimeError("db down")

    task_id, _ = private_task
    mw = TenancyMiddleware(lambda request: None, viewer_resolver=lambda user: _viewer(7, 1), task_scope_resolver=boom)
    assert _status(mw.process_view(_req(f"/analysis/{task_id}/"), _view, (), {"task_id": task_id})) == 404


def test_registered_route_filter_accepts_the_core_hook_call():
    # lib.cuckoo.common.hooks.apply_route_filter calls each filter as fn(routes, route_type).
    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy.hooks import register_core_hooks

    register_core_hooks()
    try:
        assert core_hooks.apply_route_filter(["inetsim", "tor"], "exit") == ["inetsim", "tor"]
    finally:
        core_hooks.clear_all_hooks()


def _cfg(**sections):
    return types.SimpleNamespace(**{name: {"enabled": on} for name, on in sections.items()})


def _broken_hooks(monkeypatch):
    import lib.tenancy.hooks as tenancy_hooks

    def boom():
        raise ImportError("optional dependency missing")

    monkeypatch.setattr(tenancy_hooks, "register_core_hooks", boom)


def test_bootstrap_fails_closed_when_multitenancy_is_enabled(monkeypatch):
    from lib.cuckoo.common.hooks import bootstrap_tenancy

    _broken_hooks(monkeypatch)
    with pytest.raises(RuntimeError, match="multitenancy"):
        bootstrap_tenancy(_cfg(multitenancy=True))


def test_bootstrap_storage_only_failure_is_logged_not_raised(monkeypatch):
    from lib.cuckoo.common.hooks import bootstrap_tenancy

    _broken_hooks(monkeypatch)
    assert bootstrap_tenancy(_cfg(object_storage=True)) is False


def test_bootstrap_activates_for_legacy_central_mode(monkeypatch):
    import lib.tenancy.hooks as tenancy_hooks
    from lib.cuckoo.common.hooks import bootstrap_tenancy

    calls = []
    monkeypatch.setattr(tenancy_hooks, "register_core_hooks", lambda: calls.append(1))
    assert bootstrap_tenancy(_cfg(central_mode=True)) is True
    assert calls == [1]
    assert bootstrap_tenancy(_cfg(multitenancy=False, object_storage=False)) is False


def test_hash_search_pipeline_applies_the_registered_analysis_filter(monkeypatch):
    # Hash searches aggregate over `files` and join into `analysis`; the joined analysis
    # documents must be scoped like any other analysis query.
    import lib.cuckoo.common.web_utils as web_utils
    from lib.cuckoo.common import hooks as core_hooks

    scope = {"info.tenant_id": 20}
    seen = []
    monkeypatch.setattr(web_utils.repconf.mongodb, "enabled", True, raising=False)
    monkeypatch.setattr(web_utils, "mongo_aggregate", lambda coll, pipeline, *a, **k: seen.append((coll, pipeline)) or [], raising=False)
    core_hooks.register_mongo_filter(lambda collection, query: {**query, **scope} if collection == "analysis" else query)
    try:
        web_utils.perform_search("sha256", "a" * 64, privs=True)
    finally:
        core_hooks.clear_all_hooks()

    coll, pipeline = seen[0]
    assert coll == "files"
    root = next(i for i, stage in enumerate(pipeline) if "$replaceRoot" in stage)
    assert {"$match": scope} in pipeline[root + 1 :]


def test_guac_console_requires_manage_rights(private_task, monkeypatch):
    # A tenant member who may read a tenant-visible task must not get its live VM console.
    from lib.tenancy.policy import TENANT

    task_id, _ = private_task
    import lib.tenancy.middleware as mw_mod
    from lib.tenancy.policy import ResourceScope

    monkeypatch.setattr(mw_mod, "default_task_scope_resolver", lambda tid: ResourceScope(owner_id=7, tenant_id=1, visibility=TENANT))
    member = _mw(_viewer(user_id=9, tenant_id=1))

    def index():
        pass

    assert member.process_view(_req(f"/analysis/{task_id}/"), _view, (), {"task_id": task_id}) is None
    assert _status(member.process_view(_req(f"/guac/{task_id}/xyz/"), index, (), {"task_id": task_id, "session_data": "xyz"})) == 404


def test_direct_vnc_views_are_admin_only():
    def direct_vnc_host_port():
        pass

    tenant_user = _mw(_viewer(user_id=9, tenant_id=1))
    assert _status(tenant_user.process_view(_req("/guac/vnc/10.0.0.1/5900/"), direct_vnc_host_port, (), {"host": "10.0.0.1", "port": "5900"})) == 403


def test_guac_vm_target_comes_from_the_task_not_the_url(db, temp_pe32, monkeypatch):
    import guac.views as guac_views

    task_id = db.add_path(str(temp_pe32))
    monkeypatch.setattr(guac_views, "db", db)
    with db.session.begin():
        db.view_task(task_id).machine = "win10-1"
    monkeypatch.setattr(db, "view_machine_by_label", lambda label: types.SimpleNamespace(ip="192.168.122.10") if label == "win10-1" else None)
    assert guac_views._vm_target_for_task(task_id) == ("win10-1", "192.168.122.10")


def _post_req(path, **post):
    req = _req(path)
    req.method = "POST"
    req.POST = post
    return req


def test_body_task_ids_are_gated(private_task):
    # The real view is DRF-decorated: @api_view renames the callable to "view".
    import json

    from rest_framework.decorators import api_view

    task_id, _ = private_task

    @api_view(["POST"])
    def tasks_delete_many(request):
        pass

    assert tasks_delete_many.__name__ == "view"

    req = lambda: _post_req("/apiv2/tasks/delete_many/", ids=f"{task_id}")  # noqa: E731
    assert _status(_mw(_viewer(8, 2)).process_view(req(), tasks_delete_many, (), {})) == 404
    assert _mw(_viewer(7, 1)).process_view(req(), tasks_delete_many, (), {}) is None

    def json_req(ids):
        r = _post_req("/apiv2/tasks/delete_many/")
        r.body = json.dumps({"ids": ids}).encode()  # DRF's JSONParser never fills request.POST
        return r

    for ids in (f"{task_id}", [task_id]):
        assert _status(_mw(_viewer(8, 2)).process_view(json_req(ids), tasks_delete_many, (), {})) == 404
        assert _mw(_viewer(7, 1)).process_view(json_req(ids), tasks_delete_many, (), {}) is None


@pytest.mark.parametrize("view_name, extra", [("file", {}), ("vtupload", {"filename": "x.exe"})])
@pytest.mark.parametrize("category", ["sample", "static", "staticzip"])
def test_stored_binary_routes_check_the_sample_not_just_the_route_task(db, private_task, view_name, extra, category):
    # file/<category>/<task_id>/<dlfile>/ and vtupload/... serve storage/binaries/<dlfile> whatever
    # the task id: gating only the caller's own task handed out (or uploaded to VT) any sample.
    task_id, sha256 = private_task
    other_task = db.add_url("http://example.com/", user_id=8)
    with db.session.begin():
        set_task_acl(db.session, other_task, user_id=8, tenant_id=2, visibility=PRIVATE)
    view = types.FunctionType(_view.__code__, {}, view_name)

    def kwargs(tid, dlfile):
        return {"category": category, "task_id": str(tid), "dlfile": dlfile, **extra}

    outsider, owner = _mw(_viewer(8, 2)), _mw(_viewer(7, 1))
    assert _status(outsider.process_view(_req("/file/x/"), view, (), kwargs(other_task, sha256))) == 404
    assert _status(outsider.process_view(_req("/file/x/"), view, (), kwargs(other_task, "notahash"))) == 404
    assert owner.process_view(_req("/file/x/"), view, (), kwargs(task_id, sha256)) is None
    # Other categories name files inside the route task's own directory.
    dropped = {**kwargs(other_task, sha256), "category": "dropped"}
    assert outsider.process_view(_req("/file/x/"), view, (), dropped) is None


def test_hunt_tag_body_task_ids_are_gated_as_a_task_change(private_task):
    import json

    task_id, _ = private_task

    def tag_tasks(request):
        pass

    def req():
        r = _req("/analysis/hunt/tag/")
        r.method, r.POST = "POST", {}
        r.body = json.dumps({"task_ids": [task_id], "tag": "x"}).encode()
        return r

    assert _status(_mw(_viewer(8, 2)).process_view(req(), tag_tasks, (), {})) == 404
    assert _mw(_viewer(7, 1)).process_view(req(), tag_tasks, (), {}) is None
    malformed = req()
    malformed.body = b"{nope"
    assert _mw(_viewer(8, 2)).process_view(malformed, tag_tasks, (), {}) is None  # the view answers 400


def test_central_storage_dispatch_matches_drf_wrapped_views(monkeypatch):
    # analysis.views.file / file_nl are @api_view: their __name__ is "view", so matching on it
    # never routed them to the object-storage handlers (and their sample/task binding check).
    from rest_framework.decorators import api_view

    from lib.tenancy import views as tviews
    from lib.tenancy.storage import config as storage_cfg
    from lib.tenancy.storage import views as storage_views

    monkeypatch.setattr(storage_cfg, "central_mode_config", lambda: types.SimpleNamespace(enabled=True))
    monkeypatch.setattr(storage_views, "central_file", lambda *a, **k: "CENTRAL")

    @api_view(["GET"])
    def file(request, category, task_id, dlfile):
        pass

    kw = {"category": "sample", "task_id": "5", "dlfile": "a" * 64}
    assert tviews.dispatch_object_storage_view(types.SimpleNamespace(path="/file/x/", user=None), file, (), kw) == "CENTRAL"


def test_task_id_lists_and_ranges_are_checked_per_task(private_task):
    task_id, _ = private_task

    def tasks_delete():
        pass

    for raw in (f"{task_id}-{task_id}", f"{task_id},{task_id}"):
        assert _status(_mw(_viewer(8, 2)).process_view(_req("/apiv2/tasks/delete/x/"), tasks_delete, (), {"task_id": raw})) == 404
        assert _mw(_viewer(7, 1)).process_view(_req("/apiv2/tasks/delete/x/"), tasks_delete, (), {"task_id": raw}) is None
    huge = f"1-{10**9}"
    assert _status(_mw(_viewer(7, 1)).process_view(_req("/apiv2/tasks/delete/x/"), tasks_delete, (), {"task_id": huge})) == 404


def test_task_scoped_file_hash_is_not_checked_as_a_sample(private_task):
    # on_demand/<service>/<task_id>/<category>/<sha256>: the hash names a dropped file of the task.
    task_id, _ = private_task

    def on_demand():
        pass

    kwargs = {"service": "bingraph", "task_id": task_id, "category": "dropped", "sha256": "b" * 64}
    assert _mw(_viewer(7, 1)).process_view(_req(f"/analysis/on_demand/x/{task_id}/"), on_demand, (), dict(kwargs)) is None


def test_hash_search_limits_after_scoping(monkeypatch):
    import lib.cuckoo.common.web_utils as web_utils
    from lib.cuckoo.common import hooks as core_hooks

    seen = []
    monkeypatch.setattr(web_utils.repconf.mongodb, "enabled", True, raising=False)
    monkeypatch.setattr(web_utils, "mongo_aggregate", lambda coll, pipeline, *a, **k: seen.append(pipeline) or [], raising=False)
    core_hooks.register_mongo_filter(lambda collection, query: {**query, "info.tenant_id": 20} if collection == "analysis" else query)
    try:
        web_utils.perform_search("sha256", "a" * 64, search_limit=5, privs=True)
    finally:
        core_hooks.clear_all_hooks()
    stages = [next(iter(stage)) for stage in seen[0]]
    assert stages.count("$limit") == 1
    assert stages.index("$limit") > stages.index("$replaceRoot")


class _User:
    def __init__(self, uid):
        self.id = uid
        self.is_authenticated = uid is not None


def _viewer_for_user(user):
    if getattr(user, "is_authenticated", False):
        return _viewer(user.id, {7: 1, 8: 2}.get(user.id))
    return ViewerContext.anonymous()


def _identity_mw():
    return TenancyMiddleware(lambda request: None, viewer_resolver=_viewer_for_user)


def _anon_req(path):
    # A real HttpRequest: DRF's Request() refuses anything else.
    from django.test import RequestFactory

    req = RequestFactory().get(path)
    req.user = _User(None)
    return req


def test_api_key_callers_are_scoped_as_themselves(private_task):
    # DRF authenticates inside the view, after middleware: the owner's API key must not be
    # treated as anonymous (denied) and must not be skipped either.
    from rest_framework.authentication import BaseAuthentication
    from rest_framework.decorators import api_view, authentication_classes

    task_id, _ = private_task

    def key_auth_as(uid):
        class KeyAuth(BaseAuthentication):
            def authenticate(self, request):
                return (_User(uid), None)

        return KeyAuth

    for uid, expected in ((7, None), (8, 404)):

        @api_view(["GET"])
        @authentication_classes([key_auth_as(uid)])
        def tasks_view(request, task_id):
            pass

        got = _identity_mw().process_view(_anon_req(f"/apiv2/tasks/view/{task_id}/"), tasks_view, (), {"task_id": task_id})
        assert _status(got) == expected


def test_settings_user_resolver_is_used_for_late_identity(private_task, settings, monkeypatch):
    # guac-web resolves session users itself (OIDC backends are not loaded there).
    import sys

    task_id, _ = private_task
    mod = types.ModuleType("_tenancy_test_resolver")
    mod.resolve = lambda request: _User(7)
    monkeypatch.setitem(sys.modules, "_tenancy_test_resolver", mod)
    settings.TENANCY_REQUEST_USER_RESOLVER = "_tenancy_test_resolver.resolve"

    def index(request, task_id, session_data):
        pass

    req = _anon_req(f"/guac/{task_id}/xyz/")
    assert _identity_mw().process_view(req, index, (), {"task_id": task_id, "session_data": "xyz"}) is None


def test_untyped_hash_is_checked_even_on_task_routes(private_task, db, temp_pe64):
    # compare/<own task>/<other tenant's sample hash>: the left task is readable, the hash is not.
    _, victim_sha256 = private_task
    own_task = db.add_path(str(temp_pe64), user_id=8)

    def hash(request, left_id, right_hash):  # noqa: A001 - mirrors compare.views.hash
        pass

    kwargs = {"left_id": own_task, "right_hash": victim_sha256}
    assert _status(_mw(_viewer(8, 2)).process_view(_req(f"/compare/{own_task}/{victim_sha256}/"), hash, (), kwargs)) == 404


def test_compare_checks_the_right_task_too(private_task, db, temp_pe64):
    victim_task, _ = private_task
    own_task = db.add_path(str(temp_pe64), user_id=8)

    def compare_left_right(request, left_id, right_id):
        pass

    kwargs = {"left_id": own_task, "right_id": victim_task}
    path = f"/compare/{own_task}/{victim_task}/"
    assert _status(_mw(_viewer(8, 2)).process_view(_req(path), compare_left_right, (), kwargs)) == 404


def test_remote_session_is_a_task_action_not_a_read():
    from lib.tenancy.middleware import classify_view_action

    def remote_session(request, task_id):
        pass

    assert classify_view_action("/analysis/remote_session/5/", remote_session) == "manage"


def test_sample_access_fails_closed_when_the_checker_raises(private_task):
    _, sha256 = private_task

    def boom(viewer, flt):
        raise RuntimeError("db down")

    mw = TenancyMiddleware(lambda request: None, viewer_resolver=lambda user: _viewer(7, 1), sample_access_checker=boom)
    got = mw.process_view(_req(f"/apiv2/files/get/sha256/{sha256}/"), _view, (), {"stype": "sha256", "value": sha256})
    assert _status(got) == 404


def test_guac_web_bootstraps_tenancy():
    # guac-web is its own ASGI process on web.guac_settings; without this it had no TenancyMiddleware.
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1] / "web" / "web" / "guac_settings.py").read_text()
    assert 'bootstrap_tenancy(_CapeConfig("cuckoo"), settings_globals=globals())' in src
    assert "TENANCY_REQUEST_USER_RESOLVER" in src


def test_guac_console_targets_the_tasks_vm_whatever_the_session_data_says(db, temp_pe32, monkeypatch):
    import base64

    import guac.views as guac_views

    task_id = db.add_path(str(temp_pe32))
    with db.session.begin():
        db.view_task(task_id).machine = "win10-1"
    monkeypatch.setattr(guac_views, "db", db)
    monkeypatch.setattr(db, "view_machine_by_label", lambda label: types.SimpleNamespace(ip="192.168.122.10") if label == "win10-1" else None)
    looked_up, sessions = [], []
    dom = types.SimpleNamespace(state=lambda flags=0: [1])
    conn = types.SimpleNamespace(lookupByName=lambda name: looked_up.append(name) or dom, close=lambda: None)
    monkeypatch.setattr(guac_views, "LIBVIRT_AVAILABLE", True)
    monkeypatch.setattr(guac_views, "libvirt", types.SimpleNamespace(open=lambda dsn: conn), raising=False)
    monkeypatch.setattr(guac_views, "machinery", "kvm")
    monkeypatch.setattr(db, "create_guac_session", lambda **kw: sessions.append(kw) or types.SimpleNamespace(**kw))
    monkeypatch.setattr(guac_views, "render", lambda request, tpl, ctx=None: types.SimpleNamespace(set_cookie=lambda *a, **k: None))
    forged = base64.urlsafe_b64encode(b"sid|other-tenant-vm|10.9.9.9").decode()
    req = types.SimpleNamespace(
        user=types.SimpleNamespace(is_authenticated=True), method="GET", path="/guac/", is_secure=lambda: False
    )
    guac_views.index(req, task_id, forged)
    assert looked_up == ["win10-1"]
    assert [(s["vm_label"], s["guest_ip"]) for s in sessions] == [("win10-1", "192.168.122.10")]


def test_late_identity_does_not_outlive_the_request(private_task):
    from rest_framework.authentication import BaseAuthentication
    from rest_framework.decorators import api_view, authentication_classes

    from lib.tenancy.context import get_current_viewer

    task_id, _ = private_task

    class KeyAuth(BaseAuthentication):
        def authenticate(self, request):
            return (_User(7), None)

    @api_view(["GET"])
    @authentication_classes([KeyAuth])
    def tasks_view(request, task_id):
        pass

    mw = _identity_mw()
    req = _anon_req(f"/apiv2/tasks/view/{task_id}/")
    seen = []

    def get_response(request):
        mw.process_view(request, tasks_view, (), {"task_id": task_id})
        seen.append(get_current_viewer())  # what the view's list/search filters will scope by

    mw.get_response = get_response
    mw(req)
    assert [getattr(v, "user_id", None) for v in seen] == [7]
    assert get_current_viewer() is None


def test_bootstrap_imports_nothing_when_disabled():
    import subprocess
    import sys

    code = (
        "import sys, types; from lib.cuckoo.common.hooks import bootstrap_tenancy; "
        "cfg = types.SimpleNamespace(multitenancy={'enabled': False}, object_storage={'enabled': False}); "
        "assert bootstrap_tenancy(cfg) is False; "
        "print(any(m == 'lib.tenancy' or m.startswith('lib.tenancy.') for m in sys.modules))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip().splitlines()[-1] == "False"


def test_fresh_install_without_acl_table_lists_and_authorizes(db, temp_pe32, mt_enabled):
    # task_acl used to appear only on the first submission through the tenancy wrapper.
    import sqlalchemy as sa

    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy.acl import _acl_schema_ready
    from lib.tenancy.context import set_current_viewer
    from lib.tenancy.hooks import register_core_hooks

    def acl_table_exists():
        # Through the session: an Inspector on the in-memory engine would roll the session back.
        return db.session.execute(sa.text("SELECT 1 FROM sqlite_master WHERE name = 'task_acl'")).first() is not None

    task_id = db.add_path(str(temp_pe32), user_id=7)
    _acl_schema_ready.clear()
    assert not acl_table_exists()

    owner = _mw(_viewer(user_id=7, tenant_id=1))
    assert owner.process_view(_req(f"/analysis/{task_id}/"), _view, (), {"task_id": task_id}) is None

    _acl_schema_ready.clear()
    with db.session.begin():
        db.session.execute(sa.text("DROP TABLE task_acl"))
    register_core_hooks()
    set_current_viewer(_viewer(user_id=7, tenant_id=1))
    try:
        assert [t.id for t in db.list_tasks()] == [task_id]
    finally:
        core_hooks.clear_all_hooks()


def test_sso_login_groups_reach_tenancy_group_reconciliation(monkeypatch):
    import lib.tenancy.resources as resources
    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy.hooks import register_core_hooks

    calls = []
    monkeypatch.setattr(resources, "reconcile_idp_groups_to_django_groups", lambda user, groups: calls.append((user, groups)))
    register_core_hooks()
    try:
        core_hooks.run_login_groups_hooks("alice", {"cape-acme"})
    finally:
        core_hooks.clear_all_hooks()
    assert calls == [("alice", {"cape-acme"})]


def test_sso_adapter_no_longer_uses_the_removed_tenant_model():
    import pathlib

    src = (pathlib.Path(__file__).resolve().parents[1] / "web/web/allauth_adapters.py").read_text()
    assert "users.models import Tenant" not in src
    assert "run_login_groups_hooks(user, _extract_groups(extra))" in src


def test_ensure_acl_schema_once_survives_engine_churn_and_races(monkeypatch):
    import sqlalchemy as sa

    import lib.tenancy.acl as acl

    for _ in range(20):
        engine = sa.create_engine("sqlite://")
        acl.ensure_acl_schema_once(engine)
        assert "task_acl" in sa.inspect(engine).get_table_names()
        del engine

    engine = sa.create_engine("sqlite://")
    acl.ensure_acl_schema(engine)  # a concurrent worker created it first

    def lost_race(_engine):
        raise sa.exc.ProgrammingError("CREATE TABLE task_acl", {}, Exception("relation task_acl already exists"))

    monkeypatch.setattr(acl, "ensure_acl_schema", lost_race)
    acl.ensure_acl_schema_once(engine)
    assert engine in acl._acl_schema_ready


def test_tenancy_admin_passes_django_system_checks():
    # GroupSandboxPolicy has two FKs to auth.Group (group, parent_group); without fk_name the
    # inline fails admin.E202, and with [multitenancy] on that blocks manage.py migrate/runserver.
    pytest.importorskip("django")
    import os
    import subprocess
    import sys

    script = """
import django
from django.conf import settings
settings.configure(
    INSTALLED_APPS=[
        "django.contrib.admin",
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "lib.tenancy.apps.CapeTenancyConfig",
    ],
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
    DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
)
django.setup()
import lib.tenancy.admin  # noqa: F401
from django.contrib import admin
errors = [e for e in admin.site.check(None) if e.is_serious()]
assert not errors, errors
"""
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    res = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}"


def test_visibility_toggle_on_task_without_acl_row_keeps_its_owner(monkeypatch):
    # Upgraded and unstamped tasks have no task_acl row; their scope falls back to tasks.user_id.
    # Toggling one must not create an ownerless row (and stamp info.user_id=None into Mongo).
    import sqlalchemy as sa
    from sqlalchemy.orm import Session

    from lib.tenancy.acl import resolve_task_scope
    from lib.tenancy.views import tasks_set_visibility

    monkeypatch.setattr(
        "lib.tenancy.views.multitenancy_config",
        lambda: policy.MTConfig(enabled=True, mode="shared", default_visibility="", local_admins_manage_all_tenants=True),
    )
    engine = sa.create_engine("sqlite://")
    ensure_acl_schema(engine)
    stamps = []

    def scope_loader(tid):
        sess = Session(engine)
        return sess, resolve_task_scope(sess, tid, fallback_user_id=10)

    owner = ViewerContext(user_id=10, tenant_id=None)
    req = types.SimpleNamespace(viewer=owner, data={"visibility": "public"}, method="POST")
    res = tasks_set_visibility(req, 42, scope_loader=scope_loader, mongo_update_one=lambda c, f, u: stamps.append(u))
    assert res.status_code == 200
    with Session(engine) as s:
        assert resolve_task_scope(s, 42).owner_id == 10
    assert stamps[0]["$set"]["info.user_id"] == 10

    req = types.SimpleNamespace(viewer=owner, data={"visibility": "private"}, method="POST")
    res = tasks_set_visibility(req, 42, scope_loader=scope_loader, mongo_update_one=lambda c, f, u: stamps.append(u))
    assert res.status_code == 200  # the owner can still take it back


@pytest.mark.parametrize("chain", ["key+session", "sso", "token_auth_off"])
def test_visibility_endpoint_authenticates_like_the_api(chain):
    # The middleware serves /apiv2/tasks/visibility/ before URL routing, so neither DRF auth (API
    # keys) nor CsrfViewMiddleware ever ran: key holders got 404, session callers skipped CSRF.
    # It must follow the /apiv2/ chain: key first, and no session at all under SSO. With token auth
    # off (the default) the chain is empty and /apiv2/ runs on the session, so CSRF is still required.
    pytest.importorskip("django")
    pytest.importorskip("rest_framework")
    import os
    import subprocess
    import sys

    script = f"CHAIN = {chain!r}\n"
    script += """
import json
import django
from django.conf import settings
settings.configure(
    INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes", "rest_framework"],
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
    DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
    REST_FRAMEWORK={"DEFAULT_AUTHENTICATION_CLASSES": {
        "key+session": ["__main__.HeaderKeyAuth", "rest_framework.authentication.SessionAuthentication"],
        "sso": ["__main__.HeaderKeyAuth"],
        "token_auth_off": [],
    }[CHAIN]},
)
django.setup()
import types
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
import lib.tenancy.views as views
from lib.tenancy.policy import MTConfig, ResourceScope, ViewerContext

class HeaderKeyAuth(BaseAuthentication):
    def authenticate(self, request):
        key = request.META.get("HTTP_AUTHORIZATION")
        if not key:
            return None
        if key != "Token good":
            raise AuthenticationFailed("bad key")
        return (types.SimpleNamespace(id=10, is_authenticated=True, is_superuser=False), None)

views.multitenancy_config = lambda: MTConfig(enabled=True, mode="shared", default_visibility="", local_admins_manage_all_tenants=True)
resolve = lambda u: ViewerContext(user_id=getattr(u, "id", None) if getattr(u, "is_authenticated", False) else None, tenant_id=None)
loader = lambda tid: (None, ResourceScope(owner_id=10, tenant_id=None, visibility="private"))
mongo = lambda c, f, u: None
views.toggle_task_visibility_cas = lambda *a, **k: None

def call(req, user):
    req.user = user
    req.viewer = resolve(AnonymousUser())  # what the middleware resolved before the view
    return views.tasks_set_visibility(req, 42, viewer_resolver=resolve, scope_loader=loader, mongo_update_one=mongo).status_code

def session_user():
    return types.SimpleNamespace(id=10, is_authenticated=True, is_active=True, is_superuser=False)

def with_csrf(req):
    req.COOKIES["csrftoken"] = "a" * 32
    req.META["HTTP_X_CSRFTOKEN"] = "a" * 32
    return req

rf = RequestFactory()
out = {
    "api_key": call(rf.post("/apiv2/tasks/visibility/42/", {"visibility": "public"}, HTTP_AUTHORIZATION="Token good"), AnonymousUser()),
    "bad_key": call(rf.post("/apiv2/tasks/visibility/42/", {"visibility": "public"}, HTTP_AUTHORIZATION="Token nope"), AnonymousUser()),
    "session_no_csrf": call(rf.post("/apiv2/tasks/visibility/42/", {"visibility": "public"}), session_user()),
    "session_csrf": call(with_csrf(rf.post("/apiv2/tasks/visibility/42/", {"visibility": "public"})), session_user()),
    "key_and_session_no_csrf": call(
        rf.post("/apiv2/tasks/visibility/42/", {"visibility": "public"}, HTTP_AUTHORIZATION="Token good"), session_user()),
    "session_csrf_bad_json": call(with_csrf(rf.post("/apiv2/tasks/visibility/42/", "{nope", content_type="application/json")),
                                  session_user()),
}
print(json.dumps(out))
"""
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    res = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}"
    import json

    sso, off = chain == "sso", chain == "token_auth_off"
    assert json.loads(res.stdout.strip().splitlines()[-1]) == {
        "api_key": 404 if off else 200,  # no key authenticator: anonymous, the private task stays hidden
        "bad_key": 404 if off else 403,
        # Under SSO the cookie authenticates nobody: the caller is anonymous and the private task hidden.
        "session_no_csrf": 404 if sso else 403,
        "session_csrf": 404 if sso else 200,
        "key_and_session_no_csrf": 403 if off else 200,
        "session_csrf_bad_json": 404 if sso else 400,
    }


def _reschedule_rig(monkeypatch, *, acl_table=True, source_acl=False, url="sqlite://"):
    """A shared-mode tasking class wrapped by the hooks, on CAPE's scoped session + `safe_begin`."""
    import contextlib

    import sqlalchemy as sa
    from sqlalchemy.orm import scoped_session, sessionmaker

    from lib.tenancy.hooks import wrap_submission_and_web_utils

    cfg = lambda: policy.MTConfig(enabled=True, mode="shared", default_visibility="", local_admins_manage_all_tenants=True)  # noqa: E731
    monkeypatch.setattr("lib.tenancy.hooks.multitenancy_config", cfg)
    monkeypatch.setattr("lib.tenancy.policy.multitenancy_config", cfg)
    engine = sa.create_engine(url)
    if acl_table:
        ensure_acl_schema(engine)
    session = scoped_session(sessionmaker(bind=engine, expire_on_commit=False, future=True))
    plain_begin = session.begin

    @contextlib.contextmanager
    def safe_begin(*args, **kwargs):  # as lib.cuckoo.core.database._Database installs it
        if session().in_transaction():
            yield
            session().flush()
        else:
            with plain_begin(*args, **kwargs) as tx:
                yield tx

    session.begin = safe_begin
    if source_acl:
        with session.begin():
            set_task_acl(session, 10, user_id=7, tenant_id=3, visibility=PRIVATE)

    class DummyTasking:
        added_user_ids = []

        def __init__(self, sess):
            self.session = sess

        def view_task(self, task_id):
            return types.SimpleNamespace(id=task_id, user_id=7)

        def add(self, obj, user_id=0, **kwargs):
            DummyTasking.added_user_ids.append(user_id)
            with self.session.begin():  # as TasksMixIn.add does
                pass
            return 11

        def reschedule(self, task_id):
            self.view_task(task_id)
            self.session.execute(sa.text("SELECT 1"))  # the real one reads the task first
            return self.add("target")  # and passes no user_id

    wrap_submission_and_web_utils(tasking_cls=DummyTasking)
    return session, DummyTasking


def test_task_copy_scope_commits_the_copies(monkeypatch, tmp_path):
    # Reading the source scope outside a transaction autobegan one that nothing closed: every later
    # begin() only flushed (safe_begin), and gcs_refetch_banned's copies were never committed.
    import sqlalchemy as sa

    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy.hooks import inherit_task_scope

    url = f"sqlite:///{tmp_path / 'cape.db'}"
    session, tasking = _reschedule_rig(monkeypatch, source_acl=True, url=url)
    db = tasking(session)
    core_hooks.clear_all_hooks()
    core_hooks.register_task_copy_scope_hook(inherit_task_scope)
    try:
        with core_hooks.task_copy_scope(db, 10):
            assert db.add("target") == 11
    finally:
        core_hooks.clear_all_hooks()
    assert not session().in_transaction()
    with sa.create_engine(url).connect() as other:
        assert other.execute(sa.text("SELECT user_id, visibility FROM task_acl WHERE task_id = 11")).all() == [(7, PRIVATE)]


def test_reschedule_reads_the_source_scope_in_a_savepoint(monkeypatch):
    # init_tasks reschedules inside an open transaction; on Postgres a failed ACL read would abort it
    # unless the read is isolated in a savepoint.
    import sqlalchemy as sa

    session, tasking = _reschedule_rig(monkeypatch)
    statements = []
    sa.event.listen(session.get_bind(), "before_cursor_execute", lambda c, cur, st, *a: statements.append(st))
    with session.begin():
        assert tasking(session).reschedule(10) == 11
    assert any(st.startswith("SAVEPOINT") for st in statements)


@pytest.mark.parametrize("source_acl", [True, False])
def test_reschedule_copy_inherits_the_source_task_scope(monkeypatch, source_acl):
    # Reschedule (API, and init_tasks at scheduler start) re-adds the task outside any submission,
    # so the new row took the deployment default -- public in "shared" mode -- and a private
    # analysis came back public.
    from lib.tenancy.acl import resolve_task_scope

    session, tasking = _reschedule_rig(monkeypatch, source_acl=source_acl)
    assert tasking(session).reschedule(10) == 11
    scope = resolve_task_scope(session, 11)
    assert (scope.owner_id, scope.visibility) == (7, PRIVATE)
    assert scope.tenant_id == (3 if source_acl else None)
    # tasks.user_id too: user bans and per-user listings still key on it.
    assert tasking.added_user_ids == [7]


def test_reschedule_before_the_acl_table_exists_keeps_the_copy_owner_only(monkeypatch):
    # init_tasks reschedules at scheduler start, possibly before anything created task_acl.
    from lib.tenancy.acl import resolve_task_scope

    session, tasking = _reschedule_rig(monkeypatch, acl_table=False)
    assert tasking(session).reschedule(10) == 11
    scope = resolve_task_scope(session, 11)
    assert (scope.owner_id, scope.visibility) == (7, PRIVATE)


def test_reschedule_fails_closed_when_the_source_scope_is_unreadable(monkeypatch):
    from lib.tenancy.acl import resolve_task_scope

    session, tasking = _reschedule_rig(monkeypatch)

    def _boom(*args, **kwargs):
        raise RuntimeError("transient")

    monkeypatch.setattr("lib.tenancy.hooks.resolve_task_scope", _boom)
    monkeypatch.setattr("lib.tenancy.hooks.ensure_acl_schema_once", _boom)
    assert tasking(session).reschedule(10) == 11
    assert tasking.added_user_ids == [7]
    scope = resolve_task_scope(session, 11)
    assert (scope.owner_id, scope.visibility) == (7, PRIVATE)


def test_task_copy_stays_private_when_the_source_task_cannot_be_read(monkeypatch):
    from lib.tenancy.acl import resolve_task_scope

    session, tasking = _reschedule_rig(monkeypatch)

    def _boom(self, task_id):
        raise RuntimeError("db down")

    import lib.tenancy.hooks as hooks

    # Pin the non-inherited path to a public default, so falling back to it can't pass for private.
    monkeypatch.setattr(hooks, "get_current_viewer", lambda: None)
    monkeypatch.setattr(hooks, "get_current_entitlements", lambda: None)
    monkeypatch.setattr(hooks, "get_current_submission_visibility", lambda: None)
    monkeypatch.setattr(hooks, "resolve_default_visibility", lambda cfg: "public")
    monkeypatch.setattr(tasking, "view_task", _boom)
    with hooks.inherit_task_scope(tasking(session), 10):
        assert tasking(session).add("target") == 11
    assert resolve_task_scope(session, 11).visibility == PRIVATE


def test_ownerless_tasks_stay_public_with_multitenancy_off(monkeypatch):
    # tasks.user_id 0 is CAPE's "no owner" (add()'s default), not a user.
    import sqlalchemy as sa
    from sqlalchemy.orm import Session

    from lib.tenancy.acl import resolve_task_scope

    off = lambda: policy.MTConfig(enabled=False, mode="shared", default_visibility="", local_admins_manage_all_tenants=True)  # noqa: E731
    monkeypatch.setattr("lib.tenancy.policy.multitenancy_config", off)
    engine = sa.create_engine("sqlite://")
    ensure_acl_schema(engine)
    with Session(engine) as session:
        scope = resolve_task_scope(session, 5, fallback_user_id=0)
    assert (scope.owner_id, scope.visibility) == (None, "public")


def test_task_copy_scope_hook_makes_refetched_copies_inherit(monkeypatch):
    # gcs_refetch_banned re-adds banned tasks through submit_file, outside any submission.
    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy.acl import resolve_task_scope
    from lib.tenancy.hooks import inherit_task_scope, register_core_hooks

    session, tasking = _reschedule_rig(monkeypatch, source_acl=True)
    db = tasking(session)
    core_hooks.clear_all_hooks()
    with core_hooks.task_copy_scope(db, 10):
        assert db.add("target") == 11  # no-op context without the tenancy hook
    assert "register_task_copy_scope_hook(inherit_task_scope)" in __import__("inspect").getsource(register_core_hooks)
    try:
        core_hooks.register_task_copy_scope_hook(inherit_task_scope)
        with core_hooks.task_copy_scope(db, 10):
            assert db.add("target") == 11
    finally:
        core_hooks.clear_all_hooks()
    scope = resolve_task_scope(session, 11)
    assert (scope.owner_id, scope.tenant_id, scope.visibility) == (7, 3, PRIVATE)


def test_gcs_refetch_banned_adds_copies_inside_the_task_copy_scope():
    import inspect as _inspect

    from lib.cuckoo.common import gcp

    src = _inspect.getsource(gcp.gcs_refetch_banned)
    assert 'task_copy_scope(db, task["id"])' in src


def test_visibility_toggle_restamps_the_elasticsearch_copy_too():
    # The ES filter scopes on the ES document's own info.visibility stamp: a toggle that only
    # updated SQL and Mongo left ES-backed search serving the old visibility until a reprocess.
    import sqlalchemy as sa
    from sqlalchemy.orm import Session

    from lib.tenancy.acl import toggle_task_visibility_cas

    engine = sa.create_engine("sqlite://")
    ensure_acl_schema(engine)
    calls = []
    with Session(engine) as session:
        set_task_acl(session, 42, user_id=7, tenant_id=1, visibility="public")
        session.commit()
        stamp = toggle_task_visibility_cas(
            session,
            42,
            PRIVATE,
            mongo_update_one=lambda *a: None,
            es_update_by_query=lambda query, script: calls.append((query, script)),
        )
    assert len(calls) == 1
    query, script = calls[0]
    assert {"term": {"info.id": 42}} in query["bool"]["filter"]
    assert script["params"] == {
        "user_id": 7,
        "tenant_id": 1,
        "visibility": PRIVATE,
        "visibility_seq": stamp.visibility_seq,
    }
