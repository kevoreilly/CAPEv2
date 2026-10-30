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


def _run_on(db, task_id, label, requested=None):
    """Mark the task running on VM `label` (a guests row, as the scheduler writes it)."""
    from lib.cuckoo.core.data.guests import Guest

    with db.session.begin():
        task = db.view_task(task_id)
        task.machine = requested or label
        task.status = "running"
        guest = Guest(label, label, "windows", "KVM", task_id)
        guest.status = "running"
        db.session.add(guest)
    db.session.expire_all()  # a later request reads it afresh


def test_guac_vm_target_comes_from_the_task_not_the_url(db, temp_pe32, monkeypatch):
    import guac.views as guac_views

    task_id = db.add_path(str(temp_pe32))
    monkeypatch.setattr(guac_views, "db", db)
    monkeypatch.setattr(db, "view_machine_by_label", lambda label: types.SimpleNamespace(ip="192.168.122.10") if label == "win10-1" else None)
    with db.session.begin():
        db.view_task(task_id).machine = "win10-1"
    # Pending: the requested VM may be running another tenant's task.
    assert guac_views._vm_target_for_task(task_id) == ("", None)
    _run_on(db, task_id, "win10-1")
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
    _run_on(db, task_id, "win10-1")
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


def test_dashboard_counts_are_scoped_to_the_viewer(db, private_task, temp_pe32):
    # The dashboard and apiv2 cuckoo/status showed every tenant's task volume and sample count.
    from datetime import datetime

    from lib.cuckoo.common import hooks as core_hooks
    from lib.cuckoo.core.data.task import Task
    from lib.tenancy.context import set_current_viewer
    from lib.tenancy.hooks import register_core_hooks

    own = db.add_url("http://example.com/own", user_id=8)
    with db.session.begin():
        set_task_acl(db.session, own, user_id=8, tenant_id=2, visibility=PRIVATE)
    register_core_hooks()
    set_current_viewer(_viewer(user_id=8, tenant_id=2))
    try:
        with db.session.begin():
            assert db.count_tasks() == 1
            assert sum(db.get_tasks_status_count().values()) == 1
            assert db.count_samples() == 0  # the URL task has no sample; the other tenant's PE is hidden
            foreign = db.session.get(Task, private_task[0])
            foreign.started_on, foreign.completed_on = datetime(2020, 1, 1), datetime(2020, 1, 2)
        with db.session.begin():
            assert db.minmax_tasks() == (0, 0)
        set_current_viewer(None)
        with db.session.begin():
            assert db.count_tasks() == 2
            assert db.count_samples() == 1
            assert db.minmax_tasks() != (0, 0)
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


def test_compare_in_elasticsearch_mode_scopes_every_analysis_search():
    # The compare pages list other analyses of the same file; in ES-as-database mode they ran a
    # raw es.search, so a tenant saw every other tenant's analyses of that hash.
    pytest.importorskip("django")
    import os
    import subprocess
    import sys

    script = """
import sys
sys.path[:0] = [".", "web"]
import django
from django.conf import settings
settings.configure(WEB_AUTHENTICATION=False, CUCKOO_PATH=".", INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes"],
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}})
django.setup()
from django.test import RequestFactory
from lib.cuckoo.common import hooks
import compare.views as v

bodies = []
class FakeES:
    def search(self, index, body=None, query=None, **kw):
        bodies.append(body if body is not None else {"query": query})
        src = {"info": {"id": 1}, "target": {"file": {"md5": "a" * 32}}}
        return {"hits": {"hits": [{"_source": src}]}}

hooks.register_es_filter(lambda body: dict(body, scoped=True))
v.es, v.es_as_db, v.enabledconf["mongodb"] = FakeES(), True, False
v.get_analysis_index = lambda: "cape-analysis-*"
v.get_query_by_info_id = lambda i: {"match": {"info.id": i}}
v.render = lambda request, template, ctx: ctx
req = RequestFactory().get("/")
v.left(req, 1)
v.hash(req, 1, "a" * 32)
v.diff(req, 1, 2)
assert bodies and all(b.get("scoped") for b in bodies), bodies
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

        added_attributes = []

        def add(self, obj, user_id=0, attributes=None, **kwargs):
            DummyTasking.added_user_ids.append(user_id)
            DummyTasking.added_attributes.append(attributes)
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
        "job_id": None,
        "own_job_ids": ["ui-42", "local-42"],
        "stamp": {"user_id": 7, "tenant_id": 1, "visibility": PRIVATE, "visibility_seq": stamp.visibility_seq},
    }


def test_hunt_tag_task_ids_must_be_a_list(db, private_task):
    # tag_tasks iterates task_ids: a string "12" tags tasks 1 and 2, not the caller's task 12.
    import json

    own = [db.add_url(f"http://example.com/{i}", user_id=8) for i in range(12)][-1]
    with db.session.begin():
        set_task_acl(db.session, own, user_id=8, tenant_id=2, visibility=PRIVATE)
    assert own >= 10

    def tag_tasks(request):
        pass

    r = _req("/analysis/hunt/tag/")
    r.method, r.POST = "POST", {}
    r.body = json.dumps({"task_ids": str(own), "tag": "x"}).encode()
    assert _status(_mw(_viewer(8, 2)).process_view(r, tag_tasks, (), {})) == 404


def test_unreadable_body_denies_instead_of_erroring(mt_enabled):
    from django.test import RequestFactory
    from rest_framework.decorators import api_view

    @api_view(["POST"])
    def tasks_delete_many(request):
        pass

    req = RequestFactory().post("/apiv2/tasks/delete_many/", {"delete_mongo": "1"})
    req.user = types.SimpleNamespace(id=8, is_authenticated=True)
    _ = req.POST  # an earlier middleware consumed the multipart stream; .body now raises
    assert _status(_mw(_viewer(8, 2)).process_view(req, tasks_delete_many, (), {})) == 404


def test_central_staticzip_only_stages_the_route_tasks_own_sample(db, tmp_path, mt_enabled, monkeypatch):
    # /file/staticzip/<own task>/<another sample's sha256>/ staged the route task's binary as
    # storage/binaries/<that sha256>: the first write sticks, poisoning the cache for everyone.
    import sys

    from django.http import Http404
    from rest_framework.decorators import api_view

    from lib.tenancy import views as tviews
    from lib.tenancy.storage import config as storage_cfg
    from lib.tenancy.storage import views as storage_views

    root = tmp_path / "cuckoo"
    (root / "storage" / "binaries").mkdir(parents=True)
    fake = types.ModuleType("analysis.views")
    fake.ANALYSIS_BASE_PATH, fake.CUCKOO_ROOT, fake.zip_categories = str(root / "analyses"), str(root), ("staticzip",)
    monkeypatch.setitem(sys.modules, "analysis", types.ModuleType("analysis"))
    monkeypatch.setitem(sys.modules, "analysis.views", fake)
    monkeypatch.setattr(storage_cfg, "central_mode_config", lambda: types.SimpleNamespace(enabled=True))
    staged = []
    monkeypatch.setattr(storage_views, "central_stage_one", lambda *a: staged.append(a))
    monkeypatch.setattr(storage_views, "_task_sample_sha256", lambda request, task_id: "a" * 64)

    @api_view(["GET"])
    def file(request, category, task_id, dlfile):
        pass

    req = types.SimpleNamespace(path="/file/staticzip/5/x/", user=None)
    with pytest.raises(Http404):
        tviews.dispatch_object_storage_view(req, file, (), {"category": "staticzip", "task_id": "5", "dlfile": "b" * 64})
    assert staged == []
    assert tviews.dispatch_object_storage_view(req, file, (), {"category": "staticzip", "task_id": "5", "dlfile": "A" * 64}) is None
    assert len(staged) == 1


def test_default_es_restamp_sends_a_body_the_7x_client_accepts(monkeypatch):
    # dev_utils.elasticsearchdb builds an elasticsearch-py 7.x client: no query=/script= kwargs there.
    import sys

    from lib.tenancy import views as tviews

    calls = []
    fake_es = types.ModuleType("dev_utils.elasticsearchdb")
    fake_es.elastic_handler = types.SimpleNamespace(update_by_query=lambda **kw: calls.append(kw) or {"updated": 1})
    fake_es.get_analysis_index = lambda: "cuckoo-analysis-*"
    monkeypatch.setitem(sys.modules, "dev_utils.elasticsearchdb", fake_es)
    monkeypatch.setattr(
        "lib.cuckoo.common.config.Config", lambda name: types.SimpleNamespace(elasticsearchdb=types.SimpleNamespace(enabled=True))
    )
    tviews._default_es_update_by_query()({"term": {"info.id": 1}}, {"source": "x"})
    assert calls == [
        {
            "index": "cuckoo-analysis-*",
            "body": {"query": {"term": {"info.id": 1}}, "script": {"source": "x"}},
            "refresh": True,
            "conflicts": "proceed",
        }
    ]


@pytest.mark.parametrize("as_json", [False, True])
def test_submitters_cannot_supply_their_own_task_acl_attribute(monkeypatch, as_json):
    # attributes.task_acl is how dist hands a worker the main server's ACL; the reporters copy it into
    # the report's info. From an ordinary API submitter it is a forged owner/visibility/seq, and
    # main_task_id makes mongodb reporting replace that task's report with this one.
    import json

    from lib.tenancy.context import reset_current_viewer, set_current_viewer

    session, tasking = _reschedule_rig(monkeypatch)
    forged = {"task_acl": {"visibility": "public", "visibility_seq": 10**9}, "main_task_id": 3, "note": "x"}
    attrs = json.dumps(forged) if as_json else dict(forged)
    token = set_current_viewer(_viewer(8, 2))
    try:
        tasking(session).add("target", user_id=8, attributes=attrs)
    finally:
        reset_current_viewer(token)
    assert tasking.added_attributes[-1] == {"note": "x"}

    trusted = ViewerContext(user_id=1, tenant_id=None, is_superuser=True, is_local_admin=True, is_authenticated=True)
    token = set_current_viewer(trusted)  # e.g. the dist node's service account
    try:
        tasking(session).add("target", user_id=1, attributes=dict(forged))
    finally:
        reset_current_viewer(token)
    assert tasking.added_attributes[-1] == forged


def test_reprocess_with_only_a_tenant_keeps_the_visibility():
    # utils/process.py -r --tenant-id N (or CAPE_TENANT_ID) without --visibility made the task private.
    import sqlalchemy as sa
    from sqlalchemy.orm import Session

    engine = sa.create_engine("sqlite://")
    ensure_acl_schema(engine)
    with Session(engine) as session:
        set_task_acl(session, 5, user_id=7, tenant_id=1, visibility="public")
        row = set_task_acl(session, 5, tenant_id=2, visibility=None)
        assert (row.user_id, row.tenant_id, row.visibility) == (7, 2, "public")
        assert set_task_acl(session, 6, user_id=7, visibility=None).visibility == PRIVATE


def test_central_dispatch_leaves_the_api_files_view_alone(monkeypatch):
    # apiv2's files/get view is also named "file" (stype/value kwargs): it is not analysis.views.file.
    from rest_framework.decorators import api_view

    from lib.tenancy import views as tviews
    from lib.tenancy.storage import config as storage_cfg
    from lib.tenancy.storage import views as storage_views

    monkeypatch.setattr(storage_cfg, "central_mode_config", lambda: types.SimpleNamespace(enabled=True))
    monkeypatch.setattr(storage_views, "central_file", lambda *a, **k: "CENTRAL")

    @api_view(["GET"])
    def file(request, stype, value):
        pass

    req = types.SimpleNamespace(path="/apiv2/files/get/sha256/x/", user=None)
    assert tviews.dispatch_object_storage_view(req, file, (), {"stype": "sha256", "value": "a" * 64}) is None


def test_central_filereport_serves_the_requested_format(monkeypatch):
    from lib.tenancy import views as tviews
    from lib.tenancy.storage import config as storage_cfg
    from lib.tenancy.storage import views as storage_views

    monkeypatch.setattr(storage_cfg, "central_mode_config", lambda: types.SimpleNamespace(enabled=True))
    monkeypatch.setattr(storage_views, "central_filereport", lambda request, task_id, fname: fname)

    def filereport(request, task_id, category):
        pass

    req = types.SimpleNamespace(path="/filereport/5/pdf/", user=None)
    assert tviews.dispatch_object_storage_view(req, filereport, (), {"task_id": "5", "category": "pdf"}) == "report.pdf"


@pytest.mark.parametrize("custom", ["job_id=ui-5", "job_id=ui-5,foo=bar", "  job_id=ui-5"])
def test_submitters_cannot_claim_a_broker_job_id(monkeypatch, custom):
    # custom "job_id=ui-N" renumbers the report to task N, stamps it with N's ACL, overwrites N's
    # object-storage prefix and replaces N's Mongo report: only a broker/superuser may send it.
    from lib.tenancy.context import reset_current_viewer, set_current_viewer

    session, tasking = _reschedule_rig(monkeypatch)
    customs = []
    orig = tasking.add

    def add(self, obj, custom="", **kw):
        customs.append(custom)
        return orig(self, obj, **kw)

    monkeypatch.setattr(tasking, "add", add)
    from lib.tenancy.hooks import wrap_submission_and_web_utils

    wrap_submission_and_web_utils(tasking_cls=tasking)
    token = set_current_viewer(_viewer(8, 2))
    try:
        tasking(session).add("target", custom=custom, user_id=8)
    finally:
        reset_current_viewer(token)
    assert "job_id" not in customs[-1]


def test_es_restamp_retries_version_conflicts_then_fails_the_toggle(monkeypatch):
    # conflicts=proceed skips a doc a concurrent write touched: reporting success would leave a
    # revoked report searchable under its old visibility.
    import sys

    from lib.tenancy import views as tviews

    responses = iter([{"version_conflicts": 1}, {"version_conflicts": 0, "updated": 1}])
    fake_es = types.ModuleType("dev_utils.elasticsearchdb")
    fake_es.elastic_handler = types.SimpleNamespace(update_by_query=lambda **kw: next(responses))
    fake_es.get_analysis_index = lambda: "cuckoo-analysis-*"
    monkeypatch.setitem(sys.modules, "dev_utils.elasticsearchdb", fake_es)
    monkeypatch.setattr(
        "lib.cuckoo.common.config.Config", lambda name: types.SimpleNamespace(elasticsearchdb=types.SimpleNamespace(enabled=True))
    )
    assert tviews._default_es_update_by_query()({}, {})["updated"] == 1
    fake_es.elastic_handler = types.SimpleNamespace(update_by_query=lambda **kw: {"version_conflicts": 1})
    with pytest.raises(RuntimeError):
        tviews._default_es_update_by_query()({}, {})


def _ent(**kw):
    from lib.tenancy.resources import ResourceEntitlements

    base = dict(allowed_machines=frozenset({"*"}), allowed_routes=frozenset({"none"}), allow_interactive=False)
    base.update(kw)
    return ResourceEntitlements(**base)


def _policy(pid, priority=0, **kw):
    base = dict(
        id=pid,
        priority=priority,
        active=True,
        parent_group=None,
        inherit_parent_resources=True,
        allowed_machines=[],
        allowed_tags=[],
        allowed_routes=[],
        forced_machine_tags=[],
        default_route=None,
        default_visibility=None,
        allow_all_vms=False,
        allow_interactive=False,
        max_timeout=0,
    )
    base.update(kw)
    return types.SimpleNamespace(**base)


@pytest.mark.parametrize(
    "route", ["internet", "tor", "inetsim", "drop", "nexthop", "random", "roundrobin", "gw_b", "socks_nl", "tun9"]
)
def test_typed_route_wildcard_covers_only_routes_of_that_type(monkeypatch, route):
    # "vpn:*" means any VPN exit: not internet, a nexthop gateway, a socks5 proxy or a raw tun.
    import lib.tenancy.resources as res
    from lib.tenancy.resources import validate_and_normalize_submission

    types = {"vpn_uk": {"vpn"}, "gw_b": {"gw"}, "socks_nl": {"socks5", "socks"}}
    monkeypatch.setattr(res, "_known_route_types", lambda name: frozenset(types.get(name, ())))
    ent = _ent(allowed_routes=frozenset({"none", "vpn:*"}))
    assert ent.can_use_route("vpn_uk") is True
    assert ent.can_use_route(route) is False
    assert validate_and_normalize_submission({"route": route}, ent, global_route="none")[0] is False


def test_an_add_on_group_with_machines_keeps_the_tenant_pool_tag():
    from lib.tenancy.resources import merge_group_policies, validate_and_normalize_submission

    ent = merge_group_policies(
        [
            _policy(1, allowed_machines=["win10_alpha_*"], forced_machine_tags=["pool_alpha"], allowed_routes=["none"]),
            _policy(2, priority=5, allowed_machines=["win11_special"]),
        ]
    )
    assert ent.forced_machine_tags == frozenset({"pool_alpha"})
    ok, _, norm = validate_and_normalize_submission({}, ent, global_route="none")
    assert ok and norm["tags"] == "pool_alpha"


def test_first_available_needs_a_pool_tag_when_machines_are_restricted():
    # Without a forced tag the scheduler would pick any VM, another tenant's included.
    from lib.tenancy.resources import validate_and_normalize_submission

    ent = _ent(allowed_machines=frozenset({"win10_alpha_*"}))
    assert validate_and_normalize_submission({"machine": ""}, ent, global_route="none")[0] is False
    assert validate_and_normalize_submission({"machine": "win10_alpha_1"}, ent, global_route="none")[0] is True
    assert validate_and_normalize_submission({"machine": ""}, _ent(), global_route="none")[0] is True


@pytest.mark.parametrize(
    "params",
    [{"interactive": "2"}, {"interactive": "y"}, {"options": "interactive=y"}, {"lin_options": "interactive=2"}],
)
def test_any_truthy_interactive_value_is_checked(params):
    # The submit view enables the console for any non-empty value.
    from lib.tenancy.resources import validate_and_normalize_submission

    assert validate_and_normalize_submission(params, _ent(), global_route="none")[0] is False


@pytest.mark.parametrize("params", [{"interactive": "0"}, {"options": "interactive=0"}, {"options": "interactive=no"}])
def test_interactive_zero_is_still_interactive(params):
    # The guest checks options.get("interactive") for truthiness: "0" and "no" turn it on.
    from lib.tenancy.resources import validate_and_normalize_submission

    assert validate_and_normalize_submission(params, _ent(), global_route="none")[0] is False
    assert validate_and_normalize_submission({"interactive": ""}, _ent(), global_route="none")[0] is True


@pytest.mark.parametrize("params", [{"tor": "y"}, {"tor": "on"}, {"options": "tor=yes"}])
def test_any_truthy_tor_value_is_checked(params):
    from lib.tenancy.resources import validate_and_normalize_submission

    assert validate_and_normalize_submission(params, _ent(), global_route="none")[0] is False


def test_an_omitted_route_is_checked_against_the_global_default():
    from lib.tenancy.resources import validate_and_normalize_submission

    ent = _ent(allowed_routes=frozenset({"none", "inetsim"}))
    ok, _, norm = validate_and_normalize_submission({}, ent, global_route="internet")
    assert ok and norm["route"] == "none"
    ok, _, norm = validate_and_normalize_submission({}, ent, global_route="inetsim")
    assert ok and "route" not in norm  # left to the node that runs it, as for everyone else
    assert validate_and_normalize_submission({}, _ent(allowed_routes=frozenset({"inetsim"})), global_route="internet")[0] is False
    assert validate_and_normalize_submission({}, _ent(allowed_routes=frozenset({"inetsim"})), global_route=None)[0] is False


@pytest.mark.parametrize("groups", [[], [types.SimpleNamespace(sandbox_policy=types.SimpleNamespace(id=1, active=False))]])
def test_locked_mode_denies_users_no_active_policy_covers(monkeypatch, groups):
    import lib.tenancy.resources as res

    monkeypatch.setattr(res, "multitenancy_config", lambda: types.SimpleNamespace(enabled=True, mode="locked", local_admins_manage_all_tenants=True))
    user = types.SimpleNamespace(is_authenticated=True, is_superuser=False, groups=groups)
    assert res.resolve_user_entitlements(user).unrestricted is False
    assert res.resolve_user_entitlements(user, unassigned_policy="allow").unrestricted is True
    monkeypatch.setattr(res, "multitenancy_config", lambda: types.SimpleNamespace(enabled=True, mode="shared", local_admins_manage_all_tenants=True))
    assert res.resolve_user_entitlements(user).unrestricted is True


def test_task_add_enforces_entitlements_on_the_final_kwargs(monkeypatch):
    # API bodies (JSON, re-parsed urlencoded) reach add() without the middleware's normalization.
    from lib.tenancy.context import set_current_entitlements, set_current_viewer
    from lib.tenancy.hooks import inherit_task_scope, wrap_submission_and_web_utils

    monkeypatch.setattr("lib.tenancy.resources._routing_conf_default_route", lambda: "internet")
    session, tasking = _reschedule_rig(monkeypatch)
    calls = []
    orig = tasking.add

    def add(self, obj, **kw):
        calls.append(kw)
        return orig(self, obj, user_id=kw.get("user_id", 0))

    monkeypatch.setattr(tasking, "add", add)
    wrap_submission_and_web_utils(tasking_cls=tasking)
    set_current_viewer(_viewer(8, 2))
    set_current_entitlements(
        _ent(
            allowed_machines=frozenset({"win10_alpha_*"}),
            allowed_routes=frozenset({"none", "inetsim"}),
            forced_machine_tags=frozenset({"pool_alpha"}),
            max_timeout=120,
        )
    )
    t = tasking(session)
    assert t.add("x", machine="win10_beta_1", user_id=8) is None
    assert t.add("x", machine="win10_alpha_1", route="internet", user_id=8) is None
    assert t.add("x", machine="win10_alpha_1", options="interactive=1,", user_id=8) is None
    assert calls == []
    assert t.add("x", timeout=99999, user_id=8)
    assert calls[-1]["timeout"] == 120 and calls[-1]["tags"] == "pool_alpha" and calls[-1]["route"] == "none"
    with inherit_task_scope(t, 10):  # a copy is checked against the current entitlements too
        assert t.add("x", machine="win10_beta_1", user_id=8) is None
        assert t.add("x", machine="win10_alpha_1", tags="x64", route="none", user_id=8)
    assert calls[-1]["tags"] == "x64"  # add()'s own arch tags on the source are not the submitter's


def test_json_submission_bodies_are_checked_by_the_middleware():
    import json

    from django.test import RequestFactory

    viewer = _viewer(8, 2)
    ent = _ent(allowed_machines=frozenset({"win10_alpha_*"}), forced_machine_tags=frozenset({"pool_alpha"}))
    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: viewer, entitlements_resolver=lambda u: ent)

    def tasks_create_url(request):
        pass

    req = RequestFactory().post(
        "/apiv2/tasks/create/url/", json.dumps({"url": "http://a", "machine": "win10_beta_1"}), content_type="application/json"
    )
    req.user, req.viewer, req.entitlements = object(), viewer, ent
    assert _status(mw.process_view(req, tasks_create_url, (), {})) == 403


@pytest.mark.parametrize("path", ["/guac/5/abc/", "/submit/remote_session/5/"])
def test_console_views_need_allow_interactive(path):
    def index(request, task_id=None):
        pass

    req = _req(path)
    req.entitlements = _ent(allow_interactive=False)
    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: _viewer(8, 2))
    assert _status(mw.process_view(req, index, (), {})) == 403
    req.entitlements = _ent(allow_interactive=True)
    assert _status(mw.process_view(req, index, (), {})) != 403


def test_vmless_tasks_skip_machine_and_route_entitlements(monkeypatch):
    # PCAP and static tasks never run on a VM: a group without a pool tag can still submit them.
    from lib.tenancy.context import set_current_entitlements
    from lib.tenancy.hooks import wrap_submission_and_web_utils

    session, tasking = _reschedule_rig(monkeypatch)
    wrap_submission_and_web_utils(tasking_cls=tasking)
    set_current_entitlements(_ent(allowed_machines=frozenset({"win10_alpha_*"}), allowed_routes=frozenset()))

    class PCAP:
        pass

    t = tasking(session)
    assert t.add(PCAP(), user_id=8)
    assert t.add("x", user_id=8) is None

    viewer = _viewer(8, 2)
    ent = _ent(allowed_machines=frozenset({"win10_alpha_*"}))
    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: viewer, entitlements_resolver=lambda u: ent)

    def tasks_create_static(request):
        pass

    req = types.SimpleNamespace(path="/apiv2/tasks/create/static/", method="POST", user=object(), viewer=viewer, entitlements=ent, POST={})
    assert _status(mw.process_view(req, tasks_create_static, (), {})) != 403


def test_option_timeouts_are_capped_and_an_omitted_timeout_keeps_the_default():
    # dist copies options' timeout= into the task timeout it forwards to a worker.
    from lib.tenancy.resources import validate_and_normalize_submission

    ent = _ent(max_timeout=120)
    ok, _, norm = validate_and_normalize_submission({"options": "foo=1,timeout=99999"}, ent, global_route="none", default_timeout=60)
    assert ok and norm["options"] == "foo=1,timeout=120" and norm["timeout"] == "60"  # pinned for dist
    ok, _, norm = validate_and_normalize_submission({}, ent, global_route="none", default_timeout=300)
    assert norm["timeout"] == "120"


def test_vmless_submissions_keep_the_all_vms_check():
    from lib.tenancy.resources import validate_and_normalize_submission

    ent = _ent(allowed_machines=frozenset({"win10_alpha_*"}), allowed_routes=frozenset())
    assert validate_and_normalize_submission({}, ent, vmless=True)[0] is True
    assert validate_and_normalize_submission({"machine": "all"}, ent, vmless=True)[0] is False


def test_machine_labels_are_checked_by_the_machine_name(monkeypatch):
    # machine=all expands to labels (AWS: the instance id); policies list machine names.
    from lib.tenancy.context import set_current_entitlements
    from lib.tenancy.hooks import _enforce_task_entitlements

    monkeypatch.setattr("lib.tenancy.resources._routing_conf_default_route", lambda: "none")
    set_current_entitlements(_ent(allowed_machines=frozenset({"win10_alpha_*"})))
    db = types.SimpleNamespace(view_machine_by_label=lambda label: types.SimpleNamespace(name="win10_alpha_1") if label == "i-0abc" else None)
    assert _enforce_task_entitlements({"machine": "i-0abc"}, db) is None
    assert _enforce_task_entitlements({"machine": "i-0def"}, db)


def test_locked_mode_keeps_superusers_without_a_group(monkeypatch):
    import lib.tenancy.resources as res

    monkeypatch.setattr(res, "multitenancy_config", lambda: types.SimpleNamespace(enabled=True, mode="locked", local_admins_manage_all_tenants=False))
    user = types.SimpleNamespace(is_authenticated=True, is_superuser=True, groups=[])
    assert res.resolve_user_entitlements(user).unrestricted is True


def _wrap_real_tasking(monkeypatch):
    # The real TasksMixIn.add, wrapped for this test only (monkeypatch restores the original).
    from lib.cuckoo.core.data.tasking import TasksMixIn
    from lib.tenancy.hooks import wrap_submission_and_web_utils

    monkeypatch.setattr(TasksMixIn, "add", TasksMixIn.add)
    monkeypatch.setattr(TasksMixIn, "reschedule", TasksMixIn.reschedule)
    stub = types.SimpleNamespace()
    wrap_submission_and_web_utils(tasking_cls=TasksMixIn, machines_cls=stub, web_utils_mod=stub, submission_views_mod=stub)
    monkeypatch.setattr("lib.tenancy.resources._routing_conf_default_route", lambda: "none")


def test_random_vpn_picks_only_routes_the_submitter_may_use(db, temp_pe32, monkeypatch):
    # routing.conf random_vpn ran after the middleware: an unpermitted pick dropped the task.
    import lib.cuckoo.common.web_utils as wu
    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy.context import set_current_entitlements, set_current_viewer
    from lib.tenancy.hooks import default_route_list_filter

    _wrap_real_tasking(monkeypatch)
    monkeypatch.setattr(core_hooks, "_route_filters", [default_route_list_filter])
    monkeypatch.setattr(
        wu, "routing_conf", types.SimpleNamespace(socks5=types.SimpleNamespace(random_socks5=False), vpn=types.SimpleNamespace(random_vpn=True))
    )
    monkeypatch.setattr(wu, "vpns", {"vpn_uk": object(), "vpn_de": object()})
    monkeypatch.setattr(wu, "_load_socks5_operational", lambda: {})
    monkeypatch.setattr(wu, "choice", lambda seq: "vpn_de" if "vpn_de" in seq else seq[0])
    monkeypatch.setattr(wu, "load_vms_exits", lambda: {})
    monkeypatch.setattr(wu, "DYNAMIC_PLATFORM_DETERMINATION", False)
    monkeypatch.setattr(wu, "save_script_to_storage", lambda *a, **k: None)
    monkeypatch.setattr("lib.tenancy.resources._known_route_types", lambda name: frozenset({"vpn"}) if name.startswith("vpn_") else frozenset())
    set_current_viewer(_viewer(8, 2))
    set_current_entitlements(_ent(allowed_routes=frozenset({"none", "vpn:vpn_uk"})))
    req = types.SimpleNamespace(POST={"machine": "", "platform": "", "route": ""}, FILES=[object()])
    status, result = wu.download_file(
        request=req, content=open(temp_pe32, "rb").read(), path=temp_pe32, service="t",
        options="", task_ids=[], errors=[], url=False, fhash=False, user_id=8,
    )
    assert status == "ok" and result["task_ids"]
    assert [db.view_task(t).route for t in result["task_ids"]] == ["vpn_uk"]


def test_machine_all_expansion_by_label_is_kept(db, temp_pe32, monkeypatch):
    from lib.tenancy.context import set_current_entitlements, set_current_viewer

    _wrap_real_tasking(monkeypatch)
    db.add_machine(
        name="win10_alpha_1", label="i-0abc123", arch="x64", ip="192.168.56.101", platform="windows", tags="",
        interface="virbr0", snapshot=None, resultserver_ip="192.168.56.1", resultserver_port=2042, reserved=False,
    )
    set_current_viewer(_viewer(8, 2))
    set_current_entitlements(_ent(allowed_machines=frozenset({"win10_alpha_*"}), allow_all_vms=True))
    ids, _ = db.demux_sample_and_add_to_db(temp_pe32, machine="all", platform="windows", user_id=8)
    assert [db.view_task(i).machine for i in ids] == ["i-0abc123"]


def test_dist_forwards_url_tasks_with_their_machine_tags_route_and_timeout(monkeypatch):
    # The main node's add() applied the group's pool tag, route and timeout cap; the worker's
    # dist account is unrestricted, so dropping them ran the URL anywhere, with any route.
    import requests

    dist = pytest.importorskip("utils.dist")
    node = types.SimpleNamespace(name="worker1", url="http://worker1/apiv2/", apikey="k")
    task = types.SimpleNamespace(
        tags="pool_alpha", main_task_id=5, category="url", path="http://a.test/", package="", timeout=120,
        priority=1, options="", machine="", platform="", custom="", clock=None, memory=False,
        enforce_timeout=False, route="none", tlp=None,
    )
    fake_db = types.SimpleNamespace(scalar=lambda q: node, get=lambda model, tid: task, close=lambda: None)
    posted = {}

    def post(url, data=None, **kw):
        posted.update(data)
        raise requests.RequestException("stop here")

    monkeypatch.setattr(dist.requests, "post", post)
    dist.node_submit_task(1, 1, 5, db=fake_db)
    assert posted["url"] == "http://a.test/"
    assert (posted["tags"], posted["route"], posted["timeout"]) == ("pool_alpha", "none", 120)


@pytest.mark.parametrize(
    "options, expected", [("enforce_timeout=1", 120), ("xtimeout=5", 120), ("timeout=60", "60"), ("", 120)]
)
def test_dist_takes_the_timeout_option_only_from_timeout(options, expected):
    # "timeout=" in options matched enforce_timeout=1 too and set the task's timeout to 0, which the
    # worker runs as its own default, past the group's cap the main node applied.
    dist = pytest.importorskip("utils.dist")
    from lib.cuckoo.common.utils import get_options

    assert dist._task_timeout(120, get_options(options)) == expected


def test_a_tags_list_goes_back_to_add_as_a_string(monkeypatch):
    # add() only splits a str: a JSON list of tags was dropped, so first-available ran anywhere.
    from lib.tenancy.context import set_current_entitlements
    from lib.tenancy.hooks import _enforce_task_entitlements

    monkeypatch.setattr("lib.tenancy.resources._routing_conf_default_route", lambda: "none")
    set_current_entitlements(_ent(allowed_machines=frozenset({"win10_alpha_*"}), allowed_tags=frozenset({"pool_alpha"}), forced_machine_tags=frozenset({"pool_alpha"})))
    kw = {"machine": "", "tags": ["pool_alpha"]}
    assert _enforce_task_entitlements(kw) is None
    assert kw["tags"] == "pool_alpha"


@pytest.mark.parametrize("route", ["none ", " none", "NONE", "None"])
def test_builtin_routes_are_stored_as_analysis_manager_compares_them(route):
    from lib.tenancy.resources import validate_and_normalize_submission

    ok, _, norm = validate_and_normalize_submission({"route": route}, _ent(), global_route="none")
    assert ok and norm["route"] == "none"


@pytest.mark.parametrize("options", ["netns=cape", "sslproxy=1", "mitmdump=1", "polarproxy=1"])
def test_host_proxy_and_netns_options_need_internet(options):
    from lib.tenancy.resources import validate_and_normalize_submission

    assert validate_and_normalize_submission({"options": options}, _ent(), global_route="none")[0] is False
    with_internet = _ent(allowed_routes=frozenset({"none", "internet"}))
    assert validate_and_normalize_submission({"options": options}, with_internet, global_route="none")[0] is (options != "netns=cape")


def test_json_bodies_are_read_for_any_content_type_drf_parses_as_json():
    import json

    from django.test import RequestFactory

    from lib.tenancy.middleware import _extract_submission_params

    req = RequestFactory().post("/apiv2/tasks/create/url/", json.dumps({"machine": "all"}), content_type="application/*")
    assert _extract_submission_params(req) == {"machine": "all"}


@pytest.mark.parametrize("field", ["hash", "hashes"])
@pytest.mark.parametrize("sha", ["a" * 64, "a" * 128])  # sample_path_by_hash also takes sha512
def test_posted_sample_hashes_need_sample_access(field, sha):
    # /submit/ hash= and download services read storage/binaries/<hash> first.

    def tasks_create_download_services(request):
        pass

    viewer = _viewer(8, 2)
    req = types.SimpleNamespace(path="/apiv2/tasks/create/download_services/", method="POST", user=object(), viewer=viewer, entitlements=None, POST={field: sha})
    mw = TenancyMiddleware(
        lambda r: None, viewer_resolver=lambda u: viewer, entitlements_resolver=lambda u: _ent(allowed_machines=frozenset({"*"}), allowed_routes=frozenset({"*"})),
        sample_access_checker=lambda v, f: False, sample_exists_checker=lambda f: True,
    )
    assert _status(mw.process_view(req, tasks_create_download_services, (), {})) == 404
    mw.sample_exists_checker = lambda f: False  # not stored: a download service fetches it from outside
    assert _status(mw.process_view(req, tasks_create_download_services, (), {})) == (404 if field == "hash" else None)


def test_the_middleware_leaves_an_omitted_route_to_random_vpn_and_the_final_check():
    # download_file picks routing.conf's random_vpn only when no route was submitted.
    from lib.tenancy.resources import validate_and_normalize_submission

    ent = _ent(allowed_routes=frozenset({"none", "vpn:vpn_uk"}))
    ok, _, norm = validate_and_normalize_submission({}, ent, global_route="none", resolve_omitted_route=False)
    assert ok and "route" not in norm


def test_early_from_imports_of_the_mongo_helpers_are_rebound(monkeypatch):
    # web_utils did `from dev_utils.mongodb import mongo_aggregate` before tenancy wrapped it, so
    # statistics/top_detections aggregated every tenant's reports.
    import sys

    from lib.tenancy import hooks

    fake = types.ModuleType("fake_mongodb")
    fake.mongo_find = lambda *a, **k: []
    fake.mongo_find_one = lambda *a, **k: None
    fake.mongo_aggregate = lambda coll, pipeline, *a, **k: pipeline
    early = types.ModuleType("fake_early_importer")
    early.mongo_aggregate = fake.mongo_aggregate
    monkeypatch.setitem(sys.modules, "fake_mongodb", fake)
    monkeypatch.setitem(sys.modules, "fake_early_importer", early)
    monkeypatch.setattr(hooks, "_patched_modules", set())
    hooks.wrap_mongodb_module(fake)
    assert early.mongo_aggregate is fake.mongo_aggregate
    assert getattr(early.mongo_aggregate, "_cape_tenancy_wrapped", False)


def test_cached_dashboard_aggregates_are_cached_per_viewer_scope(monkeypatch):
    from lib.tenancy.context import set_current_viewer
    from lib.tenancy.hooks import wrap_submission_and_web_utils

    wu = types.SimpleNamespace()
    calls = []

    def top_detections():
        if hasattr(wu.top_detections, "cache"):
            return wu.top_detections.cache
        calls.append(1)
        wu.top_detections.cache = f"result{len(calls)}"
        return wu.top_detections.cache

    wu.top_detections = top_detections
    stub = types.SimpleNamespace()
    wrap_submission_and_web_utils(tasking_cls=stub, machines_cls=stub, web_utils_mod=wu, submission_views_mod=stub)
    admin = ViewerContext(user_id=1, tenant_id=None, is_superuser=True, is_local_admin=True, is_authenticated=True)
    set_current_viewer(admin)
    assert wu.top_detections() == "result1"
    set_current_viewer(_viewer(8, 2))
    assert wu.top_detections() == "result2"  # not the admin's cached result
    assert wu.top_detections() == "result2"  # its own, cached
    set_current_viewer(_viewer(9, 3))
    assert wu.top_detections() == "result3"  # not tenant 2's
    set_current_viewer(admin)
    assert wu.top_detections() == "result1"


@pytest.mark.parametrize(
    "posted",
    ["https://vt.example/file/{sha}/", "{sha512}", "{a} {b},x"],
)
def test_posted_hashes_are_parsed_as_the_views_parse_them(posted):
    sha, sha512 = "c" * 64, "d" * 128
    value = posted.format(sha=sha, sha512=sha512, a=sha[:30], b=sha[30:])
    checked = []

    def tasks_create_download_services(request):
        pass

    viewer = _viewer(8, 2)
    req = types.SimpleNamespace(path="/apiv2/tasks/create/download_services/", method="POST", user=object(), viewer=viewer, entitlements=None, POST={"hashes": value})
    mw = TenancyMiddleware(
        lambda r: None, viewer_resolver=lambda u: viewer, entitlements_resolver=lambda u: _ent(allowed_machines=frozenset({"*"}), allowed_routes=frozenset({"*"})),
        sample_access_checker=lambda v, f: checked.append(f) and False, sample_exists_checker=lambda f: True,
    )
    assert _status(mw.process_view(req, tasks_create_download_services, (), {})) == 404
    assert any(f in ({"sha256": sha}, {"sha512": sha512}) for f in checked)


def test_a_recovered_tasks_redirect_target_is_authorized_too():
    # validate_task/tasks_view follow custom "Recovery_<id>" to task <id>.
    from lib.tenancy.policy import ResourceScope

    scopes = {1: ResourceScope(owner_id=8, tenant_id=2, visibility=PRIVATE), 2: ResourceScope(owner_id=7, tenant_id=1, visibility=PRIVATE)}
    mw = TenancyMiddleware(
        lambda r: None, viewer_resolver=lambda u: _viewer(8, 2), task_scope_resolver=scopes.get,
        recovery_target_resolver=lambda tid: 2 if tid == 1 else None,
    )

    def tasks_report(request, task_id):
        pass

    assert _status(mw.process_view(_req("/apiv2/tasks/get/report/1/"), tasks_report, (), {"task_id": 1})) == 404


def test_untrusted_submitters_cannot_set_a_recovery_custom(monkeypatch):
    from lib.tenancy.context import set_current_viewer
    from lib.tenancy.hooks import _strip_untrusted_broker_job_id

    set_current_viewer(_viewer(8, 2))
    assert _strip_untrusted_broker_job_id("Recovery_5") == ""
    assert _strip_untrusted_broker_job_id("note") == "note"


def test_untrusted_bare_custom_is_not_taken_as_a_broker_job_id(monkeypatch):
    # With object storage on, a bare custom token is the broker job id: "local-7" filed the
    # submitter's report and artifacts under task 7's job, replacing them.
    from lib.tenancy.context import set_current_viewer
    from lib.tenancy.hooks import _strip_untrusted_broker_job_id
    from lib.tenancy.storage import config as storage_cfg
    from lib.tenancy.storage.artifact_storage import job_id_from_custom

    monkeypatch.setattr(storage_cfg, "central_mode_config", lambda: types.SimpleNamespace(enabled=True))
    set_current_viewer(_viewer(8, 2))
    for custom in ("local-7", "note"):
        assert job_id_from_custom(_strip_untrusted_broker_job_id(custom)) is None
    assert _strip_untrusted_broker_job_id("a=b,c=d") == "a=b,c=d"
    set_current_viewer(None)  # the broker
    assert _strip_untrusted_broker_job_id("local-7") == "local-7"


@pytest.mark.parametrize("view_name", ["statistics_data", "yara_uploader"])
def test_deployment_wide_views_are_admin_only(view_name, monkeypatch):
    view = types.FunctionType((lambda request: None).__code__, {}, view_name)
    # Object storage alone installs the middleware too: without auth everything is public...
    monkeypatch.setattr("lib.tenancy.middleware.multitenancy_config", lambda: types.SimpleNamespace(enabled=False))
    monkeypatch.setattr("lib.tenancy.middleware._web_authentication_enabled", lambda: False)
    assert _status(_mw(_viewer(8, 2)).process_view(_req("/x/"), view, (), {})) is None
    # ...with auth, each user's tasks are PRIVATE, which statistics' raw SQL would list.
    monkeypatch.setattr("lib.tenancy.middleware._web_authentication_enabled", lambda: True)
    assert _status(_mw(_viewer(8, 2)).process_view(_req("/x/"), view, (), {})) == 403
    monkeypatch.setattr("lib.tenancy.middleware.multitenancy_config", lambda: types.SimpleNamespace(enabled=True))
    assert _status(_mw(_viewer(8, 2)).process_view(_req("/x/"), view, (), {})) == 403
    admin = ViewerContext(user_id=1, tenant_id=None, is_superuser=True, is_local_admin=True, is_authenticated=True)
    assert _status(_mw(admin).process_view(_req("/x/"), view, (), {})) is None


def test_path_like_filename_kwargs_are_refused():
    # vtupload joins <filename> onto the task directory: ../ reaches other tasks and binaries.
    def vtupload(request, **kw):
        pass

    req = _req("/vtupload/dropped/1/x/y/")
    kwargs = {"category": "dropped", "task_id": 1, "filename": "../../binaries/" + "a" * 64, "dlfile": "y"}
    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: _viewer(8, 2), task_scope_resolver=lambda t: types.SimpleNamespace(owner_id=8, tenant_id=2, visibility=PRIVATE), recovery_target_resolver=lambda t: None)
    assert _status(mw.process_view(req, vtupload, (), kwargs)) == 404


def test_finishing_a_task_through_tasks_status_needs_manage_rights():
    from lib.tenancy.policy import PUBLIC, ResourceScope

    def tasks_status(request, task_id):
        pass

    mw = TenancyMiddleware(
        lambda r: None, viewer_resolver=lambda u: _viewer(8, 2),
        task_scope_resolver=lambda t: ResourceScope(owner_id=7, tenant_id=1, visibility=PUBLIC), recovery_target_resolver=lambda t: None,
    )
    req = _req("/apiv2/tasks/status/1/")
    assert _status(mw.process_view(req, tasks_status, (), {"task_id": 1})) is None
    req.method = "POST"
    assert _status(mw.process_view(req, tasks_status, (), {"task_id": 1})) == 404


def test_dlnexec_needs_internet():
    # The web host fetches the URL itself, outside any VM route.
    viewer = _viewer(8, 2)
    ent = _ent()
    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: viewer, entitlements_resolver=lambda u: ent)

    def tasks_create_dlnexec(request):
        pass

    req = types.SimpleNamespace(path="/apiv2/tasks/create/dlnexec/", method="POST", user=object(), viewer=viewer, entitlements=ent, POST={"dlnexec": "http://127.0.0.1/"})
    assert _status(mw.process_view(req, tasks_create_dlnexec, (), {})) == 403


def test_unreadable_submission_bodies_are_refused():
    from django.test import RequestFactory

    viewer = _viewer(8, 2)
    ent = _ent()
    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: viewer, entitlements_resolver=lambda u: ent)

    def tasks_create_url(request):
        pass

    req = RequestFactory().post("/apiv2/tasks/create/url/", "--B\r\n", content_type="multipart/mixed; boundary=B")
    req.user, req.viewer, req.entitlements = object(), viewer, ent
    assert _status(mw.process_view(req, tasks_create_url, (), {})) == 403


@pytest.mark.parametrize("content_type", ["*/x-www-form-urlencoded", "application/*"])
def test_bodies_are_read_with_the_parser_drf_picks(content_type):
    # DRF's FormParser takes */x-www-form-urlencoded (a JSON reading of it would see other keys);
    # its JSONParser takes application/*.
    import json

    from django.test import RequestFactory

    from lib.tenancy.middleware import _extract_submission_params

    body = "url=http://a&machine=win10_beta_1" if "form" in content_type else json.dumps({"machine": "win10_beta_1"})
    req = RequestFactory().post("/apiv2/tasks/create/url/", body, content_type=content_type)
    assert _extract_submission_params(req)["machine"] == "win10_beta_1"


@pytest.mark.parametrize(
    "options,route,allowed",
    [
        ("sslproxy=1", "vpn_uk", True),
        ("sslproxy=0", "", True),
        ("filename=polarproxy_setup.exe", "", True),
        ("sslproxy=1", "", False),
        ("sslproxy=No", "", False),  # SSLProxy compares case-sensitively: "No" is on
        ("SSLPROXY=0,sslproxy=1", "", False),
        ("polarproxy =1", "", False),  # dist re-serializes it as polarproxy=1
    ],
)
def test_sslproxy_follows_a_vpn_route(monkeypatch, options, route, allowed):
    import lib.tenancy.resources as res
    from lib.tenancy.resources import validate_and_normalize_submission

    monkeypatch.setattr(res, "_known_route_types", lambda name: frozenset({"vpn"}) if name == "vpn_uk" else frozenset())
    # SSLProxy looks the table up by routing.conf section: [vpn_uk] rt_table = tun0
    monkeypatch.setattr(res, "_sslproxy_rt_table", lambda route: "tun0" if route == "vpn_uk" else "")
    ent = _ent(allowed_routes=frozenset({"none", "vpn:*"}))
    assert validate_and_normalize_submission({"options": options, "route": route}, ent, global_route="none")[0] is allowed


def test_the_middleware_accepts_a_permitted_machine_by_its_label():
    from lib.tenancy.resources import validate_and_normalize_submission

    ent = _ent(allowed_machines=frozenset({"win10_alpha_*"}))
    lookup = {"i-0abc": "win10_alpha_1"}.get
    assert validate_and_normalize_submission({"machine": "i-0abc"}, ent, global_route="none", machine_name_of=lookup)[0] is True
    assert validate_and_normalize_submission({"machine": "i-0def"}, ent, global_route="none", machine_name_of=lookup)[0] is False


def test_a_refused_reschedule_copy_leaves_its_source_as_it_was(monkeypatch):
    from lib.tenancy.context import set_current_entitlements, set_current_viewer
    from lib.tenancy.hooks import wrap_submission_and_web_utils

    monkeypatch.setattr("lib.tenancy.resources._routing_conf_default_route", lambda: "none")
    session, tasking = _reschedule_rig(monkeypatch)
    src = types.SimpleNamespace(id=10, user_id=7, status="reported", custom="job_id=ui-1")
    rows = {10: src}

    def reschedule(self, task_id):
        rows[task_id].status = "recovered"  # as TasksMixIn.reschedule does before add()
        new_id = self.add("x", machine="win10_beta_1", user_id=8)
        rows[task_id].custom = f"Recovery_{new_id}"
        return new_id

    monkeypatch.setattr(tasking, "reschedule", reschedule)
    monkeypatch.setattr(tasking, "view_task", lambda self, tid: rows.get(int(tid)))
    wrap_submission_and_web_utils(tasking_cls=tasking)
    t = tasking(session)
    monkeypatch.setattr(type(session), "get", lambda self, model, tid: rows.get(int(tid)), raising=False)
    set_current_viewer(_viewer(8, 2))
    set_current_entitlements(_ent(allowed_machines=frozenset({"win10_alpha_*"})))
    assert t.reschedule(10) is None
    assert (src.status, src.custom) == ("reported", "job_id=ui-1")


def test_task_file_stream_stays_inside_the_tasks_own_directory(db, temp_pe32, temp_pe64, tmp_path, monkeypatch):
    # filepath=../<other task>/reports/report.json passed the old storage/-prefix check.
    import apiv2.views as v
    from rest_framework.test import APIRequestFactory, force_authenticate

    root = tmp_path / "cape"
    storage = root / "storage"
    monkeypatch.setattr(v, "CUCKOO_ROOT", str(root))
    monkeypatch.setattr(v, "ANALYSIS_BASE_PATH", str(storage))
    victim = db.add_path(str(temp_pe32), user_id=7)
    own = db.add_path(str(temp_pe64), user_id=8)
    with db.session.begin():
        m = db.add_machine(
            name="win1", label="win1", arch="x64", ip="127.0.0.1", platform="windows", tags="", interface="eth0",
            snapshot=None, resultserver_ip="1.1.1.1", resultserver_port=2042, reserved=False,
        )
        db.create_guest(m, "kvm", db.session.get(v.Task, own))
    with db.session.begin():
        db.set_machine_status("win1", "running")
    (storage / "analyses" / str(victim) / "reports").mkdir(parents=True)
    (storage / "analyses" / str(victim) / "reports" / "report.json").write_bytes(b"VICTIM")
    (storage / "analyses" / str(own) / "logs").mkdir(parents=True)
    (storage / "analyses" / str(own) / "logs" / "a.log").write_bytes(b"OWN")
    user = types.SimpleNamespace(id=8, is_authenticated=True, is_staff=False, is_superuser=False)

    def stream(filepath):
        req = APIRequestFactory().post(f"/apiv2/tasks/get/stream/{own}/", {"filepath": filepath, "is_local": "1"})
        force_authenticate(req, user=user)
        return v.tasks_file_stream(req, task_id=str(own))

    assert next(iter(stream("logs/a.log").streaming_content)) == b"OWN"  # it tails while the VM runs
    resp = stream(f"../{victim}/reports/report.json")
    assert not hasattr(resp, "streaming_content") and resp.data["error"] is True


def test_wrapped_mongo_reads_keep_the_modules_result_hooks(monkeypatch):
    # dev_utils.mongodb's originals run hooks[mongo_find][collection], looked up by the module
    # global, which then names the wrapper: files-collection denormalization silently stopped.
    import collections
    import sys

    from lib.tenancy import hooks

    fake = types.ModuleType("fake_mongodb_hooks")
    fake.hooks = collections.defaultdict(lambda: collections.defaultdict(list))

    def mongo_find(collection, query, *a, **k):
        result = [{"file_ref": "abc"}]
        for hook in fake.hooks[fake.mongo_find][collection]:
            result = hook(result)
        return result

    fake.mongo_find = mongo_find
    fake.mongo_find_one = lambda *a, **k: None
    fake.mongo_aggregate = lambda *a, **k: []
    fake.hooks[mongo_find]["analysis"].append(lambda docs: [{"sha256": d["file_ref"]} for d in docs])
    monkeypatch.setitem(sys.modules, "fake_mongodb_hooks", fake)
    monkeypatch.setattr(hooks, "_patched_modules", set())
    hooks.wrap_mongodb_module(fake)
    assert fake.mongo_find("analysis", {}) == [{"sha256": "abc"}]


def test_early_importers_of_top_detections_get_the_wrapper(monkeypatch):
    import sys

    from lib.tenancy.hooks import wrap_submission_and_web_utils

    wu = types.ModuleType("fake_web_utils")
    wu.top_detections = lambda: []
    wu.top_asn = lambda: []
    dashboard = types.ModuleType("fake_dashboard_views")
    dashboard.top_detections = wu.top_detections
    monkeypatch.setitem(sys.modules, "fake_dashboard_views", dashboard)
    stub = types.SimpleNamespace()
    wrap_submission_and_web_utils(tasking_cls=stub, machines_cls=stub, web_utils_mod=wu, submission_views_mod=stub)
    assert dashboard.top_detections is wu.top_detections and getattr(wu.top_detections, "_cape_tenancy_wrapped", False)


def test_recovery_redirects_are_checked_on_the_apiv2_views_that_follow_them(db, temp_pe32, mt_enabled):
    from lib.tenancy.middleware import default_recovery_target_resolver
    from lib.tenancy.policy import ResourceScope

    src = db.add_path(str(temp_pe32), user_id=8)
    copy = db.add_path(str(temp_pe32), user_id=7)
    with db.session.begin():
        task = db.view_task(src)
        task.status, task.custom = "recovered", f"Recovery_{copy}"
    assert default_recovery_target_resolver(src) == copy

    scopes = {1: ResourceScope(owner_id=8, tenant_id=2, visibility=PRIVATE), 2: ResourceScope(owner_id=7, tenant_id=1, visibility=PRIVATE)}
    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: _viewer(8, 2), task_scope_resolver=scopes.get, recovery_target_resolver=lambda t: 2)

    def tasks_report(request, task_id):
        pass

    def tasks_status(request, task_id):
        pass

    assert _status(mw.process_view(_req("/analysis/1/"), tasks_report, (), {"task_id": 1})) is None  # serves task 1 itself
    assert _status(mw.process_view(_req("/apiv2/tasks/get/report/1/"), tasks_report, (), {"task_id": 1})) == 404
    # tasks/status, reschedule, reprocess act on task 1 itself: its owner keeps them.
    assert _status(mw.process_view(_req("/apiv2/tasks/status/1/"), tasks_status, (), {"task_id": 1})) is None


def test_the_middleware_resolves_machine_labels(monkeypatch):
    viewer = _viewer(8, 2)
    ent = _ent(allowed_machines=frozenset({"win10_alpha_*"}), forced_machine_tags=frozenset({"pool"}))
    monkeypatch.setattr("lib.tenancy.middleware.machine_name_by_label", lambda db=None: {"i-0abc": "win10_alpha_1"}.get)
    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: viewer, entitlements_resolver=lambda u: ent)

    def tasks_create_url(request):
        pass

    for machine, status in (("i-0abc", None), ("i-0def", 403)):
        req = types.SimpleNamespace(path="/apiv2/tasks/create/url/", method="POST", user=object(), viewer=viewer, entitlements=ent, POST={"url": "http://a", "machine": machine})
        assert _status(mw.process_view(req, tasks_create_url, (), {})) == status


def test_random_vpn_still_runs_when_the_default_route_is_not_allowed():
    # The middleware must not resolve the omitted route to "none": download_file only runs
    # random_vpn for an empty route, and the final add() check resolves what is left.
    from lib.tenancy.resources import validate_and_normalize_submission

    ent = _ent(allowed_routes=frozenset({"none", "vpn:vpn_uk"}))
    ok, _, norm = validate_and_normalize_submission({}, ent, global_route="internet", resolve_omitted_route=False)
    assert ok and "route" not in norm
    ok, _, norm = validate_and_normalize_submission({}, ent, global_route="internet")
    assert ok and norm["route"] == "none"


def test_a_job_id_field_does_not_smuggle_a_recovery_custom():
    from lib.tenancy.context import set_current_viewer
    from lib.tenancy.hooks import _strip_untrusted_broker_job_id

    set_current_viewer(_viewer(8, 2))
    assert _strip_untrusted_broker_job_id("Recovery_5,job_id=x") == ""


def test_dlnexec_through_tor_still_needs_internet():
    # _download_file compares the route exactly ("TOR" fetches directly) and DRF may decode the body
    # differently: the middleware can't tell a proxied fetch from a direct one.
    viewer = _viewer(8, 2)
    ent = _ent(allowed_routes=frozenset({"tor"}))
    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: viewer, entitlements_resolver=lambda u: ent)

    def tasks_create_dlnexec(request):
        pass

    req = types.SimpleNamespace(path="/apiv2/tasks/create/dlnexec/", method="POST", user=object(), viewer=viewer, entitlements=ent, POST={"dlnexec": "http://a/x.exe", "route": "TOR"})
    assert _status(mw.process_view(req, tasks_create_dlnexec, (), {})) == 403


def test_dotted_file_names_are_not_path_traversal():
    def vtupload(request, **kw):
        pass

    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: _viewer(8, 2), task_scope_resolver=lambda t: types.SimpleNamespace(owner_id=8, tenant_id=2, visibility=PRIVATE), recovery_target_resolver=lambda t: None)
    kwargs = {"category": "dropped", "task_id": 1, "filename": "Rechnung_2024..pdf.exe", "dlfile": "y"}
    assert _status(mw.process_view(_req("/vtupload/dropped/1/x/y/"), vtupload, (), kwargs)) is None
    kwargs["filename"] = ".."
    assert _status(mw.process_view(_req("/vtupload/dropped/1/x/y/"), vtupload, (), kwargs)) == 404


def test_exitnodes_lists_only_permitted_routes(monkeypatch):
    import apiv2.views as v
    from rest_framework.test import APIRequestFactory, force_authenticate

    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy.context import set_current_entitlements
    from lib.tenancy.hooks import default_route_list_filter

    monkeypatch.setattr(core_hooks, "_route_filters", [default_route_list_filter])
    monkeypatch.setattr(v, "apiconf", types.SimpleNamespace(list_exitnodes={"enabled": True}))
    monkeypatch.setattr(v, "routing_conf", types.SimpleNamespace(tor=types.SimpleNamespace(enabled=True), inetsim=types.SimpleNamespace(enabled=True)))
    monkeypatch.setattr(v, "vpns", {"vpn_uk": object()})
    monkeypatch.setattr(v, "_load_socks5_operational", lambda: {"socks_nl": {}})
    set_current_entitlements(_ent(allowed_routes=frozenset({"none", "inetsim"})))
    req = APIRequestFactory().get("/apiv2/exitnodes/")
    force_authenticate(req, user=types.SimpleNamespace(id=8, is_authenticated=True))
    assert v.exit_nodes_list(req).data["data"] == ["inetsim"]


def test_the_middleware_leaves_an_omitted_route_unset_for_random_vpn(monkeypatch):
    # download_file runs random_vpn only for an empty route: pinning "none" into request.POST
    # (routing.conf's default is not allowed) would switch it off.
    monkeypatch.setattr("lib.tenancy.resources._routing_conf_default_route", lambda: "internet")
    viewer = _viewer(8, 2)
    ent = _ent(allowed_routes=frozenset({"none", "vpn:vpn_uk"}))
    mw = TenancyMiddleware(lambda r: None, viewer_resolver=lambda u: viewer, entitlements_resolver=lambda u: ent)

    def tasks_create_file(request):
        pass

    req = types.SimpleNamespace(path="/apiv2/tasks/create/file/", method="POST", user=object(), viewer=viewer, entitlements=ent, POST={"machine": ""})
    assert _status(mw.process_view(req, tasks_create_file, (), {})) is None
    assert "route" not in req.POST


@pytest.mark.parametrize(
    "route,conf_route,expected",
    [("vpn0", "none", "tun0"), ("socks_ch", "none", ""), ("", "vpn0", "tun0"), ("tun5", "none", "tun5"), ("internet", "none", "")],
)
def test_sslproxy_routing_table_is_looked_up_as_sslproxy_does(monkeypatch, route, conf_route, expected):
    from lib.tenancy.resources import _sslproxy_rt_table

    class Routing:
        routing = types.SimpleNamespace(route=conf_route)
        vpn0 = types.SimpleNamespace(rt_table="tun0")

        def get(self, name):
            return getattr(self, name)

    monkeypatch.setattr("lib.cuckoo.common.config.Config", lambda name: Routing())
    assert _sslproxy_rt_table(route) == expected


def test_a_refused_reschedule_copy_does_not_undo_a_later_status(monkeypatch):
    from lib.tenancy.context import set_current_entitlements, set_current_viewer
    from lib.tenancy.hooks import wrap_submission_and_web_utils

    monkeypatch.setattr("lib.tenancy.resources._routing_conf_default_route", lambda: "none")
    session, tasking = _reschedule_rig(monkeypatch)
    src = types.SimpleNamespace(id=10, user_id=7, status="reported", custom="")
    rows = {10: src}

    def reschedule(self, task_id):
        rows[task_id].status = "recovered"
        new_id = self.add("x", machine="win10_beta_1", user_id=8)
        rows[task_id].status = "running"  # something else moved it on meanwhile
        return new_id

    monkeypatch.setattr(tasking, "reschedule", reschedule)
    monkeypatch.setattr(tasking, "view_task", lambda self, tid: rows.get(int(tid)))
    wrap_submission_and_web_utils(tasking_cls=tasking)
    monkeypatch.setattr(type(session), "get", lambda self, model, tid: rows.get(int(tid)), raising=False)
    set_current_viewer(_viewer(8, 2))
    set_current_entitlements(_ent(allowed_machines=frozenset({"win10_alpha_*"})))
    assert tasking(session).reschedule(10) is None
    assert src.status == "running"


@pytest.mark.parametrize("charset,readable", [("utf-7", False), ("ISO-8859-1", True), ("utf_8", True), ("utf-8-sig", True)])
def test_bodies_in_another_charset_are_left_unread(charset, readable):
    # DRF decodes with the declared charset ("rout+AGU-" is "route" in UTF-7); this reading wouldn't.
    from django.test import RequestFactory

    from lib.tenancy.middleware import _extract_submission_params

    req = RequestFactory().post("/apiv2/tasks/create/url/", b'{"route":"tor","rout+AGU-":"internet"}', content_type=f"application/json; charset={charset}")
    assert bool(_extract_submission_params(req)) is readable


def test_logged_out_users_reach_the_login_redirect_of_admin_views(monkeypatch):
    monkeypatch.setattr("lib.tenancy.middleware.multitenancy_config", lambda: types.SimpleNamespace(enabled=True))

    def statistics_data(request, days):
        pass

    anonymous = ViewerContext(user_id=None, tenant_id=None, is_authenticated=False)
    assert _status(_mw(anonymous).process_view(_req("/statistics/7/"), statistics_data, (), {"days": 7})) is None


def test_the_scoped_dashboard_cache_stays_bounded():
    from lib.tenancy.context import set_current_viewer
    from lib.tenancy.hooks import _ViewerScopedCacheFunction

    fn = _ViewerScopedCacheFunction(lambda: None)
    for uid in range(1000):
        set_current_viewer(_viewer(uid, 1))
        fn.cache = uid
    assert len(fn._caches) <= 256 and fn.cache == 999


@pytest.mark.parametrize("route", ["vpn0", "socks_ch", "tun5", "", "none", "inetsim"])
def test_the_sslproxy_table_lookup_matches_sslproxy_itself(monkeypatch, route):
    # The exemption is only safe while it agrees with modules/auxiliary/SSLProxy.py.
    from lib.tenancy.resources import _sslproxy_rt_table

    sslproxy = pytest.importorskip("modules.auxiliary.SSLProxy")

    class Routing:
        routing = types.SimpleNamespace(route="vpn0", rt_table="main")
        vpn0 = types.SimpleNamespace(rt_table="tun0")

        def get(self, name):
            return getattr(self, name)

    monkeypatch.setattr("lib.cuckoo.common.config.Config", lambda name: Routing())
    monkeypatch.setattr(sslproxy, "Config", lambda name: Routing())
    monkeypatch.setattr(sslproxy, "sslproxy_cfg", types.SimpleNamespace(cfg={}), raising=False)
    thread = sslproxy.SSLProxyThread(types.SimpleNamespace(id=1, route=route), types.SimpleNamespace(resultserver_port=2042))
    assert _sslproxy_rt_table(route) == thread.rt_table


def _reader_mw():
    from lib.tenancy.policy import PUBLIC, ResourceScope

    return TenancyMiddleware(
        lambda r: None, viewer_resolver=lambda u: _viewer(8, 2),
        task_scope_resolver=lambda t: ResourceScope(owner_id=7, tenant_id=1, visibility=PUBLIC), recovery_target_resolver=lambda t: None,
    )


def _mt_on(monkeypatch, **kw):
    from lib.tenancy import policy

    cfg = policy.MTConfig(enabled=True, mode="shared", default_visibility="", local_admins_manage_all_tenants=True, **kw)
    monkeypatch.setattr("lib.tenancy.middleware.multitenancy_config", lambda: cfg)


def test_on_demand_processing_needs_manage_rights_under_multitenancy(monkeypatch):
    # on_demand runs a service and writes its output into the task's stored report.
    def on_demand(request, service, task_id, category, sha256):
        pass

    req = _req(f"/analysis/on_demand/bingraph/1/static/{'a' * 64}/")
    kwargs = {"service": "bingraph", "task_id": 1, "category": "static", "sha256": "a" * 64}
    monkeypatch.setattr("lib.tenancy.middleware.multitenancy_config", lambda: types.SimpleNamespace(enabled=False))
    assert _status(_reader_mw().process_view(req, on_demand, (), kwargs)) is None  # stock behaviour when off
    _mt_on(monkeypatch)
    assert _status(_reader_mw().process_view(req, on_demand, (), kwargs)) == 404


def test_posting_a_comment_needs_manage_rights_unless_readers_may_comment(monkeypatch):
    def comments(request, task_id):
        pass

    _mt_on(monkeypatch)
    req = _req("/analysis/1/comments/")
    assert _status(_reader_mw().process_view(req, comments, (), {"task_id": 1})) is None
    req.method = "POST"
    assert _status(_reader_mw().process_view(req, comments, (), {"task_id": 1})) == 404
    _mt_on(monkeypatch, readers_can_comment=True)
    assert _status(_reader_mw().process_view(req, comments, (), {"task_id": 1})) is None


def test_duplicate_check_only_counts_tasks_the_submitter_can_see(db, private_task):
    # unique=1 refused another tenant's sample as "Duplicated file" (an existence oracle), and the
    # submitter could never see the analysis it pointed them at.
    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy.context import set_current_viewer
    from lib.tenancy.hooks import register_core_hooks

    _, sha256 = private_task
    register_core_hooks()
    set_current_viewer(_viewer(user_id=8, tenant_id=2))
    try:
        with db.session.begin():
            assert not db.check_file_uniq(sha256)
            assert not db.check_file_uniq(sha256, hours=24)
        set_current_viewer(_viewer(user_id=7, tenant_id=1))
        with db.session.begin():
            assert db.check_file_uniq(sha256)
            assert db.check_file_uniq(sha256, hours=24)
        set_current_viewer(None)
        with db.session.begin():
            assert db.check_file_uniq(sha256)
    finally:
        core_hooks.clear_all_hooks()


def test_audit_framework_is_admin_only_under_multitenancy(monkeypatch):
    # Test sessions are deployment-wide: any tenant could reload, queue or delete them.
    def audit_index(request, page=1):
        pass

    monkeypatch.setattr("lib.tenancy.middleware.multitenancy_config", lambda: types.SimpleNamespace(enabled=False))
    assert _status(_mw(_viewer(8, 2)).process_view(_req("/audit/"), audit_index, (), {})) is None
    _mt_on(monkeypatch)
    assert _status(_mw(_viewer(8, 2)).process_view(_req("/audit/"), audit_index, (), {})) == 403
    admin = ViewerContext(user_id=1, tenant_id=None, is_superuser=True, is_local_admin=True, is_authenticated=True)
    assert _status(_mw(admin).process_view(_req("/audit/"), audit_index, (), {})) is None
    # The audit views skip their login check under ANON_VIEW: anonymous is denied too.
    assert _status(_mw(ViewerContext.anonymous()).process_view(_req("/audit/"), audit_index, (), {})) == 403


def test_a_tenant_scoped_superuser_is_not_a_trusted_submitter():
    # With local_admins_manage_all_tenants = no a superuser is tenant-scoped; the docs say dist-only
    # attributes (main_task_id, task_acl) and ui-<id> job ids need that flag.
    from lib.tenancy.context import set_current_viewer
    from lib.tenancy.hooks import _trusted_submitter

    scoped_super = ViewerContext(user_id=1, tenant_id=2, is_superuser=True, is_local_admin=False, is_authenticated=True)
    set_current_viewer(scoped_super)
    try:
        assert not _trusted_submitter()
    finally:
        set_current_viewer(None)
    assert _trusted_submitter()


def test_tenancy_registers_the_own_report_query_hook(monkeypatch):
    from lib.cuckoo.common import hooks as core_hooks
    from lib.tenancy.acl import own_report_es_query, own_report_mongo_query
    from lib.tenancy.hooks import register_core_hooks

    assert core_hooks.task_report_query(5) is None  # stock: callers keep their info.id lookup
    register_core_hooks()
    try:
        # Object storage alone also bootstraps tenancy; with multitenancy off the lookup stays stock.
        monkeypatch.setattr("lib.tenancy.hooks.multitenancy_config", lambda: types.SimpleNamespace(enabled=False))
        assert core_hooks.task_report_query(5) is None
        monkeypatch.setattr("lib.tenancy.hooks.multitenancy_config", lambda: types.SimpleNamespace(enabled=True))
        assert core_hooks.task_report_query(5) == own_report_mongo_query(5)
        assert core_hooks.task_report_query(5, "es") == own_report_es_query(5)
    finally:
        core_hooks.clear_all_hooks()


def test_comments_write_to_the_tasks_own_report_by_document_id():
    # The comment was written with update_one({"info.id": N}): in a shared report store that is the
    # oldest doc with that id, possibly another tenant's report the commenter cannot read.
    pytest.importorskip("django")
    import os
    import subprocess
    import sys

    script = """
import sys
sys.path[:0] = [".", "web"]
import django
from django.conf import settings
settings.configure(WEB_AUTHENTICATION=False, CUCKOO_PATH=".", COMMENTS=True, ANON_VIEW=False, ALLOW_DL_REPORTS_TO_ALL=False,
    MOLOCH_ENABLED=False, MOLOCH_BASE="", MOLOCH_NODE="", HUNT_ENABLED=False, REPROCESS_TASKS=False, ZIP_PWD=b"infected",
    TEMP_PATH="/tmp", STATIC_URL="/static/", RATELIMIT_ERROR_MSG="", NOCAPTCHA=True, TWOFA=False,
    INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes"],
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}})
django.setup()
from django.test import RequestFactory
from lib.cuckoo.common import hooks
import analysis.views as v

hooks.register_task_report_query_hook(lambda tid, store: {"own": tid, "store": store})
hooks.register_es_filter(lambda body: dict(body, scoped=True))
reads, writes, es_bodies, es_writes = [], [], [], []
v.mongo_find_one = lambda c, q, p=None, **kw: reads.append(q) or {"_id": "oid-own", "info": {"comments": []}}
v.mongo_update_one = lambda c, q, u, **kw: writes.append(q)
v.redirect = lambda *a, **k: "ok"
v.settings.COMMENTS = True
req = RequestFactory().post("/analysis/5/comments/", {"commentbox": "hi"})
v.enabledconf["mongodb"], v.es_as_db = True, False
assert v.comments(req, 5) == "ok"
assert reads == [{"own": 5, "store": "mongo"}], reads
assert writes == [{"_id": "oid-own"}], writes

class FakeES:
    def search(self, index, body=None, **kw):
        es_bodies.append(body)
        return {"hits": {"hits": [{"_source": {"info": {}}, "_id": "es-own", "_index": "idx"}]}}
    def update(self, index, id, body):
        es_writes.append((index, id))
v.es, v.es_as_db, v.enabledconf["mongodb"] = FakeES(), True, False
v.get_analysis_index = lambda: "cape-analysis-*"
assert v.comments(req, 5) == "ok"
assert es_bodies == [{"query": {"own": 5, "store": "es"}, "scoped": True}], es_bodies
assert es_writes == [("idx", "es-own")], es_writes

# on_demand stores the service output into the task's own report.
reads.clear(); writes.clear()
v.enabledconf["mongodb"], v.es_as_db = True, False
v.CUSTOM_SERVICES = ["stubsvc"]
v.ObjectId = lambda oid: oid  # imported only when reporting.conf enables mongodb
v.handle_custom_service = lambda service, task_id, sha256: ({"x": 1}, "stubsvc")
v.mongo_find_one = lambda c, q, p=None, **kw: reads.append(q) or {"_id": "507f1f77bcf86cd799439011"}
v.render = lambda request, template, ctx=None, **kw: ("render", ctx)
out = v.on_demand(RequestFactory().get("/"), "stubsvc", "5", "static", "a" * 64)
assert reads == [{"own": 5, "store": "mongo"}], reads
assert len(writes) == 1 and str(writes[0]["_id"]) == "507f1f77bcf86cd799439011", (writes, out)
"""
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    res = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"STDOUT: {res.stdout}\nSTDERR: {res.stderr[-3000:]}"
