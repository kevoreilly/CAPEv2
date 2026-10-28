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
    from rest_framework.decorators import api_view

    task_id, _ = private_task

    @api_view(["POST"])
    def tasks_delete_many(request):
        pass

    assert tasks_delete_many.__name__ == "view"

    req = lambda: _post_req("/apiv2/tasks/delete_many/", ids=f"{task_id}")  # noqa: E731
    assert _status(_mw(_viewer(8, 2)).process_view(req(), tasks_delete_many, (), {})) == 404
    assert _mw(_viewer(7, 1)).process_view(req(), tasks_delete_many, (), {}) is None


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
    mw.get_response = lambda request: mw.process_view(request, tasks_view, (), {"task_id": task_id})
    mw(req)
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


def test_visibility_endpoint_authenticates_like_the_api():
    # The middleware serves /apiv2/tasks/visibility/ before URL routing, so neither DRF auth (API
    # keys) nor CsrfViewMiddleware ever ran: key holders got 404, session callers skipped CSRF.
    pytest.importorskip("django")
    pytest.importorskip("rest_framework")
    import os
    import subprocess
    import sys

    script = """
import json
import django
from django.conf import settings
settings.configure(
    INSTALLED_APPS=["django.contrib.auth", "django.contrib.contenttypes", "rest_framework"],
    DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
    DEFAULT_AUTO_FIELD="django.db.models.BigAutoField",
    REST_FRAMEWORK={"DEFAULT_AUTHENTICATION_CLASSES": ["__main__.HeaderKeyAuth"]},
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

rf = RequestFactory()
out = {
    "api_key": call(rf.post("/apiv2/tasks/visibility/42/", {"visibility": "public"}, HTTP_AUTHORIZATION="Token good"), AnonymousUser()),
    "bad_key": call(rf.post("/apiv2/tasks/visibility/42/", {"visibility": "public"}, HTTP_AUTHORIZATION="Token nope"), AnonymousUser()),
    "session_no_csrf": call(rf.post("/apiv2/tasks/visibility/42/", {"visibility": "public"}),
                            types.SimpleNamespace(id=10, is_authenticated=True, is_superuser=False)),
}
print(json.dumps(out))
"""
    env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
    res = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env)
    assert res.returncode == 0, f"STDOUT: {res.stdout}\nSTDERR: {res.stderr}"
    import json

    assert json.loads(res.stdout.strip().splitlines()[-1]) == {"api_key": 200, "bad_key": 403, "session_no_csrf": 403}
