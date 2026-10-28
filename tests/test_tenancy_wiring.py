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
    from lib.tenancy.bootstrap import bootstrap_tenancy

    _broken_hooks(monkeypatch)
    with pytest.raises(RuntimeError, match="multitenancy"):
        bootstrap_tenancy(_cfg(multitenancy=True))


def test_bootstrap_storage_only_failure_is_logged_not_raised(monkeypatch):
    from lib.tenancy.bootstrap import bootstrap_tenancy

    _broken_hooks(monkeypatch)
    assert bootstrap_tenancy(_cfg(object_storage=True)) is False


def test_bootstrap_activates_for_legacy_central_mode(monkeypatch):
    import lib.tenancy.hooks as tenancy_hooks
    from lib.tenancy.bootstrap import bootstrap_tenancy

    calls = []
    monkeypatch.setattr(tenancy_hooks, "register_core_hooks", lambda: calls.append(1))
    assert bootstrap_tenancy(_cfg(central_mode=True)) is True
    assert calls == [1]
    assert bootstrap_tenancy(_cfg(multitenancy=False, object_storage=False)) is False
