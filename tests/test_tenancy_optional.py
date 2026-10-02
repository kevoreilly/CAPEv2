import builtins
import pytest
from lib.cuckoo.common import tenancy_optional as topt


def _hide(monkeypatch, modname):
    real_import = builtins.__import__
    def fake(name, *a, **k):
        if name == modname or name.startswith(modname + "."):
            raise ImportError(f"simulated-absent: {modname}")
        return real_import(name, *a, **k)
    monkeypatch.setattr(builtins, "__import__", fake)


def test_lib_facade_present_delegates(monkeypatch):
    # MT present: multitenancy_config() returns the real config object (has .enabled)
    cfg = topt.multitenancy_config()
    assert hasattr(cfg, "enabled")


def test_lib_facade_absent_is_see_all(monkeypatch):
    _hide(monkeypatch, "lib.cuckoo.common.tenancy")
    assert topt.multitenancy_config().enabled is False
    assert topt.viewer_for(object()).is_local_admin is True
    assert topt.scope_match("acme", topt.viewer_for(object())) is None


def test_web_facade_absent_is_see_all(monkeypatch):
    _hide(monkeypatch, "users.tenancy")
    from web.tenancy_optional import can_view_task, can_view_sample, submission_scope, can_ban_user, PUBLIC
    assert can_view_task(object(), object()) is True
    assert can_view_sample(object(), sha256="x") is True
    # submission_scope MUST return a 2-tuple (callers unpack it); single-tenant -> (None, public)
    assert submission_scope(object()) == (None, PUBLIC)
    _tid, _vis = submission_scope(object())  # unpack like the real callers do
    assert (_tid, _vis) == (None, "public")
    # can_ban_user is the ONE facade that must NOT degrade to see-all: the ban_user /
    # ban_all_user_tasks views gate SOLELY on it, so the MT-absent fallback preserves
    # upstream's staff/superuser-only boundary (a see-all True would let any authenticated
    # user ban accounts on a single-node build). Deny a plain user; allow staff/superuser.
    class _Plain:
        is_staff = False
        is_superuser = False

    class _Staff:
        is_staff = True
        is_superuser = False

    class _Super:
        is_staff = False
        is_superuser = True

    assert can_ban_user(_Plain(), 1) is False
    assert can_ban_user(_Staff(), 1) is True
    assert can_ban_user(_Super(), 1) is True


def test_web_facade_entitled_scope_filter_absent(monkeypatch):
    _hide(monkeypatch, "dashboard.views")
    from web.tenancy_optional import viewer_scope_filter
    assert viewer_scope_filter(object()) is None


def test_web_facade_fail_closed_on_runtime_error(monkeypatch):
    # Fail-closed is an MT-present contract: with the MT layer deployed, a runtime error in the
    # authz backend must PROPAGATE (never degrade to see-all). Skip on an MT-free upstream build.
    ut = pytest.importorskip("users.tenancy")
    def boom(*a, **k):
        raise RuntimeError("authz backend down")
    monkeypatch.setattr(ut, "can_view_task", boom)
    from web.tenancy_optional import can_view_task
    with pytest.raises(RuntimeError):
        can_view_task(object(), object())
