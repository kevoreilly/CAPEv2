"""Tenancy-optional central scope shim (web/analysis/central_scope.py).

Verifies the three deployment states (MT layer absent / present+disabled / present+
enabled) collapse to the right scope, AND the security-critical FAIL-CLOSED contract:
when the MT layer IS deployed, a RUNTIME error in the scope/visibility resolution must
PROPAGATE — never be swallowed into a see-all result (which would silently bypass tenant
isolation). The shim catches ImportError ONLY (= MT layer not deployed); these tests lock
that down so a later broad-`except` regression is caught.
"""
import builtins

import pytest

from analysis.central_scope import viewer_scope, viewer_can_view_sample


def _hide(monkeypatch, modname):
    """Force `import <modname>` to raise ImportError, simulating an MT-free deployment
    REGARDLESS of whether the module physically exists — so the MT-absent behavior can be
    exercised on both an MT-present (fork) build and an MT-absent (upstream) build."""
    real_import = builtins.__import__

    def fake(name, *a, **k):
        if name == modname or name.startswith(modname + "."):
            raise ImportError(f"simulated-absent: {modname}")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)


def test_viewer_scope_mt_layer_absent_is_see_all(monkeypatch):
    # MT layer not deployed: `from dashboard.views import entitled_scope_filter` raises
    # ImportError -> see-all (None). Hide the module so this holds on any build.
    _hide(monkeypatch, "dashboard.views")
    assert viewer_scope(object()) is None


def test_viewer_scope_delegates_when_mt_present(monkeypatch):
    # Delegation is only meaningful when the MT layer is deployed (entitled_scope_filter lives
    # in the MT-only dashboard.views surface); skip on an MT-free upstream build.
    pytest.importorskip("users.tenancy")
    sentinel = {"$or": [{"info.tenant_slug": "acme"}]}
    monkeypatch.setattr("dashboard.views.entitled_scope_filter", lambda user: sentinel, raising=False)
    assert viewer_scope(object()) is sentinel


def test_viewer_scope_fail_closed_on_runtime_error(monkeypatch):
    # MT deployed but resolution blows up at runtime -> MUST propagate, not see-all.
    pytest.importorskip("users.tenancy")

    def boom(user):
        raise RuntimeError("scope resolution failed")

    monkeypatch.setattr("dashboard.views.entitled_scope_filter", boom, raising=False)
    with pytest.raises(RuntimeError):
        viewer_scope(object())


def test_viewer_can_view_sample_mt_layer_absent_is_true(monkeypatch):
    _hide(monkeypatch, "users.tenancy")
    assert viewer_can_view_sample(object(), sha256="abc") is True


def test_viewer_can_view_sample_delegates_when_mt_present(monkeypatch):
    pytest.importorskip("users.tenancy")
    seen = {}

    def fake(user, *, sha256=None, sha1=None, md5=None, sample_id=None):
        seen.update(sha256=sha256, sha1=sha1, md5=md5, sample_id=sample_id)
        return False

    monkeypatch.setattr("users.tenancy.can_view_sample", fake)
    assert viewer_can_view_sample(object(), sha256="deadbeef") is False
    assert seen == {"sha256": "deadbeef", "sha1": None, "md5": None, "sample_id": None}


def test_viewer_can_view_sample_fail_closed_on_runtime_error(monkeypatch):
    pytest.importorskip("users.tenancy")

    def boom(user, **kw):
        raise RuntimeError("visibility check failed")

    monkeypatch.setattr("users.tenancy.can_view_sample", boom)
    with pytest.raises(RuntimeError):
        viewer_can_view_sample(object(), sha256="abc")
