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


def _matches(doc, flt):
    """Minimal MongoDB-filter evaluator: $and / $or / dotted-key equality (None = null).
    Lets the tests assert the SEMANTICS of central_analysis_query (which docs it returns)
    rather than a brittle structural match."""
    if "$and" in flt:
        return all(_matches(doc, s) for s in flt["$and"])
    if "$or" in flt:
        return any(_matches(doc, s) for s in flt["$or"])
    for key, want in flt.items():
        cur = doc
        for part in key.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if cur != want:
            return False
    return True


def test_central_analysis_query_bridged_authorizes(monkeypatch):
    """Bridged task (RDS-derived job_id): key off unique info.job_id, but AUTHORIZE against the
    viewer scope OR the authorized owner's not-yet-reconciled doc. The unstamped arm is constrained
    to THIS task (info.id == task_id) so a forged job_id can't ride it to another task's doc."""
    import analysis.central_views as cv
    monkeypatch.setattr(cv, "central_job_id_for_task", lambda tid: "ui-5")
    scope = {"info.tenant_id": 10}
    q = cv.central_analysis_query(7, scope=scope)
    assert q == {"$and": [{"info.job_id": "ui-5"},
                          {"$or": [scope, {"$and": [{"info.tenant_id": None}, {"info.id": 7}]}]}]}, q


def test_central_analysis_query_forged_jobid_cannot_read_unstamped_cross_tenant(monkeypatch):
    """Adversarial-review HIGH: attacker in tenant A forges the victim's job_id via their own
    task's `custom`. The victim's doc is UNSTAMPED (tenant_id null, not-yet-reconciled) and belongs
    to a DIFFERENT task (info.id=42) than the attacker's authorized task (999). The constrained
    null arm (info.id == 999) must NOT match the victim doc -> no cross-tenant leak."""
    import analysis.central_views as cv
    monkeypatch.setattr(cv, "central_job_id_for_task", lambda tid: "ui-42")
    q = cv.central_analysis_query(999, scope={"info.tenant_id": "A"})
    victim = {"info": {"job_id": "ui-42", "id": 42, "tenant_id": None},
              "signatures": ["victim-secret-behaviour"]}
    assert not _matches(victim, q), "forged job_id read a different task's unstamped cross-tenant doc"


def test_central_analysis_query_owner_unstamped_still_resolves(monkeypatch):
    """No owner-lockout: the legit owner viewing their OWN not-yet-reconciled bridged task (doc
    re-keyed to the central id, so info.id == task_id) still resolves via the constrained null arm."""
    import analysis.central_views as cv
    monkeypatch.setattr(cv, "central_job_id_for_task", lambda tid: "ui-42")
    q = cv.central_analysis_query(42, scope={"info.tenant_id": "A"})
    own = {"info": {"job_id": "ui-42", "id": 42, "tenant_id": None}}
    assert _matches(own, q), "owner locked out of their own not-yet-reconciled doc"


def test_central_analysis_query_forged_jobid_stamped_denied(monkeypatch):
    """Control: a forged job_id at another tenant's STAMPED doc fails the scope arm too."""
    import analysis.central_views as cv
    monkeypatch.setattr(cv, "central_job_id_for_task", lambda tid: "ui-42")
    q = cv.central_analysis_query(999, scope={"info.tenant_id": "A"})
    victim_stamped = {"info": {"job_id": "ui-42", "id": 42, "tenant_id": "B"}}
    assert not _matches(victim_stamped, q), "forged job_id read another tenant's stamped doc"


def test_central_analysis_query_bridged_no_scope_is_bare(monkeypatch):
    """No scope (see-all / break-glass / MT-off): bare info.job_id, no restriction."""
    import analysis.central_views as cv
    monkeypatch.setattr(cv, "central_job_id_for_task", lambda tid: "ui-5")
    assert cv.central_analysis_query(7, scope=None) == {"info.job_id": "ui-5"}


def test_central_analysis_query_nonbridged_is_scoped(monkeypatch):
    """Non-bridged task (no RDS job_id): fall back to info.id ANDed with the viewer scope
    (defence-in-depth against cross-store id collision)."""
    import analysis.central_views as cv
    monkeypatch.setattr(cv, "central_job_id_for_task", lambda tid: None)
    scope = {"info.tenant_id": 10}
    assert cv.central_analysis_query(7, scope=scope) == {"$and": [{"info.id": 7}, scope]}


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
