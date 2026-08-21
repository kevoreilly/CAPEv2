"""apiv2 report-family reads route through the central-scoped analysis filter (adversarial-review HIGH).

report()/central_analysis_query hardened the web report view against a cross-store info.id collision: in
central+MT a colliding worker-local doc for another tenant (reconcile-skipped / direct-submit / seeded)
can shadow another tenant's central task id in the shared DocumentDB. The parallel apiv2 report-family
reads (tasks_view / tasks_iocs / tasks_config / selfextract) key the SAME shared analysis collection, so
they must use the same scoped filter -- otherwise a tenant-A caller's GET on their own task id could
surface tenant B's colliding doc (detections, CAPE config, certs, IOCs). _analysis_filter is the shared
seam; these lock its contract:
  - single-node / central OFF: bare info.id (behaviour unchanged)
  - central ON: central_analysis_query(task_id, scope=viewer_scope(user)) -- the viewer scope is ANDed
    onto the non-bridged info.id fallback, so a colliding foreign doc can't surface
  - central ON + viewer_scope errors: MUST propagate (fail-closed), never fall back to an unscoped read
"""
import pytest


class _Req:
    def __init__(self, user):
        self.user = user


def _central(monkeypatch, enabled):
    monkeypatch.setattr(
        "lib.cuckoo.common.central_mode.central_mode_config",
        lambda: type("C", (), {"enabled": enabled})(),
    )


def test_analysis_filter_bare_infoid_when_central_off(monkeypatch):
    # Single-node / non-central: unchanged bare info.id (and str task_id coerced to int).
    import apiv2.views as views

    _central(monkeypatch, False)
    assert views._analysis_filter(_Req(object()), "7") == {"info.id": 7}


def test_analysis_filter_uses_scoped_central_query_when_central_on(monkeypatch):
    # Central ON: delegate to central_analysis_query with the caller's viewer scope threaded in.
    import apiv2.views as views

    _central(monkeypatch, True)
    scope = {"info.tenant_id": 10}
    seen = {}

    def _vs(user):
        seen["user"] = user
        return scope

    def _caq(task_id, scope=None):
        seen["caq"] = (task_id, scope)
        return {"$and": [{"info.job_id": "ui-5"}, {"$or": [scope, {"$and": [{"info.tenant_id": None}, {"info.id": task_id}]}]}]}

    monkeypatch.setattr("analysis.central_scope.viewer_scope", _vs)
    monkeypatch.setattr("analysis.central_views.central_analysis_query", _caq)

    user = object()
    q = views._analysis_filter(_Req(user), 7)
    assert seen["user"] is user            # scope resolved for the caller, not a bare read
    assert seen["caq"] == (7, scope)       # viewer scope threaded into the central query
    assert q == _caq(7, scope)             # returns the scoped filter (not {"info.id": 7})


def test_analysis_filter_fail_closed_when_scope_errors(monkeypatch):
    """viewer_scope raising (a real MT resolution failure) MUST propagate -- never be swallowed into a
    bare, unscoped {info.id} read that would serve a colliding foreign doc. Mirrors central_scope's
    fail-closed contract (test_viewer_scope_fail_closed_on_runtime_error)."""
    import apiv2.views as views

    _central(monkeypatch, True)

    def _boom(user):
        raise RuntimeError("scope resolution failed")

    monkeypatch.setattr("analysis.central_scope.viewer_scope", _boom)
    # If the helper wrongly swallowed the error it would fall to a bare read; central_analysis_query
    # returning a bare-looking filter here would let such a regression pass silently -- so assert raise.
    monkeypatch.setattr("analysis.central_views.central_analysis_query", lambda *a, **k: {"info.id": 999})
    with pytest.raises(RuntimeError):
        views._analysis_filter(_Req(object()), 7)
