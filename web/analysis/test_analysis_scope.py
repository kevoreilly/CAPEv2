"""web/analysis report-UI reads route through the central-scoped analysis filter (adversarial-review HIGH).

report() was hardened against a central+MT cross-store info.id collision: a colliding worker-local
analysis doc for another tenant (reconcile-skipped / direct-submit / seeded) can shadow another tenant's
central task id in the shared DocumentDB. The rest of the per-task report-UI readers (load_files, chunk,
filtered_chunk, antivirus, suri*, search_behavior, procdump, comments, on_demand, the ETW/signature-call
helpers) key the SAME analysis collection by a bare {info.id}, so they must use the same scoped filter.
_scoped_analysis_query is the shared seam; these lock its contract:
  - single-node / central OFF: bare info.id (behaviour unchanged)
  - central ON: central_analysis_query(task_id, scope=viewer_scope(user)) -- viewer scope ANDed onto the
    non-bridged info.id fallback, so a colliding foreign doc can't surface
  - extra= (reads keyed on more than info.id, e.g. a process_id): AND-merged so the sub-document target is
    preserved WITHOUT dropping the collision defence
  - central ON + viewer_scope errors: MUST propagate (fail-closed), never a bare/unscoped read
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


def test_scoped_query_bare_infoid_when_central_off(monkeypatch):
    from analysis.views import _scoped_analysis_query

    _central(monkeypatch, False)
    assert _scoped_analysis_query(_Req(object()), "7") == {"info.id": 7}


def test_scoped_query_bare_infoid_with_extra_when_central_off(monkeypatch):
    from analysis.views import _scoped_analysis_query

    _central(monkeypatch, False)
    q = _scoped_analysis_query(_Req(object()), 7, {"behavior.processes.process_id": 4})
    assert q == {"$and": [{"info.id": 7}, {"behavior.processes.process_id": 4}]}


def test_scoped_query_uses_central_query_when_central_on(monkeypatch):
    from analysis.views import _scoped_analysis_query

    _central(monkeypatch, True)
    scope = {"info.tenant_id": 10}
    seen = {}

    def _vs(user):
        seen["user"] = user
        return scope

    def _caq(task_id, scope=None):
        seen["caq"] = (task_id, scope)
        return {"info.job_id": "ui-5"}

    monkeypatch.setattr("analysis.central_scope.viewer_scope", _vs)
    monkeypatch.setattr("analysis.central_views.central_analysis_query", _caq)

    user = object()
    q = _scoped_analysis_query(_Req(user), 7)
    assert seen["user"] is user           # scope resolved for the caller
    assert seen["caq"] == (7, scope)      # viewer scope threaded into the central query
    assert q == {"info.job_id": "ui-5"}   # scoped filter, not {"info.id": 7}


def test_scoped_query_central_on_with_extra_and_merges(monkeypatch):
    from analysis.views import _scoped_analysis_query

    _central(monkeypatch, True)
    monkeypatch.setattr("analysis.central_scope.viewer_scope", lambda u: {"info.tenant_id": 1})
    monkeypatch.setattr("analysis.central_views.central_analysis_query", lambda tid, scope=None: {"info.job_id": "ui-5"})

    q = _scoped_analysis_query(_Req(object()), 7, {"behavior.processes.process_id": 9})
    # the central (scoped) filter is preserved AND the sub-document constraint is ANDed on -- a colliding
    # foreign doc still can't surface even though the read keys on more than info.id
    assert q == {"$and": [{"info.job_id": "ui-5"}, {"behavior.processes.process_id": 9}]}


def test_scoped_query_fail_closed_when_scope_errors(monkeypatch):
    """viewer_scope raising (a real MT resolution failure) MUST propagate -- never be swallowed into a
    bare, unscoped {info.id} read that would serve a colliding foreign doc."""
    from analysis.views import _scoped_analysis_query

    _central(monkeypatch, True)

    def _boom(user):
        raise RuntimeError("scope resolution failed")

    monkeypatch.setattr("analysis.central_scope.viewer_scope", _boom)
    monkeypatch.setattr("analysis.central_views.central_analysis_query", lambda *a, **k: {"info.id": 999})
    with pytest.raises(RuntimeError):
        _scoped_analysis_query(_Req(object()), 7)
