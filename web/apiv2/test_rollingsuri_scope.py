"""tasks_rollingsuri constrains its aggregate feed to the viewer's tenant in central mode (MEDIUM).

The feed pulls every recent analysis doc, then keeps rows by numeric SQL-task-id membership -- which in
central mode does NOT prove a Mongo doc belongs to that SQL task (a colliding worker-local doc for
another tenant, same info.id, would ride the caller's visible-id set and leak its alerts). So in central
mode the Mongo query must AND the viewer's tenant scope; single-node / break-glass is unchanged
(viewer_scope returns None). tasks_rollingsuri is a DRF @api_view, so drive it with APIRequestFactory.
"""
import pytest
from django.contrib.auth.models import User

pytest_plugins = ("mt_test_fixtures",)


class _Viewer:
    is_local_admin = False


def _run(monkeypatch, user, *, central, scope):
    import apiv2.views as views
    from rest_framework.test import APIRequestFactory, force_authenticate

    captured = {}

    def _mongo_find(coll, flt, proj, **k):
        captured["coll"] = coll
        captured["filter"] = flt
        return []  # empty feed -- we only assert the query shape (the DB does the actual $match)

    # mongo_find is module-imported only under `if repconf.mongodb.enabled` (absent in the test config);
    # tasks_rollingsuri resolves it as a module global at call time, so inject it (raising=False).
    monkeypatch.setattr(views, "mongo_find", _mongo_find, raising=False)
    monkeypatch.setattr(views, "viewer_for", lambda u: _Viewer())
    monkeypatch.setattr(views, "apiconf", type("A", (), {"rollingsuri": {"enabled": True, "maxwindow": 0}})())
    monkeypatch.setattr("lib.cuckoo.common.central_mode.central_mode_config", lambda: type("C", (), {"enabled": central})())
    monkeypatch.setattr("analysis.central_scope.viewer_scope", lambda u: scope)

    req = APIRequestFactory().get("/apiv2/tasks/rollingsuri/60/")
    force_authenticate(req, user=user)
    resp = views.tasks_rollingsuri(req, window=60)
    return captured, resp


@pytest.mark.django_db
def test_rollingsuri_scoped_in_central_mode(cape_db, monkeypatch):
    u = User.objects.create_user("rs1", "rs1@x.com", "x")
    scope = {"info.tenant_id": 7}
    captured, _ = _run(monkeypatch, u, central=True, scope=scope)
    assert captured["coll"] == "analysis"
    # the base recency predicate is ANDed with the viewer's tenant scope so foreign-tenant docs drop
    assert "$and" in captured["filter"], captured["filter"]
    assert scope in captured["filter"]["$and"], captured["filter"]


@pytest.mark.django_db
def test_rollingsuri_bare_query_single_node(cape_db, monkeypatch):
    u = User.objects.create_user("rs2", "rs2@x.com", "x")
    captured, _ = _run(monkeypatch, u, central=False, scope=None)
    assert "$and" not in captured["filter"]
    assert captured["filter"].get("suricata.alerts") == {"$exists": True}


@pytest.mark.django_db
def test_rollingsuri_central_break_glass_not_scoped(cape_db, monkeypatch):
    # central ON but viewer_scope None (break-glass / see-all) -> no tenant $match added
    u = User.objects.create_user("rs3", "rs3@x.com", "x")
    captured, _ = _run(monkeypatch, u, central=True, scope=None)
    assert "$and" not in captured["filter"]
    assert captured["filter"].get("suricata.alerts") == {"$exists": True}
