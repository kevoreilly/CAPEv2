"""Central-mode task_id -> job_id resolution (lib.cuckoo.common.artifact_storage).

The staging/serving resolver must PREFER the RDS-authorized job_id (from the task's
custom field — collision-free and independent of the tenancy reconcile) so an authorized
OWNER isn't locked out of a fail-closed/unstamped doc, and only fall back to the scoped
mongo info.id lookup for non-bridged tasks (defence-in-depth against cross-store id
collision).
"""


def test_job_id_from_custom():
    from lib.cuckoo.common.artifact_storage import job_id_from_custom
    assert job_id_from_custom("job_id=ui-5,foo=bar") == "ui-5"   # only the job_id= value
    assert job_id_from_custom("job_id=ui-9") == "ui-9"
    assert job_id_from_custom("ui-3") == "ui-3"                  # bare token (non-bridged)
    assert job_id_from_custom("foo=bar") is None
    assert job_id_from_custom(None) is None
    assert job_id_from_custom("") is None


def test_rds_job_id_nonnumeric_not_logged_as_rds_failure(monkeypatch, caplog):
    """A non-numeric task_id (the filereport/full_memory \\w+ routes) is bad INPUT, not an
    RDS error: _rds_job_id returns None silently and must NOT emit the ERROR-level
    "RDS lookup failed" traceback (which would flood logs + mask real pool-exhaustion)."""
    import logging
    import sys
    import types
    import lib.cuckoo.common.artifact_storage as a

    fake = types.ModuleType("lib.cuckoo.core.database")

    class _DB:
        def view_task(self, tid):
            return types.SimpleNamespace(custom="job_id=ui-1")
    fake.Database = _DB
    monkeypatch.setitem(sys.modules, "lib.cuckoo.core.database", fake)
    with caplog.at_level(logging.ERROR, logger=a.log.name):
        assert a._rds_job_id("abc") is None
    assert not [r for r in caplog.records if "RDS lookup failed" in r.getMessage()], \
        [r.getMessage() for r in caplog.records]


def test_job_id_for_task_rds_no_scope_skips_mongo(monkeypatch):
    """RDS job_id + no scope (see-all/break-glass): return it directly, no mongo verify."""
    import lib.cuckoo.common.artifact_storage as a
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: "ui-42")

    def boom(*x, **k):
        raise AssertionError("mongo consulted on the unscoped RDS path")
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", boom, raising=False)
    assert a._job_id_for_task(42, scope=None) == "ui-42"


def test_job_id_for_task_rds_scoped_authorizes(monkeypatch):
    """RDS job_id + scope: the resolved doc must pass a per-call authorization (in scope OR
    unstamped). job_id is from user custom, so it is NOT trusted blindly."""
    import lib.cuckoo.common.artifact_storage as a
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: "ui-42")
    seen = {}

    def find(coll, q, proj):
        seen["q"] = q
        return {"_id": 1}  # authorized: doc in scope-or-unstamped
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", find, raising=False)
    scope = {"info.tenant_id": 7}
    assert a._job_id_for_task(42, scope=scope) == "ui-42"
    assert seen["q"] == {"$and": [{"info.job_id": "ui-42"}, {"$or": [scope, {"info.tenant_id": None}]}]}


def test_job_id_for_task_rds_forged_denied(monkeypatch):
    """A FORGED custom job_id pointing at another tenant's STAMPED doc fails the per-call
    authorization (the authq matches nothing) -> Http404, not a cross-tenant serve."""
    import lib.cuckoo.common.artifact_storage as a
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: "ui-victim")
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", lambda *x, **k: None, raising=False)
    import pytest
    from django.http import Http404
    with pytest.raises(Http404):
        a._job_id_for_task(9, scope={"info.tenant_id": 7})


def test_job_id_for_task_fallback_scoped(monkeypatch):
    """Non-bridged (no RDS job_id): fall back to the mongo info.id lookup ANDed with the
    viewer scope (the cross-store id-collision defence)."""
    import lib.cuckoo.common.artifact_storage as a
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: None)
    seen = {}

    def fake_find(coll, query, proj):
        seen["query"] = query
        return {"info": {"job_id": "wl-9"}}
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", fake_find, raising=False)
    scope = {"info.tenant_id": 3}
    assert a._job_id_for_task(9, scope=scope) == "wl-9"
    assert seen["query"] == {"$and": [{"info.id": 9}, scope]}, seen["query"]
