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


def test_job_id_for_task_prefers_rds(monkeypatch):
    """RDS-authorized job_id resolves WITHOUT any mongo lookup (collision-free +
    stamping-independent) — mongo must not be consulted when it's present."""
    import lib.cuckoo.common.artifact_storage as a
    a._JOB_ID_CACHE.clear()
    monkeypatch.setattr(a, "_rds_job_id", lambda tid: "ui-42")

    def boom(*x, **k):
        raise AssertionError("mongo consulted despite an RDS-authorized job_id")
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", boom, raising=False)
    assert a._job_id_for_task(42, scope={"info.tenant_id": 1}) == "ui-42"


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
