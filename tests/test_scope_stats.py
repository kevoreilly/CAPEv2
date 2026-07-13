import time


def test_statistics_helpers_merge_scope_match(monkeypatch):
    import lib.cuckoo.common.web_utils as wu
    captured = {}

    def fake_agg(coll, cmd):
        captured["cmd"] = cmd
        return []

    monkeypatch.setattr(wu, "mongo_aggregate", fake_agg, raising=False)
    # Bypass config guards so mongo_aggregate is reached in the test environment.
    monkeypatch.setattr(wu.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(wu.web_cfg.general, "top_detections", True)
    # Clear any cached result so the aggregation actually runs.
    if hasattr(wu.top_detections, "cache"):
        del wu.top_detections.cache
    wu.top_detections(date_since=False, scope_match={"info.tenant_id": 10, "info.visibility": "tenant"})
    first_match = captured["cmd"][0]["$match"]
    assert first_match.get("info.tenant_id") == 10 and first_match.get("info.visibility") == "tenant"


def test_top_detections_scoped_bypasses_cache(monkeypatch):
    """Scoped calls must never read from or write to the shared time-keyed cache."""
    import lib.cuckoo.common.web_utils as wu

    call_count = {"n": 0}

    def counting_agg(coll, cmd):
        call_count["n"] += 1
        return []

    monkeypatch.setattr(wu, "mongo_aggregate", counting_agg, raising=False)
    monkeypatch.setattr(wu.repconf.mongodb, "enabled", True)
    monkeypatch.setattr(wu.web_cfg.general, "top_detections", True)

    # Plant a fresh-looking stale sentinel in the cache so an unguarded read would return it.
    stale_data = [{"sentinel": 1}]
    wu.top_detections.cache = (time.time(), stale_data)

    scope = {"info.tenant_id": 10, "info.visibility": "tenant"}

    # First scoped call: must NOT return the sentinel and must have called the aggregation.
    result1 = wu.top_detections(date_since=False, scope_match=scope)
    assert result1 != stale_data, "scoped call returned stale cached data from the shared cache"
    assert call_count["n"] == 1, "expected exactly one aggregation call after first scoped call"

    # Second scoped call: scoped path must not have populated the cache, so aggregation runs again.
    result2 = wu.top_detections(date_since=False, scope_match=scope)
    assert call_count["n"] == 2, "expected aggregation to run again (scoped calls must not populate cache)"

    # The shared cache must still hold the original sentinel (scoped calls never overwrite it).
    assert hasattr(wu.top_detections, "cache"), "cache attr should still exist"
    _, cached_val = wu.top_detections.cache
    assert cached_val == stale_data, "scoped call must not have overwritten the shared cache"


def test_static_config_lookup_scopes_mongo_query(monkeypatch):
    """Deep-hunt: the static-config dedup lookup must AND-in the submitter's scope
    so it can't return another tenant's task id / config-exists inference. Locked
    viewer -> query AND-ed with the scope $or; break-glass / disabled -> unscoped."""
    import lib.cuckoo.common.cape_utils as cu
    from lib.cuckoo.common.tenancy import Viewer, MTConfig
    import lib.cuckoo.common.tenancy as t

    captured = {}
    monkeypatch.setattr(cu, "mongo_find_one", lambda coll, q, proj, **k: captured.update(q=q) or None, raising=False)
    monkeypatch.setattr(cu.repconf.mongodb, "enabled", True)

    # locked, non-admin -> scoped
    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    cu.static_config_lookup("/x", sha256="a" * 64, viewer=Viewer(user_id=2, tenant_id=10))
    assert "$and" in captured["q"], "locked-mode dedup must AND-in the tenant scope"
    assert {"target.file.sha256": "a" * 64} in captured["q"]["$and"]

    # break-glass -> unscoped (plain query)
    cu.static_config_lookup("/x", sha256="a" * 64, viewer=Viewer(user_id=9, tenant_id=None, is_local_admin=True))
    assert captured["q"] == {"target.file.sha256": "a" * 64}

    # MT disabled -> unscoped
    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(False, "shared", "", True))
    cu.static_config_lookup("/x", sha256="a" * 64, viewer=Viewer(user_id=2, tenant_id=10))
    assert captured["q"] == {"target.file.sha256": "a" * 64}


def test_top_detections_es_branch_scoped(monkeypatch):
    """Deep-hunt: the ES top_detections branch must apply the viewer scope filter
    (parity with the mongo branch), or a locked tenant's stat panels show the
    global per-family malware landscape on an ES-backed install."""
    import lib.cuckoo.common.web_utils as wu
    from lib.cuckoo.common.tenancy import Viewer, MTConfig
    import lib.cuckoo.common.tenancy as t

    captured = {}
    monkeypatch.setattr(wu.repconf.mongodb, "enabled", False)
    monkeypatch.setattr(wu.repconf.elasticsearchdb, "enabled", True)
    monkeypatch.setattr(wu.web_cfg.general, "top_detections", True)
    monkeypatch.setattr(wu, "es", type("E", (), {"search": staticmethod(lambda **k: captured.update(body=k["body"]) or {"aggregations": {"family": {"buckets": []}}})}), raising=False)
    # get_analysis_index is imported only when ES is enabled at module load; the
    # test env loads with ES disabled, so provide it (production ES installs have it).
    monkeypatch.setattr(wu, "get_analysis_index", lambda: "idx", raising=False)
    if hasattr(wu.top_detections, "cache"):
        del wu.top_detections.cache

    monkeypatch.setattr(t, "multitenancy_config", lambda: MTConfig(True, "locked", "", True))
    wu.top_detections(date_since=False, viewer=Viewer(user_id=2, tenant_id=10))
    flt = captured["body"]["query"]["bool"].get("filter")
    assert flt, "ES top_detections must carry a tenant scope filter in locked mode"
    shoulds = flt[0]["bool"]["should"]
    assert {"term": {"info.visibility": "public"}} in shoulds and {"term": {"info.user_id": 2}} in shoulds
