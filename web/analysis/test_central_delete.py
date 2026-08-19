"""central_delete_analysis deletes ONLY the caller's OWN doc in central mode (adversarial-review HIGH).

Single-node: delegates to mongo_delete_data (unchanged). Central: the delete key is the SHARED
the SHARED, bridge-aware central_own_analysis_filter(task_id, task.tenant) -- ui-only under central+MT, or the
three-arm {ui- OR info.id} form single-node/MT-off -- derived from the authorized task_id (never custom /
never the read viewer_scope), so it can't be steered to another task's doc and excludes a foreign doc stamped
for another tenant. The apiv2 routes resolve the tenant while the SQL row exists and pass it, running the
Mongo delete after the SQL delete commits. Deletes by _id + own call chunks by ObjectId, never by the bare
task_id. A 0-match is LOGGED, not a silent "success".
"""
import logging


class _Req:
    def __init__(self, user):
        self.user = user


def _central(monkeypatch, enabled):
    monkeypatch.setattr(
        "lib.cuckoo.common.central_mode.central_mode_config",
        lambda: type("C", (), {"enabled": enabled})(),
    )


def _fake_db(tenant_id):
    class _DB:
        def view_task(self, tid):
            return type("T", (), {"tenant_id": tenant_id})()
    return _DB


def _mongo_matches(doc, flt):
    if "$and" in flt:
        return all(_mongo_matches(doc, s) for s in flt["$and"])
    if "$or" in flt:
        return any(_mongo_matches(doc, s) for s in flt["$or"])
    for key, want in flt.items():
        cur = doc
        for part in key.split("."):
            cur = cur.get(part) if isinstance(cur, dict) else None
        if isinstance(want, dict) and "$in" in want:
            if cur not in want["$in"]:
                return False
        elif cur != want:
            return False
    return True


def test_delete_non_central_delegates_to_mongo_delete_data(monkeypatch):
    import analysis.central_views as cv

    _central(monkeypatch, False)
    seen = {}
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_data", lambda tid: seen.setdefault("tid", tid), raising=False)
    cv.central_delete_analysis(_Req(object()), 7)
    assert seen == {"tid": 7}  # single-node path unchanged


def test_delete_central_scopes_to_own_doc_and_deletes_by_id(monkeypatch):
    import analysis.central_views as cv

    _central(monkeypatch, True)
    monkeypatch.setattr("lib.cuckoo.core.database.Database", _fake_db(10), raising=False)
    captured = {}
    doc = {"_id": "OID_ANALYSIS", "behavior": {"processes": [{"calls": ["c1", "c2"]}, {"calls": ["c3"]}]}}

    def _find(coll, q, proj=None):
        captured["f"] = q
        return doc

    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", _find, raising=False)
    deletes = []
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_many", lambda coll, q: deletes.append((coll, q)), raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_data", lambda tid: deletes.append(("MDD", tid)), raising=False)

    cv.central_delete_analysis(_Req(object()), 5)

    f = captured["f"]
    assert _mongo_matches({"info": {"id": 5, "job_id": "ui-5", "tenant_id": 10}}, f), "own bridged matches"
    assert _mongo_matches({"info": {"id": 5, "job_id": "local-5", "tenant_id": 10}}, f), "own direct-submit matches"
    assert not _mongo_matches({"info": {"id": 5, "job_id": "ui-5", "tenant_id": 77}}, f), "foreign-stamped excluded"
    assert ("calls", {"_id": {"$in": ["c1", "c2", "c3"]}}) in deletes   # calls by ObjectId
    assert ("analysis", {"_id": "OID_ANALYSIS"}) in deletes             # analysis by _id
    assert not any(d[0] == "MDD" for d in deletes), "must not fall back to unscoped mongo_delete_data"
    assert not any(d[0] == "calls" and "task_id" in d[1] for d in deletes), "must never delete calls by bare task_id"


def test_delete_central_excludes_forged_victim(monkeypatch):
    """A forged custom / colliding foreign doc for a DIFFERENT task must NOT be selectable by the delete."""
    import analysis.central_views as cv

    _central(monkeypatch, True)
    monkeypatch.setattr("lib.cuckoo.core.database.Database", _fake_db(10), raising=False)
    captured = {}
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one",
                        lambda coll, q, proj=None: captured.__setitem__("f", q), raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_many", lambda *a, **k: None, raising=False)

    cv.central_delete_analysis(_Req(object()), 500)  # attacker's own task
    f = captured["f"]
    assert not _mongo_matches({"info": {"id": 42, "job_id": "ui-42", "tenant_id": 9, "visibility": "public"}}, f), \
        "a victim's PUBLIC doc for a DIFFERENT task must NOT match (unique derived key, no custom/read-scope pivot)"
    assert _mongo_matches({"info": {"id": 500, "job_id": "ui-500", "tenant_id": 10}}, f), "own doc still matches"


def test_delete_central_zero_match_logs_and_deletes_nothing(monkeypatch, caplog):
    import analysis.central_views as cv

    _central(monkeypatch, True)
    monkeypatch.setattr("lib.cuckoo.core.database.Database", _fake_db(10), raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", lambda coll, q, proj=None: None, raising=False)  # no match
    deletes = []
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_many", lambda coll, q: deletes.append((coll, q)), raising=False)

    with caplog.at_level(logging.WARNING):
        cv.central_delete_analysis(_Req(object()), 9)

    assert deletes == [], "fail-closed: nothing deleted Mongo-side when no own doc resolves"
    assert any("no own analysis doc matched" in r.getMessage() for r in caplog.records), \
        "a 0-match delete must be LOGGED, not a silent success (SQL row + tree already gone)"


def test_delete_central_passed_tenant_skips_view_task(monkeypatch):
    """The apiv2 delete routes reorder the Mongo delete to AFTER the SQL delete (so a delete_folder failure
    can't destroy the report while the task survives), which means view_task would return None by then. They
    pass the tenant resolved BEFORE the SQL delete via tenant_id=; when it is passed, central_delete_analysis
    must NOT consult the DB at all."""
    import analysis.central_views as cv

    _central(monkeypatch, True)

    def _boom(*a, **k):
        raise AssertionError("view_task consulted despite an explicit tenant_id")

    monkeypatch.setattr("lib.cuckoo.core.database.Database", _boom, raising=False)
    captured = {}
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one",
                        lambda coll, q, proj=None: captured.__setitem__("f", q), raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_many", lambda *a, **k: None, raising=False)

    cv.central_delete_analysis(_Req(object()), 5, tenant_id=10)
    f = captured["f"]
    assert _mongo_matches({"info": {"id": 5, "job_id": "ui-5", "tenant_id": 10}}, f), "own doc still matches"
    assert not _mongo_matches({"info": {"id": 5, "job_id": "local-5"}}, f), \
        "a foreign UNSTAMPED colliding doc must NOT match (tenant guard uses the passed tenant)"


def test_delete_central_tenant_lookup_failure_fails_closed(monkeypatch, caplog):
    """When tenant_id is NOT passed (the web remove() caller) and the guarded view_task raises (RDS blip), the
    delete fails closed -- logs and leaves Mongo untouched -- rather than 500-ing mid-delete."""
    import logging
    import analysis.central_views as cv

    _central(monkeypatch, True)

    class _DB:
        def view_task(self, tid):
            raise RuntimeError("central RDS pool exhausted")

    monkeypatch.setattr("lib.cuckoo.core.database.Database", _DB, raising=False)
    deletes = []
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one",
                        lambda *a, **k: deletes.append("find") or None, raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_many", lambda *a, **k: deletes.append("del"), raising=False)

    with caplog.at_level(logging.ERROR):
        cv.central_delete_analysis(_Req(object()), 9)

    assert deletes == [], "fail-closed: no Mongo read/delete when the tenant can't be resolved"
    assert any("tenant lookup failed" in r.getMessage() for r in caplog.records)
