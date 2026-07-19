"""central_delete_analysis scopes the Mongo delete to the caller in central mode (adversarial-review MEDIUM).

Single-node: delegates to mongo_delete_data (unchanged). Central: deletes ONLY the caller's scope-matched
analysis doc (by _id) + its own call chunks (by ObjectId), NEVER by the bare task_id -- so a colliding
tenant's analysis/calls doc is not destroyed. Fail-closed: no scope-matched doc -> nothing deleted.
"""


class _Req:
    def __init__(self, user):
        self.user = user


def _central(monkeypatch, enabled):
    monkeypatch.setattr(
        "lib.cuckoo.common.central_mode.central_mode_config",
        lambda: type("C", (), {"enabled": enabled})(),
    )


def test_delete_non_central_delegates_to_mongo_delete_data(monkeypatch):
    import analysis.central_views as cv

    _central(monkeypatch, False)
    seen = {}
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_data", lambda tid: seen.setdefault("tid", tid), raising=False)
    cv.central_delete_analysis(_Req(object()), 7)
    assert seen == {"tid": 7}  # single-node path unchanged


def test_delete_central_scopes_analysis_by_id_and_calls_by_objectid(monkeypatch):
    import analysis.central_views as cv

    _central(monkeypatch, True)
    monkeypatch.setattr(cv, "scoped_analysis_query", lambda request, tid: {"info.job_id": "ui-5"})
    doc = {"_id": "OID_ANALYSIS", "behavior": {"processes": [{"calls": ["c1", "c2"]}, {"calls": ["c3"]}]}}
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", lambda coll, q, proj=None: doc, raising=False)
    deletes = []
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_many", lambda coll, q: deletes.append((coll, q)), raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_data", lambda tid: deletes.append(("MDD", tid)), raising=False)

    cv.central_delete_analysis(_Req(object()), 5)

    assert ("calls", {"_id": {"$in": ["c1", "c2", "c3"]}}) in deletes   # calls by ObjectId, gathered from the doc
    assert ("analysis", {"_id": "OID_ANALYSIS"}) in deletes             # analysis by _id (the scope-matched doc)
    assert not any(d[0] == "MDD" for d in deletes), "must not fall back to unscoped mongo_delete_data"
    assert not any(d[0] == "calls" and "task_id" in d[1] for d in deletes), "must never delete calls by bare task_id"


def test_delete_central_fail_closed_when_no_scoped_doc(monkeypatch):
    import analysis.central_views as cv

    _central(monkeypatch, True)
    monkeypatch.setattr(cv, "scoped_analysis_query", lambda request, tid: {"info.job_id": "ui-9"})
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", lambda coll, q, proj=None: None, raising=False)  # no match
    deletes = []
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_many", lambda coll, q: deletes.append((coll, q)), raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_data", lambda tid: deletes.append(("MDD", tid)), raising=False)

    cv.central_delete_analysis(_Req(object()), 9)

    assert deletes == [], "fail-closed: nothing deleted on the Mongo side when no scope-matched doc resolves"
