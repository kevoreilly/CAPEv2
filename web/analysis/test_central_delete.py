"""central_delete_analysis deletes ONLY the caller's OWN doc in central mode (adversarial-review HIGH).

Single-node: delegates to mongo_delete_data (unchanged). Central: the delete key is DERIVED from the
authorized task_id (ui-<task_id> / info.id==task_id, ANDed with the task's own tenant) -- NOT read from the
forgeable task.custom and NOT gated on the READ viewer_scope (whose public/tenant arms match OTHER owners'
docs). It deletes the resolved doc by _id + its own call chunks by ObjectId, never by the bare task_id.
Fail-closed: no own doc -> nothing deleted.
"""


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
    """Minimal $and/$or/$in/dotted-key evaluator (None matches missing) -- so the derived delete filter can
    be asserted at the document level."""
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


def test_delete_central_derives_filter_from_task_id_and_deletes_by_id(monkeypatch):
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

    # the filter is DERIVED from the authorized task_id (ui-5 / info.id 5), not read from custom:
    assert _mongo_matches({"info": {"id": 5, "job_id": "ui-5", "tenant_id": None}}, captured["f"]), "own doc must match"
    assert ("calls", {"_id": {"$in": ["c1", "c2", "c3"]}}) in deletes   # calls by ObjectId, gathered from the doc
    assert ("analysis", {"_id": "OID_ANALYSIS"}) in deletes             # analysis by _id (the resolved doc)
    assert not any(d[0] == "MDD" for d in deletes), "must not fall back to unscoped mongo_delete_data"
    assert not any(d[0] == "calls" and "task_id" in d[1] for d in deletes), "must never delete calls by bare task_id"


def test_delete_central_filter_excludes_forged_victim_doc(monkeypatch):
    """The HIGH: a forged custom must NOT let the delete select another task's doc. The filter keys on the
    AUTHORIZED task_id, so a victim's PUBLIC doc for a DIFFERENT task (and a same-tenant other-owner doc)
    can't be matched -- regardless of what custom said or what the read scope would allow."""
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
        "a PUBLIC victim doc for a DIFFERENT task must NOT match the delete filter (no forged-custom pivot)"
    assert not _mongo_matches({"info": {"id": 42, "job_id": "ui-42", "tenant_id": 10, "visibility": "tenant"}}, f), \
        "a same-tenant other-owner doc for a different task must NOT match either"
    assert _mongo_matches({"info": {"id": 500, "job_id": "ui-500", "tenant_id": None}}, f), "own doc still matches"


def test_delete_central_fail_closed_when_no_own_doc(monkeypatch):
    import analysis.central_views as cv

    _central(monkeypatch, True)
    monkeypatch.setattr("lib.cuckoo.core.database.Database", _fake_db(10), raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", lambda coll, q, proj=None: None, raising=False)  # no match
    deletes = []
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_many", lambda coll, q: deletes.append((coll, q)), raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_data", lambda tid: deletes.append(("MDD", tid)), raising=False)

    cv.central_delete_analysis(_Req(object()), 9)

    assert deletes == [], "fail-closed: nothing deleted on the Mongo side when no own doc resolves"
