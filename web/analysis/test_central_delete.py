"""central_delete_analysis deletes ONLY the caller's OWN doc in central mode (adversarial-review HIGH).

Single-node: delegates to mongo_delete_data (unchanged). Central: the delete key is the SHARED
central_own_analysis_filter(task_id) = {info.job_id: 'ui-<task_id>'} -- globally unique, DERIVED from the
authorized task_id (never read from custom, never the read viewer_scope), so it can't be steered to another
task's doc and can't collide with a worker-local doc. It does NOT depend on the SQL row still existing (the
apiv2 routes delete the relational row first). Deletes by _id + own call chunks by ObjectId, never by the
bare task_id. Fail-closed: no own doc -> nothing deleted.
"""


class _Req:
    def __init__(self, user):
        self.user = user


def _central(monkeypatch, enabled):
    monkeypatch.setattr(
        "lib.cuckoo.common.central_mode.central_mode_config",
        lambda: type("C", (), {"enabled": enabled})(),
    )


def _mongo_matches(doc, flt):
    """Minimal $and/$or/$in/dotted-key evaluator (None matches missing)."""
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


def test_delete_central_uses_unique_jobid_key_and_deletes_by_id(monkeypatch):
    import analysis.central_views as cv

    _central(monkeypatch, True)
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

    assert captured["f"] == {"info.job_id": "ui-5"}, captured["f"]  # shared derived unique key
    assert ("calls", {"_id": {"$in": ["c1", "c2", "c3"]}}) in deletes   # calls by ObjectId
    assert ("analysis", {"_id": "OID_ANALYSIS"}) in deletes             # analysis by _id
    assert not any(d[0] == "MDD" for d in deletes), "must not fall back to unscoped mongo_delete_data"
    assert not any(d[0] == "calls" and "task_id" in d[1] for d in deletes), "must never delete calls by bare task_id"


def test_delete_central_key_excludes_forged_victim_and_needs_no_sql_row(monkeypatch):
    """The HIGH: the derived unique key can't be steered to another task's doc (no forged-custom pivot), and
    -- unlike a tenant-derived filter -- it does NOT depend on the SQL row still existing, so the apiv2 routes
    that delete the relational row before the Mongo cleanup still address the right doc."""
    import analysis.central_views as cv

    _central(monkeypatch, True)
    captured = {}
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one",
                        lambda coll, q, proj=None: captured.__setitem__("f", q), raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_many", lambda *a, **k: None, raising=False)

    cv.central_delete_analysis(_Req(object()), 500)  # attacker's own task
    f = captured["f"]
    assert f == {"info.job_id": "ui-500"}
    assert _mongo_matches({"info": {"job_id": "ui-500"}}, f), "own doc matches"
    assert not _mongo_matches({"info": {"id": 42, "job_id": "ui-42", "tenant_id": 9, "visibility": "public"}}, f), \
        "a victim's doc for a DIFFERENT task must NOT match (unique derived key, no custom/read-scope pivot)"


def test_delete_central_fail_closed_when_no_own_doc(monkeypatch):
    import analysis.central_views as cv

    _central(monkeypatch, True)
    monkeypatch.setattr("dev_utils.mongodb.mongo_find_one", lambda coll, q, proj=None: None, raising=False)  # no match
    deletes = []
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_many", lambda coll, q: deletes.append((coll, q)), raising=False)
    monkeypatch.setattr("dev_utils.mongodb.mongo_delete_data", lambda tid: deletes.append(("MDD", tid)), raising=False)

    cv.central_delete_analysis(_Req(object()), 9)

    assert deletes == [], "fail-closed: nothing deleted on the Mongo side when no own doc resolves"
