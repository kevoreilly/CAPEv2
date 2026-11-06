"""Tests for the conditional _id hint in dev_utils.mongodb.

No MongoDB instance is required: the pymongo collection is stubbed and only the
hint application logic is asserted.
"""

import types
import pytest


# --------------------------------------------------------------- _id hint selection


@pytest.mark.parametrize(
    "query,expected",
    [
        ({"_id": 1}, [("_id", 1)]),
        ({"$and": [{"_id": 1}, {"info.tenant_id": "t"}]}, [("_id", 1)]),
        # These used to get the _id hint too, which forced a full _id index scan.
        ({"info.id": 7}, None),
        ({"info.job_id": "ui-7"}, None),
        ({"$and": [{"info.job_id": "ui-7"}, {"info.tenant_id": "t"}]}, None),
        ({}, None),
        (None, None),
    ],
)
def test_id_hint_only_applies_to_id_filters(query, expected):
    from dev_utils.mongodb import _id_hint

    assert _id_hint(query) == expected


def test_id_hint_only_applied_on_empty_query():
    from dev_utils.mongodb import _id_hint

    assert _id_hint({"_id": 1}) == [("_id", 1)]
    assert _id_hint({"$and": [{"_id": 1}]}) == [("_id", 1)]
    assert _id_hint({"info.id": 1}) is None
    assert _id_hint({"info.job_id": 1}) is None
    assert _id_hint({}) is None
    assert _id_hint(None) is None


def test_delete_and_update_one_hint_application(monkeypatch):
    import dev_utils.mongodb as dm

    recorded_calls = []

    class _FakeColl:
        def delete_one(self, query, hint=None):
            recorded_calls.append(("delete_one", query, hint))
            return True

        def update_one(self, query, update, bypass_document_validation=False, upsert=False, hint=None):
            recorded_calls.append(("update_one", query, update, upsert, hint))
            return True

    monkeypatch.setattr(dm, "results_db", types.SimpleNamespace(analysis=_FakeColl()))

    # delete_one with _id query uses hint
    dm.mongo_delete_one("analysis", {"_id": 123})
    assert recorded_calls[-1] == ("delete_one", {"_id": 123}, [("_id", 1)])

    # delete_one with non-_id query omits hint
    dm.mongo_delete_one("analysis", {"info.id": 123})
    assert recorded_calls[-1] == ("delete_one", {"info.id": 123}, None)

    # update_one with _id query and not upsert uses hint
    dm.mongo_update_one("analysis", {"_id": 123}, {"$set": {"a": 1}}, upsert=False)
    assert recorded_calls[-1] == ("update_one", {"_id": 123}, {"$set": {"a": 1}}, False, [("_id", 1)])

    # update_one with upsert=True omits hint even on _id
    dm.mongo_update_one("analysis", {"_id": 123}, {"$set": {"a": 1}}, upsert=True)
    assert recorded_calls[-1] == ("update_one", {"_id": 123}, {"$set": {"a": 1}}, True, None)

    # update_one with non-_id query omits hint
    dm.mongo_update_one("analysis", {"info.job_id": "test"}, {"$set": {"a": 1}})
    assert recorded_calls[-1] == ("update_one", {"info.job_id": "test"}, {"$set": {"a": 1}}, False, None)
