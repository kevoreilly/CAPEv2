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


def test_insert_calls_sanitizes_keys_splits_large_chunks_and_falls_back_per_chunk(monkeypatch):
    from modules.reporting import report_doc

    # 1. Dict keys with invalid surrogates and NUL bytes are sanitized.
    sanitized = report_doc._sanitize_call_data({"bad\x00key\ud800": "ok", "good": "v"})
    assert "badkey?" in sanitized
    assert sanitized["good"] == "v"

    # 2. Oversized chunk splits below max_bytes.
    big_calls = [{"api": "WriteFile", "arg": "A" * 4000} for _ in range(6)]
    split_docs = report_doc._build_mongo_call_docs(123, 7, big_calls, max_bytes=10000)
    assert len(split_docs) > 1
    assert sum(len(d["calls"]) for d in split_docs) == 6

    # 3. BulkWriteError on chunk 1 keeps chunk 0's already-inserted _id and inserts chunk 2 individually.
    class _FakeBulkError(Exception):
        def __init__(self, details):
            super().__init__("bulk failure")
            self.details = details

    monkeypatch.setattr(report_doc, "CHUNK_CALL_SIZE", 1)
    call_log = []

    def fake_insert_many(coll, docs):
        call_log.append(len(docs))
        if len(docs) == 3:
            docs[0]["_id"] = "id-0"
            docs[1]["_id"] = "id-1"
            docs[2]["_id"] = "id-2"
            raise _FakeBulkError({"nInserted": 1, "writeErrors": [{"index": 1, "errmsg": "bad doc"}]})
        return types.SimpleNamespace(inserted_ids=[docs[0].get("_id") or "id-single"])

    monkeypatch.setattr(report_doc, "mongo_insert_many", fake_insert_many)
    report = {
        "info": {"id": 99},
        "behavior": {"processes": [{"process_id": 42, "calls": [{"a": 1}, {"a": 2}, {"a": 3}]}]},
    }
    procs = report_doc.insert_calls(report, mongodb=True)
    assert call_log == [3, 1]
    assert procs[0]["calls"] == ["id-0", "id-2"]


def test_sanitize_call_data_converts_non_string_keys_and_splits_without_double_truncation(monkeypatch):
    from bson import BSON

    from modules.reporting import report_doc

    # Non-string dict keys (int, tuple, None, bytes) must be converted to str so BSON.encode succeeds.
    raw = {
        1: "int-key",
        (2, 3): {"nested\x00": "ok"},
        None: "none-key",
        b"raw": "bytes-key",
    }
    sanitized = report_doc._sanitize_call_data(raw)
    assert set(sanitized.keys()) == {"1", "(2, 3)", "None", "b'raw'"}
    assert sanitized["(2, 3)"] == {"nested": "ok"}
    encoded = BSON.encode({"pid": 1, "calls": [sanitized], "task_id": 1})
    assert len(encoded) > 0

    # Recursive BSON chunk splitting must sanitize once and never double-truncate strings.
    monkeypatch.setattr(report_doc, "MAX_CALL_VALUE_LEN", 100)
    top_level_sanitize_calls = 0
    orig_sanitize = report_doc._sanitize_call_data

    def counting_sanitize(obj, max_len=None, bytes_to_str=False):
        nonlocal top_level_sanitize_calls
        if isinstance(obj, list):
            top_level_sanitize_calls += 1
        return orig_sanitize(obj, max_len=max_len, bytes_to_str=bytes_to_str)

    monkeypatch.setattr(report_doc, "_sanitize_call_data", counting_sanitize)

    oversized_val = "X" * 250
    calls_list = [{"api": "WriteFile", "buf": oversized_val} for _ in range(8)]
    docs = report_doc._build_mongo_call_docs(10, 20, calls_list, max_bytes=350)
    assert len(docs) > 1
    assert top_level_sanitize_calls == 1
    expected_val = ("X" * 100) + "...[truncated]"
    for doc in docs:
        for call in doc["calls"]:
            assert call["buf"] == expected_val
            assert call["buf"].count("...[truncated]") == 1


def test_insert_calls_wire_batches_and_preserves_duplicate_key_ids_on_fallback(monkeypatch):
    from modules.reporting import report_doc

    monkeypatch.setattr(report_doc, "CHUNK_CALL_SIZE", 1)
    monkeypatch.setattr(report_doc, "MAX_MONGO_BULK_BATCH_BYTES", 600)

    # 1. Multiple chunks exceeding MAX_MONGO_BULK_BATCH_BYTES are split into multiple wire batches.
    batch_sizes = []

    def fake_insert_many_batched(coll, docs):
        batch_sizes.append(len(docs))
        ids = []
        for idx, doc in enumerate(docs):
            doc_id = f"b{len(batch_sizes)}-{idx}"
            doc["_id"] = doc_id
            ids.append(doc_id)
        return types.SimpleNamespace(inserted_ids=ids)

    monkeypatch.setattr(report_doc, "mongo_insert_many", fake_insert_many_batched)
    report = {
        "info": {"id": 55},
        "behavior": {
            "processes": [
                {
                    "process_id": 7,
                    "calls": [{"api": "Send", "buf": "A" * 250} for _ in range(5)],
                }
            ]
        },
    }
    procs = report_doc.insert_calls(report, mongodb=True)
    assert len(batch_sizes) > 1
    assert sum(batch_sizes) == 5
    assert len(procs[0]["calls"]) == 5

    # 2. Fallback retry preserves pre-stamped _id when MongoDB raises E11000 (duplicate key).
    class _DupKeyDetailsError(Exception):
        def __init__(self):
            super().__init__("E11000 duplicate key")
            self.details = {"writeErrors": [{"code": 11000, "errmsg": "dup"}]}

    class _DupKeyCodeError(Exception):
        code = 11000

    monkeypatch.setattr(report_doc, "MAX_MONGO_BULK_BATCH_BYTES", 1024 * 1024)
    fallback_attempts = []

    def fake_insert_many_with_e11000(coll, docs):
        if len(docs) == 4:
            for i, d in enumerate(docs):
                d["_id"] = f"pre-{i}"
            raise RuntimeError("socket timeout after partial commit")
        doc_id = docs[0]["_id"]
        fallback_attempts.append(doc_id)
        if doc_id == "pre-0":
            raise _DupKeyDetailsError()
        if doc_id == "pre-1":
            raise _DupKeyCodeError()
        if doc_id == "pre-2":
            return types.SimpleNamespace(inserted_ids=[doc_id])
        raise RuntimeError("permanent non-duplicate error")

    monkeypatch.setattr(report_doc, "mongo_insert_many", fake_insert_many_with_e11000)
    report2 = {
        "info": {"id": 56},
        "behavior": {"processes": [{"process_id": 8, "calls": [{"a": i} for i in range(4)]}]},
    }
    procs2 = report_doc.insert_calls(report2, mongodb=True)
    assert fallback_attempts == ["pre-0", "pre-1", "pre-2", "pre-3"]
    assert procs2[0]["calls"] == ["pre-0", "pre-1", "pre-2"]
