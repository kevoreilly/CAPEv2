"""Tests for the batched call-chunk insert and the conditional _id hint.

No MongoDB instance is required: the pymongo collection is stubbed and only the
round-trip count, ordering and failure handling are asserted.
"""

import os
import sys

import pytest

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.insert(0, CUCKOO_ROOT)


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


# --------------------------------------------------------------- insert_calls batching


class _Result:
    def __init__(self, ids):
        self.inserted_ids = ids


def _report(ncalls, nproc=1):
    return {
        "info": {"id": 42},
        "behavior": {
            "processes": [
                {"process_id": 1000 + p, "process_name": f"p{p}.exe", "calls": [{"api": "A", "i": i} for i in range(ncalls)]}
                for p in range(nproc)
            ]
        },
    }


def _patch_insert(monkeypatch, impl):
    from modules.reporting import report_doc

    monkeypatch.setattr(report_doc, "mongo_insert_many", impl, raising=False)
    return report_doc


def test_insert_calls_batches_round_trips(monkeypatch):
    batches = []

    def fake(collection, docs, ordered=True):
        assert collection == "calls"
        assert ordered is False
        batches.append(len(docs))
        return _Result([f"id{len(batches)}-{i}" for i in range(len(docs))])

    report_doc = _patch_insert(monkeypatch, fake)

    # 50k calls / 100 per chunk = 500 chunks. Previously 500 round trips.
    out = report_doc.insert_calls(_report(50_000), mongodb=True)

    assert len(batches) == 3, batches  # 200 + 200 + 100
    assert batches == [200, 200, 100]
    assert len(out[0]["calls"]) == 500


def test_insert_calls_preserves_chunk_contents_and_order(monkeypatch):
    seen = []

    def fake(collection, docs, ordered=True):
        seen.extend(docs)
        return _Result([f"id{i}" for i in range(len(docs))])

    report_doc = _patch_insert(monkeypatch, fake)
    report = _report(250)
    report_doc.insert_calls(report, mongodb=True)

    assert [len(d["calls"]) for d in seen] == [100, 100, 50]
    assert [d["task_id"] for d in seen] == [42, 42, 42]
    assert [d["pid"] for d in seen] == [1000, 1000, 1000]
    # Calls arrive in their original order, split across chunks.
    flattened = [c["i"] for d in seen for c in d["calls"]]
    assert flattened == list(range(250))


def test_insert_calls_salvages_ids_when_part_of_a_batch_fails(monkeypatch):
    from pymongo.errors import BulkWriteError

    def fake(collection, docs, ordered=True):
        # pymongo assigns _id client side before sending, so the caller can recover
        # the ids of the documents that did land.
        for i, doc in enumerate(docs):
            doc["_id"] = f"oid{i}"
        raise BulkWriteError({"writeErrors": [{"index": 1}]})

    report_doc = _patch_insert(monkeypatch, fake)
    out = report_doc.insert_calls(_report(300), mongodb=True)

    # Three chunks submitted, the middle one rejected.
    assert out[0]["calls"] == ["oid0", "oid2"]


def test_insert_calls_handles_an_empty_call_log(monkeypatch):
    calls = []
    report_doc = _patch_insert(monkeypatch, lambda *a, **kw: calls.append(1) or _Result([]))

    out = report_doc.insert_calls(_report(0), mongodb=True)

    assert calls == []
    assert out[0]["calls"] == []
