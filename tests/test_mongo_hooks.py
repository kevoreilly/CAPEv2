import pytest

from dev_utils import mongo_hooks


@pytest.fixture
def files_collection(monkeypatch):
    docs = {}

    def fake_find(collection, query, projection=None):
        assert collection == mongo_hooks.FILES_COLL
        return [dict(docs[k], _id=k) for k in query["_id"]["$in"] if k in docs]

    monkeypatch.setattr(mongo_hooks, "mongo_find", fake_find)
    return docs


def test_denormalize_restores_normalized_fields(files_collection):
    files_collection["aa"] = {"sha256": "aa", "size": 10, "type": "data", "yara": []}
    report = {"target": {"file": {"file_ref": "aa", "name": "sample.bin"}}}
    mongo_hooks.denormalize_files(report)
    assert report["target"]["file"] == {"name": "sample.bin", "sha256": "aa", "size": 10, "type": "data", "yara": []}


def test_denormalize_keeps_the_tasks_own_results(files_collection):
    # the submission preview stored its shellcode check (no payload extraction) in the shared document;
    # this task's processing extracted the payload, and its own result must be what the report shows
    preview = {"verdict": "shellcode", "frameworks": [{"name": "Donut"}]}
    task = dict(preview, extracted=[{"sha256": "bb", "framework": "Donut"}])
    files_collection["aa"] = {"sha256": "aa", "size": 10, "static_shellcode_check": preview, "die": ["preview only"]}
    report = {"target": {"file": {"file_ref": "aa", "static_shellcode_check": task}}}
    mongo_hooks.denormalize_files(report)
    file_info = report["target"]["file"]
    assert file_info["static_shellcode_check"]["extracted"] == [{"sha256": "bb", "framework": "Donut"}]
    assert file_info["size"] == 10 and file_info["die"] == ["preview only"]  # fields only the shared document has still come back
    assert "file_ref" not in file_info
