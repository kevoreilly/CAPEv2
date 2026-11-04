"""Tests for the elasticsearchdb date_hook guard and the jsondump zip path.

No Elasticsearch instance is required: only the pure helpers are exercised.
"""

import json
import os
import sys
import zipfile
from datetime import datetime

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.insert(0, CUCKOO_ROOT)


def _hook():
    from modules.reporting.elasticsearchdb import ElasticSearchDB

    return ElasticSearchDB.__new__(ElasticSearchDB).date_hook


def _unguarded_hook(json_dict):
    """The previous implementation, for equivalence comparison."""
    from contextlib import suppress

    for key, value in json_dict.items():
        with suppress(Exception):
            json_dict[key] = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    return json_dict


SAMPLES = [
    "2024-01-01 10:00:00",
    "2024-1-1 0:0:0",
    "0001-01-01 00:00:00",
    "9999-12-31 23:59:59",
    "2024-01-01 10:00:00 ",
    " 2024-01-01 10:00:00",
    "2024-01-01T10:00:00",
    "2024-01-01",
    "10:00:00",
    "not a date",
    "C:\\Windows\\System32\\kernel32.dll",
    "0x41414141",
    "",
    "-",
    ":",
    "1-:",
]


def test_date_hook_matches_the_unguarded_version():
    hook = _hook()
    for s in SAMPLES:
        assert hook({"k": s}) == _unguarded_hook({"k": s}), s


def test_date_hook_still_converts_and_leaves_non_strings_alone():
    hook = _hook()
    out = hook({"started": "2024-01-01 10:00:00", "count": 5, "tags": ["a"], "nothing": None})
    assert out["started"] == datetime(2024, 1, 1, 10, 0, 0)
    assert out["count"] == 5
    assert out["tags"] == ["a"]
    assert out["nothing"] is None


def test_date_hook_runs_as_a_json_object_hook():
    hook = _hook()
    out = json.loads('{"a": {"b": "2024-01-01 10:00:00"}}', object_hook=hook)
    assert out["a"]["b"] == datetime(2024, 1, 1, 10, 0, 0)


def test_jsondump_store_compressed_writes_a_readable_zip(tmp_path):
    from modules.reporting.jsondump import JsonDump

    reports = tmp_path / "reports"
    reports.mkdir()

    rep = JsonDump.__new__(JsonDump)
    rep.reports_path = str(reports)
    rep.options = {"store_compressed": True, "indent": 4}

    rep.run({"info": {"id": 1}, "strings": ["a" * 1000]})

    zip_path = reports / "report.json.zip"
    assert zip_path.exists()
    with zipfile.ZipFile(zip_path) as zf:
        # Same entry name create_zip produced: "<reports dir>/report.json".
        assert zf.namelist() == ["reports/report.json"]
        assert json.loads(zf.read("reports/report.json"))["info"]["id"] == 1


def test_jsondump_without_store_compressed_writes_only_the_json(tmp_path):
    from modules.reporting.jsondump import JsonDump

    reports = tmp_path / "reports"
    reports.mkdir()

    rep = JsonDump.__new__(JsonDump)
    rep.reports_path = str(reports)
    rep.options = {}

    rep.run({"info": {"id": 2}})

    assert (reports / "report.json").exists()
    assert not (reports / "report.json.zip").exists()


def test_insert_calls_elastic_sanitizes_bytes_for_json_serialization(monkeypatch):
    from modules.reporting import report_doc

    captured_docs = []

    def fake_parallel_bulk(client, actions):
        for action in actions:
            # Must be directly JSON-serializable without default=str.
            json.dumps(action)
            captured_docs.append(action)
            yield True, {"index": {"_id": "chunk-1"}}

    monkeypatch.setattr(report_doc, "parallel_bulk", fake_parallel_bulk, raising=False)
    monkeypatch.setattr(report_doc, "get_daily_calls_index", lambda: "calls-idx", raising=False)

    report = {
        "info": {"id": 42},
        "behavior": {
            "processes": [
                {
                    "process_id": 1000,
                    "calls": [{"api": "NtWriteFile", "raw": b"\x80\x81"}],
                }
            ]
        },
    }
    new_procs = report_doc.insert_calls(report, elastic_db=object())
    assert new_procs[0]["calls"] == ["chunk-1"]
    assert captured_docs[0]["_source"]["calls"][0]["raw"] == "b'\\x80\\x81'"
