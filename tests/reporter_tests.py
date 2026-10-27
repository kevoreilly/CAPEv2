# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


from lib.cuckoo.common.abstracts import Report


class ReportMock(Report):
    def run(self, data):
        return


class ReportAlterMock(Report):
    """Corrupts results dict."""

    def run(self, data):
        data["foo"] = "notbar"


def test_mongodb_operation_failure_prunes_all_processtree_entries(monkeypatch):
    from unittest.mock import MagicMock

    from pymongo.errors import OperationFailure

    import modules.reporting.mongodb as mongodb_mod

    calls = []

    def fake_insert_one(collection, doc):
        calls.append(
            [
                dict(entry)
                for entry in doc.get("behavior", {}).get("processtree", [])
                if isinstance(entry, dict)
            ]
        )
        if len(calls) == 1:
            raise OperationFailure("BSONObj size too large", code=15)
        return MagicMock()

    monkeypatch.setattr(mongodb_mod, "mongo_insert_one", fake_insert_one)

    report = {
        "info": {"id": 989477},
        "behavior": {
            "processtree": [
                {"pid": 100, "children": [{"pid": 101}]},
                {"pid": 200, "children": [{"pid": 201}]},
            ]
        },
    }

    try:
        mongodb_mod.mongo_insert_one("analysis", report)
    except OperationFailure as e:
        if e.code in (10334, 15):
            processtree = report.get("behavior", {}).get("processtree") or []
            for proc_entry in processtree:
                if isinstance(proc_entry, dict):
                    proc_entry.pop("children", None)
            mongodb_mod.mongo_insert_one("analysis", report)

    assert len(calls) == 2
    assert "children" not in report["behavior"]["processtree"][0]
    assert "children" not in report["behavior"]["processtree"][1]


def test_jsondump_and_dump_iocs_handle_surrogate_strings(tmp_path, monkeypatch):
    import json
    from lib.cuckoo.common import iocs as iocs_mod
    from modules.reporting.jsondump import JsonDump

    surrogate_name = "\udc8f\udce0\udcae_sample.txt"
    results = {
        "info": {"id": 101},
        "malscore": 0.0,
        "detections": [],
        "dropped": [
            {
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "guest_paths": [surrogate_name],
            }
        ],
    }

    dumper = JsonDump()
    dumper.reports_path = str(tmp_path)
    dumper.options = {"indent": 2}
    dumper.run(results)

    report_file = tmp_path / "report.json"
    assert report_file.is_file()
    parsed_report = json.loads(report_file.read_text(encoding="utf-8"))
    assert len(parsed_report["dropped"][0]["guest_paths"]) == 1

    analysis_reports = tmp_path / "storage" / "analyses" / "101" / "reports"
    analysis_reports.mkdir(parents=True)
    monkeypatch.setattr(iocs_mod, "CUCKOO_ROOT", str(tmp_path))
    iocs_mod.dump_iocs(results, task_id=101)

    iocs_file = analysis_reports / "iocs.json"
    assert iocs_file.is_file()
    parsed_iocs = json.loads(iocs_file.read_text(encoding="utf-8"))
    assert len(parsed_iocs["dropped"][0]["guest_paths"]) == 1


def test_mongodb_ensure_schema_caches_and_raises_on_mismatch(monkeypatch):
    import pytest
    from lib.cuckoo.common.exceptions import CuckooReportError
    import modules.reporting.mongodb as mongodb_mod

    # Fresh state
    monkeypatch.setattr(mongodb_mod.MongoDB, "_schema_checked", False)
    finds = []
    inserts = []
    monkeypatch.setattr(mongodb_mod, "mongo_find_one", lambda coll, query, proj: finds.append((coll, query, proj)) or None)
    monkeypatch.setattr(mongodb_mod, "mongo_insert_one", lambda coll, doc: inserts.append((coll, doc)) or True)

    mongodb_mod.MongoDB._ensure_schema()
    assert mongodb_mod.MongoDB._schema_checked is True
    assert len(finds) == 1
    assert len(inserts) == 1

    # Second call uses cached _schema_checked and does not query or insert
    mongodb_mod.MongoDB._ensure_schema()
    assert len(finds) == 1
    assert len(inserts) == 1

    # Version mismatch raises CuckooReportError
    monkeypatch.setattr(mongodb_mod.MongoDB, "_schema_checked", False)
    monkeypatch.setattr(mongodb_mod, "mongo_find_one", lambda coll, query, proj: {"version": "999"})
    with pytest.raises(CuckooReportError, match="Mongo schema version not expected"):
        mongodb_mod.MongoDB._ensure_schema()

    # Transient insert failure (None from graceful_auto_reconnect) must not cache _schema_checked
    monkeypatch.setattr(mongodb_mod.MongoDB, "_schema_checked", False)
    monkeypatch.setattr(mongodb_mod, "mongo_find_one", lambda coll, query, proj: None)
    monkeypatch.setattr(mongodb_mod, "mongo_insert_one", lambda coll, doc: None)
    mongodb_mod.MongoDB._ensure_schema()
    assert mongodb_mod.MongoDB._schema_checked is False


