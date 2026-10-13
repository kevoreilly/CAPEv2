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

