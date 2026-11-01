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


def test_mongodb_worker_main_task_id_does_not_delete_central_report_with_local_id(monkeypatch, tmp_path):
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    import modules.reporting.mongodb as mongodb_mod

    deleted = []
    resynced = []
    monkeypatch.setattr(mongodb_mod, "HAVE_MONGO", True, raising=False)
    monkeypatch.setattr(mongodb_mod, "mongo_collection_names", lambda: ["cuckoo_schema"], raising=False)
    monkeypatch.setattr(mongodb_mod, "mongo_find_one", lambda *a, **k: {"version": mongodb_mod.MongoDB.SCHEMA_VERSION}, raising=False)
    monkeypatch.setattr(mongodb_mod, "mongo_delete_data", lambda ids: deleted.append(list(ids)), raising=False)
    monkeypatch.setattr(mongodb_mod, "mongo_insert_one", lambda coll, doc: MagicMock(inserted_id="oid1"), raising=False)
    monkeypatch.setattr(mongodb_mod, "_ensure_tenancy_indexes", lambda: None)
    monkeypatch.setattr(
        mongodb_mod,
        "_resync_local_acl_stamp",
        lambda report, main_task_id: resynced.append((report["info"]["id"], main_task_id)),
    )
    monkeypatch.setattr(mongodb_mod, "get_json_document", lambda results, path: results)
    monkeypatch.setattr(mongodb_mod, "insert_calls", lambda report, **kw: [])
    monkeypatch.setattr(mongodb_mod, "reporting_conf", SimpleNamespace(mongodb=SimpleNamespace(dump_iocs=False)))

    reporter = mongodb_mod.MongoDB()
    reporter.analysis_path = str(tmp_path)
    reporter.task = {
        "id": 7,
        "attributes": {
            "main_task_id": 500,
            "task_acl": {"user_id": 4, "tenant_id": 2, "visibility": "tenant", "visibility_seq": 3},
        },
    }
    reporter.options = {}
    results = {"info": {"id": 7, "local_task_id": 7}, "behavior": {"processes": []}, "debug": {"errors": []}}
    reporter.run(results)

    assert deleted == [[500]]  # never deletes central task 7 when worker local task 7 runs main_task_id 500
    assert results["info"]["id"] == 500
    assert results["info"]["visibility"] == "tenant"
    assert resynced == [(500, 500)]


def test_elasticsearchdb_rewrites_main_task_id_and_stamps_task_acl(monkeypatch, tmp_path):
    from unittest.mock import MagicMock

    import lib.tenancy.hooks as tenancy_hooks
    import modules.reporting.elasticsearchdb as es_mod

    indexed = []
    resynced = []
    fake_es = MagicMock()
    fake_es.index.side_effect = lambda **kw: indexed.append(kw) or {"_id": "es1"}
    monkeypatch.setattr(es_mod, "HAVE_ELASTICSEARCH", True, raising=False)
    monkeypatch.setattr(es_mod, "elastic_handler", fake_es, raising=False)
    monkeypatch.setattr(es_mod, "daily_analysis_index_exists", lambda: True, raising=False)
    monkeypatch.setattr(es_mod, "daily_calls_index_exists", lambda: True, raising=False)
    monkeypatch.setattr(es_mod, "get_daily_analysis_index", lambda: "cape-analysis", raising=False)
    monkeypatch.setattr(es_mod, "delete_analysis_and_related_calls", lambda tid: None, raising=False)
    monkeypatch.setattr(es_mod, "get_json_document", lambda results, path: results)
    monkeypatch.setattr(es_mod, "insert_calls", lambda report, **kw: [])
    monkeypatch.setattr(tenancy_hooks, "_resync_retrieved_report", lambda tid: resynced.append(tid))

    reporter = es_mod.ElasticSearchDB()
    reporter.analysis_path = str(tmp_path)
    reporter.task = {
        "id": 7,
        "attributes": {
            "main_task_id": 500,
            "task_acl": {"user_id": 9, "tenant_id": 2, "visibility": "tenant", "visibility_seq": 4},
        },
    }
    reporter.options = {"calls": False}
    results = {"info": {"id": 7, "started": "2026-01-01 00:00:00", "ended": "2026-01-01 00:01:00"}, "behavior": {"processes": []}}
    reporter.run(results)

    assert len(indexed) == 1
    doc = indexed[0]["body"]
    assert doc["info"]["id"] == 500
    assert doc["info"]["local_task_id"] == 7
    assert (doc["info"]["user_id"], doc["info"]["tenant_id"], doc["info"]["visibility"], doc["info"]["visibility_seq"]) == (
        9,
        2,
        "tenant",
        4,
    )
    assert resynced == []  # worker with main_task_id must not resync against worker-local SQL

    # Local single-node reprocessing (no main_task_id) resyncs against local TaskAcl after ES index
    reporter.task = {"id": 7, "attributes": {}}
    local_results = {"info": {"id": 7, "started": "2026-01-01 00:00:00", "ended": "2026-01-01 00:01:00"}, "behavior": {"processes": []}}
    reporter.run(local_results)
    assert resynced == [7]


