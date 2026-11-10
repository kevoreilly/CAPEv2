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


def test_insert_calls_mongodb_bulk_fast_path(monkeypatch):
    from unittest.mock import MagicMock

    import modules.reporting.report_doc as report_doc

    inserted_batches = []

    def fake_insert_many(collection, docs):
        assert collection == "calls"
        inserted_batches.append(docs)
        res = MagicMock()
        res.inserted_ids = [f"oid_{i}" for i in range(len(docs))]
        return res

    monkeypatch.setattr(report_doc, "mongo_insert_many", fake_insert_many)

    calls = [{"api": "NtCreateFile", "arguments": [{"name": "FileName", "value": f"file_{i}"}]} for i in range(250)]
    report = {
        "info": {"id": 42},
        "behavior": {
            "processes": [
                {
                    "process_id": 1000,
                    "calls": calls,
                }
            ]
        },
    }

    new_procs = report_doc.insert_calls(report, mongodb=True)
    assert len(inserted_batches) == 1
    assert len(inserted_batches[0]) == 3
    assert [len(chunk["calls"]) for chunk in inserted_batches[0]] == [100, 100, 50]
    assert new_procs[0]["calls"] == ["oid_0", "oid_1", "oid_2"]
    # Clean calls are not copied unnecessarily
    assert inserted_batches[0][0]["calls"][0] is calls[0]


def test_insert_calls_mongodb_sanitizes_oversized_and_surrogate_values(monkeypatch):
    from unittest.mock import MagicMock

    import modules.reporting.report_doc as report_doc

    inserted_batches = []

    def fake_insert_many(collection, docs):
        assert collection == "calls"
        inserted_batches.append(docs)
        res = MagicMock()
        res.inserted_ids = [f"oid_{i}" for i in range(len(docs))]
        return res

    monkeypatch.setattr(report_doc, "mongo_insert_many", fake_insert_many)

    oversized_str = "A" * 50000
    oversized_bytes = b"B" * 50000
    surrogate_str = "C:\\Temp\\bad_\udc80_name.exe"

    calls = [{"api": "NtWriteFile", "arguments": [{"name": "Buffer", "value": "normal"}]} for _ in range(250)]
    calls[100] = {
        "api": "NtWriteFile",
        "arguments": [
            {"name": "Buffer", "value": oversized_str},
            {"name": "RawBuffer", "value": oversized_bytes},
            {"name": "FileName", "value": surrogate_str},
        ],
    }

    report = {
        "info": {"id": 99},
        "behavior": {"processes": [{"process_id": 500, "calls": calls}]},
    }

    new_procs = report_doc.insert_calls(report, mongodb=True)
    assert new_procs[0]["calls"] == ["oid_0", "oid_1", "oid_2"]
    assert len(inserted_batches) == 1

    chunk_1_call_0 = inserted_batches[0][1]["calls"][0]
    trunc_str = chunk_1_call_0["arguments"][0]["value"]
    trunc_bytes = chunk_1_call_0["arguments"][1]["value"]
    clean_surrogate = chunk_1_call_0["arguments"][2]["value"]

    assert len(trunc_str) == report_doc.MAX_CALL_VALUE_LEN + len("...[truncated]")
    assert trunc_str.endswith("...[truncated]")
    assert len(trunc_bytes) == report_doc.MAX_CALL_VALUE_LEN
    assert isinstance(clean_surrogate, str)
    clean_surrogate.encode("utf-8")

    # Original call in caller's list is not mutated in-place
    assert len(calls[100]["arguments"][0]["value"]) == 50000
    assert len(calls[100]["arguments"][1]["value"]) == 50000
    assert calls[100]["arguments"][2]["value"] == surrogate_str


def test_gcs_uploader_zip_archive_clamps_timestomped_mtimes(tmp_path, monkeypatch):
    import os
    import zipfile
    from unittest.mock import MagicMock

    import lib.cuckoo.common.gcp as gcp_mod

    src_dir = tmp_path / "analysis"
    src_dir.mkdir()
    past_file = src_dir / "epoch_1970.bin"
    past_file.write_bytes(b"past")
    os.utime(past_file, (0, 0))

    future_file = src_dir / "future_2150.bin"
    future_file.write_bytes(b"future")
    # 2150-01-01 UTC (> 2107 MS-DOS ZIP limit)
    os.utime(future_file, (5680281600, 5680281600))

    uploaded_archives = []

    class FakeBlob:
        def __init__(self, name):
            self.name = name
            self.metadata = None

        def upload_from_filename(self, filename):
            with zipfile.ZipFile(filename, "r") as zf:
                uploaded_archives.append({zi.filename: zi.date_time for zi in zf.infolist()})

    uploader = object.__new__(gcp_mod.GCSUploader)
    uploader.exclude_dirs = set()
    uploader.exclude_files = set()
    uploader.mode = "zip"
    uploader.bucket = MagicMock()
    uploader.bucket.name = "test-bucket"
    uploader.bucket.blob.side_effect = FakeBlob

    uploader.upload_zip_archive(123, str(src_dir))
    assert len(uploaded_archives) == 1
    dates = uploaded_archives[0]
    assert dates["123/epoch_1970.bin"][0] == 1980
    assert dates["123/future_2150.bin"][0] == 2107


def test_gcs_uploader_zip_archive_uses_cape_external_and_cleans_up(tmp_path, monkeypatch):
    import os
    from unittest.mock import MagicMock

    import lib.cuckoo.common.gcp as gcp_mod

    ext_dir = tmp_path / "cape-external"
    ext_dir.mkdir()
    monkeypatch.setattr(gcp_mod, "get_cape_external_dir", lambda: str(ext_dir))

    src_dir = tmp_path / "analysis"
    src_dir.mkdir()
    (src_dir / "report.json").write_text("{}", encoding="utf-8")

    staged_paths = []

    class _FakeBlob:
        def __init__(self, _name):
            self.metadata = None

        def upload_from_filename(self, filename):
            staged_paths.append(filename)
            assert os.path.exists(filename)

    uploader = object.__new__(gcp_mod.GCSUploader)
    uploader.exclude_dirs = set()
    uploader.exclude_files = set()
    uploader.mode = "zip"
    uploader.bucket = MagicMock()
    uploader.bucket.name = "test-bucket"
    uploader.bucket.blob.side_effect = _FakeBlob

    uploader.upload_zip_archive(456, str(src_dir))
    assert len(staged_paths) == 1
    assert os.path.dirname(staged_paths[0]) == str(ext_dir)
    assert os.path.basename(staged_paths[0]).startswith("gcs_456_")
    assert staged_paths[0].endswith(".zip")
    assert list(ext_dir.iterdir()) == []

    # Already-deleted temp file in finally: does not raise FileNotFoundError
    class _UnlinkingBlob:
        def __init__(self, _name):
            self.metadata = None

        def upload_from_filename(self, filename):
            os.unlink(filename)

    uploader.bucket.blob.side_effect = _UnlinkingBlob
    uploader.upload_zip_archive(456, str(src_dir))
    assert list(ext_dir.iterdir()) == []


def test_gcs_upload_diagnostic_report_and_helper(monkeypatch):
    import json
    from unittest.mock import MagicMock

    import lib.cuckoo.common.gcp as gcp_mod

    uploaded = []

    class _FakeDiagBlob:
        def __init__(self, name):
            self.name = name

        def upload_from_string(self, payload, content_type=None):
            uploaded.append((self.name, json.loads(payload), content_type))

    uploader = object.__new__(gcp_mod.GCSUploader)
    uploader.bucket = MagicMock()
    uploader.bucket.name = "diag-bucket"
    uploader.bucket.blob.side_effect = _FakeDiagBlob

    report = {"mounts": [{"path": "/tmp", "free_mb": 12}], "truncated": False}
    uri = uploader.upload_diagnostic_report(report, prefix="/disk_usage/")
    assert uri is not None
    assert uri.startswith("gs://diag-bucket/diagnostics/disk_usage_")
    assert uri.endswith(".json")
    assert len(uploaded) == 1
    assert uploaded[0][1] == report
    assert uploaded[0][2] == "application/json"

    monkeypatch.setattr(gcp_mod, "GCS_ENABLED", False)
    monkeypatch.setattr(gcp_mod, "gcs_uploader", uploader)
    assert gcp_mod.gcs_upload_disk_report(report) is None

    monkeypatch.setattr(gcp_mod, "GCS_ENABLED", True)
    assert gcp_mod.gcs_upload_disk_report(report) == uri

    def _fail_upload(_payload, content_type=None):
        raise RuntimeError("gcs unavailable")

    class _FailingBlob:
        def __init__(self, _name):
            self.upload_from_string = _fail_upload

    uploader.bucket.blob.side_effect = _FailingBlob
    assert gcp_mod.gcs_upload_disk_report(report) is None


def test_gcs_refetch_banned_uses_cape_external_and_unlinks_always(db, tmp_path, monkeypatch):
    import os
    from pathlib import Path

    import pytest

    monkeypatch.setenv("CAPE_AS_ROOT", "1")
    import lib.cuckoo.common.gcp as gcp_mod
    import utils.submit as submit_mod
    from lib.cuckoo.core.data.samples import Sample
    from lib.cuckoo.core.data.task import TASK_BANNED, Task

    sha256 = "f" * 64
    with db.session.begin():
        sample = Sample(
            md5="0" * 32,
            crc32="00000000",
            sha1="0" * 40,
            sha256=sha256,
            sha512="0" * 128,
            file_size=4,
            file_type="PE32",
        )
        db.session.add(sample)
        db.session.flush()
        task = Task(target="/samples/banned.bin")
        task.category = "file"
        task.timeout = 0
        task.priority = 1
        task.memory = False
        task.enforce_timeout = False
        task.timedout = False
        task.sample_id = sample.id
        task.status = TASK_BANNED
        db.session.add(task)

    ext_dir = tmp_path / "cape-external"
    ext_dir.mkdir()
    monkeypatch.setattr(gcp_mod, "HAVE_GCP", True)
    monkeypatch.setattr(gcp_mod, "get_cape_external_dir", lambda: str(ext_dir))

    seen_dests = []

    def _ok_download(_uri, dest_path, **_kw):
        seen_dests.append(dest_path)
        Path(dest_path).write_bytes(b"MZ\x90\x00")
        return True

    monkeypatch.setattr(gcp_mod, "download_from_gcs", _ok_download)
    monkeypatch.setattr(submit_mod, "submit_file", lambda **_kw: ([1234], {}))

    gcp_mod.gcs_refetch_banned("1d", samples_bucket="test-samples")
    assert len(seen_dests) == 1
    assert os.path.dirname(seen_dests[0]) == str(ext_dir)
    assert os.path.basename(seen_dests[0]).startswith(f"refetch_{sha256[:12]}_")
    assert list(ext_dir.iterdir()) == []

    # Failed download also unlinks temp file
    def _fail_download(_uri, dest_path, **_kw):
        Path(dest_path).write_bytes(b"partial")
        return False

    monkeypatch.setattr(gcp_mod, "download_from_gcs", _fail_download)
    gcp_mod.gcs_refetch_banned("1d", samples_bucket="test-samples")
    assert list(ext_dir.iterdir()) == []

    # Exception inside submit_file still unlinks temp file via finally:
    monkeypatch.setattr(gcp_mod, "download_from_gcs", _ok_download)

    def _boom_submit(**_kw):
        raise RuntimeError("submit failed")

    monkeypatch.setattr(submit_mod, "submit_file", _boom_submit)
    with pytest.raises(RuntimeError, match="submit failed"):
        gcp_mod.gcs_refetch_banned("1d", samples_bucket="test-samples")
    assert list(ext_dir.iterdir()) == []


def test_bingraph_reporter_processes_cape_payloads_once_without_mutating_defaults(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import modules.reporting.bingraph as bingraph_mod

    target_file = tmp_path / "target.bin"
    target_file.write_bytes(b"MZ" + b"\x00" * 64)
    dropped_file = tmp_path / "dropped.bin"
    dropped_file.write_bytes(b"\x90" * 64)
    payload_file = tmp_path / "payload.bin"
    payload_file.write_bytes(b"\xcc" * 64)

    calls = []
    orig_args = dict(bingraph_mod.bingraph_args_dict)

    monkeypatch.setattr(bingraph_mod, "HAVE_BINGRAPH", True)
    monkeypatch.setattr(
        bingraph_mod,
        "reporting_conf",
        SimpleNamespace(bingraph=SimpleNamespace(enabled=True, on_demand=False)),
    )
    monkeypatch.setattr(bingraph_mod, "bingraph_gen", lambda args_dict: calls.append(dict(args_dict)), raising=False)

    reporter = bingraph_mod.BinGraph()
    reporter.analysis_path = str(tmp_path)
    reporter.file_path = str(target_file)

    results = {
        "target": {"file": {"sha256": "1" * 64}},
        "dropped": [{"sha256": "2" * 64, "size": 64, "type": "data", "path": str(dropped_file)}],
        "procdump": [],
        "CAPE": {"payloads": [{"sha256": "3" * 64, "size": 64, "type": "PE32 executable", "path": str(payload_file)}]},
    }

    reporter.run(results)

    assert [c["prefix"] for c in calls] == ["1" * 64, "2" * 64, "3" * 64]
    assert bingraph_mod.bingraph_args_dict == orig_args

    calls.clear()
    procdump_file = tmp_path / "procdump.bin"
    procdump_file.write_bytes(b"\xaa" * 64)
    results["procdump"] = [{"sha256": "4" * 64, "size": 64, "type": "PE32 executable", "path": str(procdump_file)}]
    monkeypatch.setattr(
        bingraph_mod,
        "reporting_conf",
        SimpleNamespace(bingraph=SimpleNamespace(enabled=True, on_demand=False, binary=False, procdump=False, cape=False)),
    )
    reporter.run(results)
    assert [c["prefix"] for c in calls] == ["2" * 64]


