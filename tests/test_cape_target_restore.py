import json
from types import SimpleNamespace

import modules.processing.CAPE as cape_mod
from modules.processing.CAPE import CAPE


def _make_cape(tmp_path, task_id=42):
    proc = CAPE()
    proc.task = {"id": task_id, "category": "file", "target": str(tmp_path / "missing_sample.exe")}
    proc.analysis_path = str(tmp_path)
    proc.reports_path = str(tmp_path / "reports")
    proc.files_metadata = str(tmp_path / "files.json")
    proc.file_path = str(tmp_path / "missing_sample.exe")
    proc.results = {}
    proc.options = SimpleNamespace(buffer=8192, replace_patterns="")
    return proc


def test_cape_run_restores_target_from_mongodb_when_file_missing(tmp_path, monkeypatch):
    proc = _make_cape(tmp_path)
    expected_target = {"category": "file", "file": {"name": "sample.exe", "sha256": "abc123"}}
    monkeypatch.setattr(cape_mod, "mongo_find_one", lambda coll, q, proj=None: {"target": expected_target})

    proc.run()

    assert proc.results.get("target") == expected_target


def test_cape_run_restores_target_from_report_json_when_mongodb_empty(tmp_path, monkeypatch):
    proc = _make_cape(tmp_path)
    monkeypatch.setattr(cape_mod, "mongo_find_one", lambda coll, q, proj=None: None)

    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    expected_target = {"category": "file", "file": {"name": "from_json.exe", "sha256": "def456"}}
    (reports_dir / "report.json").write_text(json.dumps({"target": expected_target}), encoding="utf-8")

    proc.run()

    assert proc.results.get("target") == expected_target
