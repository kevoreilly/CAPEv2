# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.


def _make_info(monkeypatch, source_url):
    import modules.processing.analysisinfo as ai

    inst = ai.AnalysisInfo.__new__(ai.AnalysisInfo)
    inst.task = {
        "id": 1,
        "sample_id": 5,
        "options": "",
        "package": "exe",
        "category": "file",
        "custom": "",
        "machine": "",
        "tlp": None,
        "route": None,
        "started_on": "-",
        "completed_on": "-",
    }
    inst.log_path = "/tmp/nonexistent_analysis.log"

    class _DB:
        def view_task(self, *a, **k):
            return None

        def get_parent_sample_from_task(self, *a, **k):
            return None

        def get_source_url(self, sample_id=None):
            return source_url

    monkeypatch.setattr(ai, "db", _DB())
    return inst


def test_analysisinfo_keeps_source_url(monkeypatch):
    inst = _make_info(monkeypatch, "https://example.com/x")
    assert inst.run()["source_url"] == "https://example.com/x"


def test_analysisinfo_uses_attributes_for_parent_sample_and_main_task_id(monkeypatch):
    inst = _make_info(monkeypatch, "")
    parent_dict = {"id": 9, "sha256": "deadbeef" * 8}
    inst.task["attributes"] = {"main_task_id": 1234, "parent_sample": parent_dict}

    called_db_parent = False

    def _unexpected_db_lookup(*a, **k):
        nonlocal called_db_parent
        called_db_parent = True
        return None

    monkeypatch.setattr("modules.processing.analysisinfo.db.get_parent_sample_from_task", _unexpected_db_lookup)
    info = inst.run()
    assert info["parent_sample"] == parent_dict
    assert called_db_parent is False
