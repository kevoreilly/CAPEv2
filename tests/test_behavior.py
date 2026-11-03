# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from lib.cuckoo.common.config import Config
from lib.cuckoo.common.dictionary import Dictionary
from modules.processing.behavior import Enhanced, ParseProcessLog, Summary

cfg = Config("processing")


class TestParseProcessLog:
    def test_init(self):
        assert (
            str(ParseProcessLog("CAPEv2/tests/test_bson.bson", cfg.behavior))
            == "<ParseProcessLog log-path: CAPEv2/tests/test_bson.bson>"
        )


class TestSummaryAndEnhanced:
    def test_summary_read_files_and_file_activities(self):
        options = Dictionary({"replace_patterns": False, "file_activities": True})
        summary = Summary(options=options)
        process = {
            "process_id": 2256,
            "file_activities": {
                "read_files": [],
                "write_files": [],
                "delete_files": [],
            },
        }
        call = {
            "api": "NtOpenFile",
            "category": "filesystem",
            "status": True,
            "arguments": [
                {"name": "FileHandle", "value": "0x000002cc"},
                {"name": "DesiredAccess", "value": "0x00100021"},
                {"name": "FileName", "value": r"C:\Users\Bruno\AppData\Local\Temp\data.bin"},
                {"name": "ShareAccess", "value": "5"},
            ],
        }
        summary.event_apicall(call, process)
        result = summary.run()
        assert r"C:\Users\Bruno\AppData\Local\Temp\data.bin" in result["read_files"]
        assert r"C:\Users\Bruno\AppData\Local\Temp\data.bin" in process["file_activities"]["read_files"]

    def test_enhanced_registry_writes_and_disposition(self):
        enhanced = Enhanced()

        nt_set_call = {
            "api": "NtSetValueKey",
            "category": "registry",
            "timestamp": "2026-09-29 13:42:00,360",
            "arguments": [
                {
                    "name": "FullName",
                    "value": r"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\5.0\Cache\Cookies\CachePrefix",
                },
                {"name": "Buffer", "value": "Cookie:"},
            ],
        }
        ev = enhanced._process_call(nt_set_call)
        assert ev is not None
        assert ev["event"] == "write"
        assert ev["object"] == "registry"
        assert ev["data"]["content"] == "Cookie:"

        # RegCreateKeyExW with Disposition=2 (REG_OPENED_EXISTING_KEY) should not be treated as a write
        open_existing_call = {
            "api": "RegCreateKeyExW",
            "category": "registry",
            "timestamp": "2026-09-29 13:42:00,400",
            "arguments": [
                {"name": "FullName", "value": r"HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel"},
                {"name": "Disposition", "value": "2"},
            ],
        }
        assert enhanced._process_call(open_existing_call) is None

        # RegCreateKeyExW with Disposition=1 (REG_CREATED_NEW_KEY) is recorded as a write
        create_new_call = {
            "api": "RegCreateKeyExW",
            "category": "registry",
            "timestamp": "2026-09-29 13:42:00,410",
            "arguments": [
                {"name": "FullName", "value": r"HKEY_CURRENT_USER\Software\NewMalwareKey"},
                {"name": "Disposition", "value": "1"},
            ],
        }
        ev_create = enhanced._process_call(create_new_call)
        assert ev_create is not None
        assert ev_create["event"] == "write"
        assert ev_create["data"]["regkey"] == r"HKEY_CURRENT_USER\Software\NewMalwareKey"

    def test_summary_api_spam_detection_and_options_merging(self):
        # 1. Missing keys on Dictionary should default safely to detect_apispam=True, apispam_limit=256
        empty_opts = Dictionary({})
        task = {"options": "exclude-apis=NtQueryValueKey:NtOpenFile"}
        summary = Summary(options=empty_opts, task=task)
        assert summary.detect_apispam is True
        assert summary.apispam_limit == 256

        # Simulate 300 calls to NtDelayExecution and 50 to NtClose
        process = {"process_id": 1000}
        call_delay = {"api": "NtDelayExecution", "category": "system"}
        call_close = {"api": "NtClose", "category": "system"}
        for _ in range(300):
            summary.event_apicall(call_delay, process)
        for _ in range(50):
            summary.event_apicall(call_close, process)

        res = summary.run()
        assert res["apispam"] == ["NtDelayExecution"]
        # Merged exclude-apis should be deduplicated and deterministically sorted
        assert res["apispam_exclude_apis"] == "NtDelayExecution:NtOpenFile:NtQueryValueKey"

    def test_summary_api_spam_disabled(self):
        opts = Dictionary({"detect_apispam": "no", "apispam_limit": "100"})
        summary = Summary(options=opts)
        assert summary.detect_apispam is False
        assert summary.apispam_limit == 100

        process = {"process_id": 1000}
        call = {"api": "NtDelayExecution", "category": "system"}
        for _ in range(200):
            summary.event_apicall(call, process)

        assert len(summary.api_counts) == 0
        res = summary.run()
        assert res["apispam"] == []
        assert res["apispam_exclude_apis"] == ""


