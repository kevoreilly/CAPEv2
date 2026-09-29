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

