# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from unittest.mock import MagicMock, patch

from modules.processing.procmemory import ProcessMemory
from modules.processing.strace import ParseProcessLog


class TestProcessMemory:
    def test_run_with_missing_module_path(self, tmp_path):
        pmem_dir = tmp_path / "pmemory"
        pmem_dir.mkdir()
        dmp_file = pmem_dir / "1234.dmp"
        dmp_file.write_bytes(b"dummy dump content")

        pm = ProcessMemory()
        pm.pmemory_path = str(pmem_dir)
        pm.options = {"strings": False}
        pm.results = {
            "behavior": {
                "processes": [
                    {
                        "process_id": 1234,
                        "process_name": "test_process",
                        # "module_path" intentionally omitted (e.g. Linux strace log)
                    }
                ]
            }
        }

        mock_file = MagicMock()
        mock_file.get_sha256.return_value = "dummy_sha256"
        mock_file.get_yara.return_value = []

        mock_procdump = MagicMock()
        mock_procdump.pretty_print.return_value = []

        with patch("modules.processing.procmemory.File", return_value=mock_file), \
             patch("modules.processing.procmemory.ProcDump", return_value=mock_procdump), \
             patch.object(pm, "get_procmemory_pe", return_value=[]):
            results = pm.run()

        assert len(results) == 1
        assert results[0]["pid"] == 1234
        assert results[0]["name"] == "test_process"
        assert results[0]["proc_path"] == ""

    def test_run_with_module_path(self, tmp_path):
        pmem_dir = tmp_path / "pmemory"
        pmem_dir.mkdir()
        dmp_file = pmem_dir / "5678.dmp"
        dmp_file.write_bytes(b"dummy dump content")

        pm = ProcessMemory()
        pm.pmemory_path = str(pmem_dir)
        pm.options = {"strings": False}
        pm.results = {
            "behavior": {
                "processes": [
                    {
                        "process_id": 5678,
                        "process_name": "sample.exe",
                        "module_path": r"C:\Windows\System32\sample.exe",
                    }
                ]
            }
        }

        mock_file = MagicMock()
        mock_file.get_sha256.return_value = "dummy_sha256_5678"
        mock_file.get_yara.return_value = []

        mock_procdump = MagicMock()
        mock_procdump.pretty_print.return_value = []

        with patch("modules.processing.procmemory.File", return_value=mock_file), \
             patch("modules.processing.procmemory.ProcDump", return_value=mock_procdump), \
             patch.object(pm, "get_procmemory_pe", return_value=[]):
            results = pm.run()

        assert len(results) == 1
        assert results[0]["pid"] == 5678
        assert results[0]["name"] == "sample.exe"
        assert results[0]["proc_path"] == r"C:\Windows\System32\sample.exe"


class TestStraceModulePath:
    def test_strace_parse_process_log_execve_extracts_module_path(self):
        logs = [
            {
                "time": "10:00:00",
                "syscall": "execve",
                "args": '"/bin/ls", ["ls", "-la"], 0x7ffd',
                "retval": "0",
            }
        ]
        log = ParseProcessLog(process_id=1001, logs=logs, syscalls_info={}, options={})
        assert log.process_name == "ls -la"
        assert log.module_path == "/bin/ls"
