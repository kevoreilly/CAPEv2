"""Tests for Analyzer.analysis_loop() process tracking and protected paths."""

import ctypes
import os
import unittest
from unittest.mock import MagicMock, patch

if not hasattr(ctypes, "WINFUNCTYPE"):
    ctypes.WINFUNCTYPE = ctypes.CFUNCTYPE
if not hasattr(ctypes, "windll"):
    ctypes.windll = MagicMock()
ctypes.windll.ntdll.NtQueryInformationProcess.return_value = 0
os.environ.setdefault("SystemDrive", "C:")
os.environ.setdefault("TMP", "/tmp")

import analyzer


class TestProtectedPathNormalization(unittest.TestCase):
    """`path[-1]` on bytes yields an int, so the old trailing separator check
    was always true and appended a second backslash."""

    def test_directory_without_separator_gets_one(self):
        with patch("analyzer.os.path.isdir", return_value=True):
            self.assertEqual(b"c:\\dir\\", analyzer._normalized_protected_path("C:\\dir"))

    def test_directory_with_separator_is_left_alone(self):
        with patch("analyzer.os.path.isdir", return_value=True):
            self.assertEqual(b"c:\\dir\\", analyzer._normalized_protected_path("C:\\dir\\"))

    def test_file_is_left_alone(self):
        with patch("analyzer.os.path.isdir", return_value=False):
            self.assertEqual(b"c:\\dir\\file.exe", analyzer._normalized_protected_path("C:\\dir\\file.exe"))

    def test_trailing_separator_directory_still_protects_children(self):
        with patch("analyzer.PROTECTED_PATH_LIST", []), patch("analyzer.os.path.isdir", return_value=True):
            analyzer.add_protected_path("C:\\dir\\")
            self.assertTrue(analyzer.in_protected_path("C:\\dir\\child.exe"))
            self.assertFalse(analyzer.in_protected_path("C:\\other\\child.exe"))


class TestAnalysisLoopProcessTracking(unittest.TestCase):
    def tearDown(self):
        analyzer.Process.clear_monitor_handles()

    def _analyzer(self, pids):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.config.timeout = 60
        test.config.id = 1
        test.options = {}
        test.pid_check = True
        test.package = MagicMock()
        # One pass through the loop, then the package asks to stop.
        test.package.check.return_value = False
        test.process_list = analyzer.ProcessList()
        test.process_list.add_pids(pids)
        return test

    def test_every_dead_process_is_removed_in_one_pass(self):
        """remove_pid() mutates the list the loop iterates, so walking the live
        list skipped the entry after each removal: five dead processes needed
        several one second iterations to drain."""
        test = self._analyzer([101, 102, 103, 104, 105])

        dead = MagicMock()
        dead.is_alive.return_value = False
        dead.exit_code.return_value = 0

        with patch("analyzer.Process", return_value=dead), patch("analyzer.KERNEL32"):
            test.analysis_loop([])

        self.assertEqual([], test.process_list.pids)

    def test_live_processes_are_kept(self):
        test = self._analyzer([101, 102, 103])

        def make_process(pid=None, **kwargs):
            proc = MagicMock()
            alive = pid == 102
            proc.is_alive.return_value = alive
            proc.exit_code.return_value = analyzer.STILL_ACTIVE if alive else 0
            return proc

        with patch("analyzer.Process", side_effect=make_process), patch("analyzer.KERNEL32"):
            test.analysis_loop([])

        self.assertEqual([102], test.process_list.pids)

    def test_early_ntstatus_crash_logs_status_using_retained_monitor_handle_and_releases_it(self):
        def fill_image_name(h_proc, buf, size):
            if h_proc == 0xBEEF:
                buf.value = b"\\Device\\HarddiskVolume1\\sample.exe"
                return len(buf.value)
            return 0

        def fill_exit_code(h_proc, out_ptr):
            if h_proc == 0xBEEF:
                out_ptr._obj.value = 0xC0000135
                return 1
            return 0

        test = self._analyzer([])

        with (
            patch("lib.api.process.KERNEL32") as mock_k32,
            patch("lib.api.process.PSAPI") as mock_psapi,
            patch("analyzer.KERNEL32"),
        ):
            mock_k32.OpenProcess.return_value = 0xBEEF
            mock_k32.CloseHandle.return_value = 1
            mock_psapi.GetProcessImageFileNameA.side_effect = fill_image_name
            mock_k32.GetExitCodeProcess.side_effect = fill_exit_code

            test.process_list.add_pids([220])
            # Simulate PID 220 exiting and being reaped by the OS before analysis_loop checks it.
            mock_k32.OpenProcess.return_value = 0

            with (
                self.assertLogs(level="WARNING") as ana_logs,
                self.assertNoLogs("lib.api.process", level="WARNING"),
            ):
                test.analysis_loop([])

        self.assertEqual([], test.process_list.pids)
        self.assertNotIn(220, analyzer.Process._monitor_handles)
        closed_beef = [c for c in mock_k32.CloseHandle.call_args_list if getattr(c[0][0], "value", c[0][0]) == 0xBEEF]
        self.assertEqual(len(closed_beef), 1)
        joined = "\n".join(ana_logs.output)
        self.assertIn("220 (sample.exe)", joined)
        self.assertIn("0xc0000135 (STATUS_DLL_NOT_FOUND)", joined)


if __name__ == "__main__":
    unittest.main()
