"""Tests for Analyzer.analysis_loop() process tracking and protected paths."""

import unittest
from unittest.mock import MagicMock, patch

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

        with patch("analyzer.Process", return_value=dead), patch("analyzer.KERNEL32"):
            test.analysis_loop([])

        self.assertEqual([], test.process_list.pids)

    def test_live_processes_are_kept(self):
        test = self._analyzer([101, 102, 103])

        def make_process(pid=None, **kwargs):
            proc = MagicMock()
            proc.is_alive.return_value = pid == 102
            return proc

        with patch("analyzer.Process", side_effect=make_process), patch("analyzer.KERNEL32"):
            test.analysis_loop([])

        self.assertEqual([102], test.process_list.pids)


if __name__ == "__main__":
    unittest.main()
