"""Tests for the analyzer."""
import os
import pathlib
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import analyzer
import modules.packages.pdf


class TestModule(unittest.TestCase):
    def test_pid_from_service_name(self):
        # just check it doesn't crash
        _ = analyzer.pid_from_service_name("W32Time")

    def test_get_explorer_pid(self):
        # just check it doesn't crash
        _ = analyzer.get_explorer_pid()

    def test_pids_from_image_names(self):
        pids = analyzer.pids_from_image_names('python.exe')
        # should be at least one Python process running
        self.assertGreaterEqual(len(pids),1)
        self.assertIn(os.getpid(), pids)

    def test_protected_path(self):
        with tempfile.NamedTemporaryFile() as ntf:
            protected_paths = [str(pathlib.Path(ntf.name)).lower().encode()]
            with patch('analyzer.PROTECTED_PATH_LIST', protected_paths):
                self.assertTrue(analyzer.in_protected_path(ntf.name.encode()))


class TestAnalyzer(unittest.TestCase):
    def test___init__(self):
        _ = analyzer.Analyzer()

    @patch("analyzer.PipeServer")
    @patch("analyzer.Config")
    @patch("analyzer.init_logging")
    @patch("analyzer.set_clock")
    def test_prepare(self, set_lock, init_logging, config, pipeserver):
        test = analyzer.Analyzer()
        test.prepare()

    def test_choose_package_pdf(self):
        test = analyzer.Analyzer()
        test.config = MagicMock()
        test.options = MagicMock()
        test.config.package = "pdf"
        pkg_name, pkg_class = test.choose_package()
        self.assertEqual('modules.packages.pdf', pkg_name)
        self.assertIsInstance(pkg_class, modules.packages.pdf.PDF)
