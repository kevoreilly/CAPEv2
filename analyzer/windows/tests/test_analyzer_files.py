"""Tests for analyzer.Files class and for protected_path() functions."""
import unittest

import analyzer
from analyzer import Files, add_protected_path, in_protected_path


class TestFiles(unittest.TestCase):
    def test_can_instantiate(self):
        files = Files()
        self.assertIsInstance(files, Files)

    def test_is_protected_filename(self):
        files = Files()
        not_protected = "not_protected"
        self.assertFalse(files.is_protected_filename(not_protected))
        should_be_protected = "PYTHON.EXE"
        self.assertTrue(files.is_protected_filename(should_be_protected))

    def test_is_protected_filename_class_method(self):
        not_protected = "not_protected"
        self.assertFalse(Files.is_protected_filename(not_protected))
        should_be_protected = "PYTHON.EXE"
        self.assertTrue(Files.is_protected_filename(should_be_protected))

    def test_add_protected_path(self):
        self.assertEqual(0, len(analyzer.PROTECTED_PATH_LIST))
        add_protected_path("FOO")
        self.assertEqual(1, len(analyzer.PROTECTED_PATH_LIST))
        self.assertIn("foo", analyzer.PROTECTED_PATH_LIST)
        # Restore original value
        analyzer.PROTECTED_PATH_LIST = []

    def test_in_protected_path(self):
        self.assertEqual(0, len(analyzer.PROTECTED_PATH_LIST))
        analyzer.PROTECTED_PATH_LIST.append("abcde")
        self.assertTrue(in_protected_path("ABCDE"))
        self.assertFalse(in_protected_path("foo"))
        # Restore original value
        analyzer.PROTECTED_PATH_LIST = []
