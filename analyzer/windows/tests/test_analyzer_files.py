"""Tests for analyzer.Files class and for protected_path() functions."""

import os
import tempfile
import unittest
from unittest.mock import patch

from analyzer import Files


class TestFiles(unittest.TestCase):
    def test_can_instantiate(self):
        files = Files()
        self.assertIsInstance(files, Files)
        self.assertFalse(files.files)
        self.assertFalse(files.files_orig)
        self.assertFalse(files.dumped)

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

    def test_dumped_is_a_set(self):
        """Membership is the only operation performed on it, and a dropper can
        produce tens of thousands of entries."""
        files = Files()
        self.assertIsInstance(files.dumped, set)

    def test_dump_file_records_hash_once(self):
        files = Files()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "dropped.bin")
            with open(path, "wb") as fd:
                fd.write(b"payload")

            with patch("analyzer.upload_to_host") as upload:
                files.dump_file(path)
                files.dump_file(path)

        self.assertEqual(1, len(files.dumped))
        self.assertEqual(2, upload.call_count)
        # The second upload is flagged as a duplicate, so no bytes are resent.
        self.assertFalse(upload.call_args_list[0].kwargs["duplicated"])
        self.assertTrue(upload.call_args_list[1].kwargs["duplicated"])

    def test_dump_files_drains_every_file(self):
        files = Files()
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = []
            for i in range(25):
                path = os.path.join(tmpdir, f"dropped{i}.bin")
                with open(path, "wb") as fd:
                    fd.write(f"payload {i}".encode())
                paths.append(path)
                files.add_file(path)

            with patch("analyzer.upload_to_host") as upload:
                files.dump_files()

        self.assertEqual({}, files.files)
        self.assertEqual({}, files.files_orig)
        self.assertEqual(25, upload.call_count)
        self.assertEqual(25, len(files.dumped))

    def test_dump_files_picks_up_files_added_while_draining(self):
        """Pipe handler threads can add files while dump_files() runs, which is
        why self.files is re-checked on every iteration."""
        files = Files()
        with tempfile.TemporaryDirectory() as tmpdir:
            first = os.path.join(tmpdir, "first.bin")
            late = os.path.join(tmpdir, "late.bin")
            for path in (first, late):
                with open(path, "wb") as fd:
                    fd.write(path.encode())
            files.add_file(first)

            def add_late(*args, **kwargs):
                if late.lower() not in files.files:
                    files.add_file(late)

            with patch("analyzer.upload_to_host", side_effect=add_late) as upload:
                files.dump_files()

        self.assertEqual({}, files.files)
        self.assertEqual(2, upload.call_count)
