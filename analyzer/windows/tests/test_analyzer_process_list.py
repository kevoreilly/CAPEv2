"""Tests for analyzer.ProcessList class."""
import unittest

from analyzer import ProcessList


class TestProcessList(unittest.TestCase):
    def test_can_instantiate(self):
        process_list = ProcessList()
        self.assertIsInstance(process_list, ProcessList)

    def test_add_pid(self):
        """Calling add_pid() on ProcessList should add the PID to the list."""
        process_list = ProcessList()
        self.assertEqual(0, len(process_list.pids))
        self.assertEqual(0, len(process_list.pids_notrack))
        pid1 = 12345
        process_list.add_pid(pid1)
        self.assertIn(pid1, process_list.pids)
        pid2 = 334455
        process_list.add_pid(pid2, track=False)
        self.assertIn(pid2, process_list.pids_notrack)
        self.assertNotIn(pid2, process_list.pids)
        # Try adding the pid, it shouldn't get added
        process_list.add_pid(pid2)
        self.assertNotIn(pid2, process_list.pids)
        self.assertEqual(1, len(process_list.pids))
        self.assertEqual(1, len(process_list.pids_notrack))

    def test_not_a_number(self):
        pid1 = "not a number"
        process_list = ProcessList()
        with self.assertRaises(ValueError):
            process_list.add_pid(pid1)

    def test_add_pids(self):
        """Calling add_pids() on ProcessList should add the pids to the list."""
        pids_to_add = [1, 2, 3, 4, 5]
        process_list = ProcessList()
        process_list.add_pids(pids_to_add)
        self.assertEqual(5, len(process_list.pids))
        self.assertEqual(0, len(process_list.pids_notrack))

    def test_has_pid(self):
        pid1 = 808
        pid2 = 31415
        process_list = ProcessList()
        process_list.pids = [pid1]
        process_list.pids_notrack = [pid2]
        self.assertTrue(process_list.has_pid(pid1))
        self.assertTrue(process_list.has_pid(pid2))
        self.assertTrue(process_list.has_pid(pid1, notrack=False))
        self.assertFalse(process_list.has_pid(pid2, notrack=False))

    def test_remove_pid(self):
        """Calling remove_pid should remove pid from process_list."""
        process_list = ProcessList()
        pid_to_remove = 54321
        process_list.pids = [pid_to_remove]
        self.assertEqual(1, len(process_list.pids))
        process_list.remove_pid(pid_to_remove)
        self.assertEqual(0, len(process_list.pids))
        process_list.pids_notrack = [pid_to_remove]
        self.assertEqual(1, len(process_list.pids_notrack))
        process_list.remove_pid(pid_to_remove)
        self.assertEqual(0, len(process_list.pids_notrack))
