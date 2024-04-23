"""Tests for Analyzer and CommandPipeHandler.

Major components not yet tested:
- Analyzer.prepare()
- Analyzer.run()
- Analyzer.complete()
"""
import random
import unittest
from unittest.mock import MagicMock, patch

import analyzer
from analyzer import Analyzer, CommandPipeHandler


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.patches = []
        patch_sleep = patch("lib.common.defines.KERNEL32.Sleep")
        _ = patch_sleep.start()
        self.addCleanup(patch_sleep.stop)
        patch_call = patch("subprocess.call")
        self.call = patch_call.start()
        self.addCleanup(patch_call.stop)
        self.analyzer = Analyzer()
        self.cph = CommandPipeHandler(self.analyzer)
        # Since the CommandPipeHandler.ignore_list is a class variable,
        # we reset it between tests, so we get a fresh start.
        self.cph.ignore_list = dict(pid=[])

    def test_can_instantiate(self):
        self.assertIsInstance(self.analyzer, Analyzer)
        self.assertIsInstance(self.cph, CommandPipeHandler)

    def test_get_pipe_path(self):
        pipe_name = "random_text"
        pipe_path = self.analyzer.get_pipe_path(pipe_name)
        self.assertIsNotNone(pipe_path)
        self.assertIsInstance(pipe_path, str)
        self.assertIn(pipe_name, pipe_path)
        self.assertIn("PIPE", pipe_path)

    def test_handle_loaded(self):
        random_pid = random.randint(1, 99999999)
        with patch("analyzer.INJECT_LIST", [random_pid]):
            ana = self.analyzer
            self.assertEqual(1, len(analyzer.INJECT_LIST))
            self.cph._handle_loaded(data=str(random_pid))
            self.assertIn(random_pid, ana.process_list.pids)
            self.assertEqual(0, len(analyzer.INJECT_LIST))

    def test_handle_kterminate(self):
        ana = self.analyzer
        random_pid = random.randint(1, 99999999)
        ana.process_list.pids.append(random_pid)
        self.assertEqual(1, len(ana.process_list.pids))
        self.cph._handle_kterminate(data=str(random_pid))
        self.assertEqual(0, len(ana.process_list.pids))

    @patch("analyzer.Process")
    def test_handle_kprocess(self, mock_process):
        ana = self.analyzer
        random_pid = random.randint(1, 99999999)
        self.assertEqual(0, len(ana.process_list.pids))
        self.cph._handle_kprocess(data=str(random_pid))
        self.assertEqual(1, len(ana.process_list.pids))
        self.assertIn(random_pid, ana.process_list.pids)
        mock_process.assert_called_once()

    def test_handle_ksubvert(self):
        ana = self.analyzer
        random_pid1 = random.randint(1, 99999999)
        random_pid2 = random.randint(1, 99999999)
        random_pid3 = random.randint(1, 99999999)
        ana.process_list.pids = [random_pid1, random_pid2, random_pid3]
        self.cph._handle_ksubvert(data=None)
        self.assertEqual(0, len(ana.process_list.pids))

    @patch("analyzer.Process")
    @patch("analyzer.get_explorer_pid")
    def test_handle_shell(self, mock_get_explorer_pid, mock_process):
        ana = self.analyzer
        random_pid = random.randint(1, 99999999)
        mock_get_explorer_pid.return_value = random_pid
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.cph._handle_shell(data=None)
        self.assertEqual(1, len(ana.CRITICAL_PROCESS_LIST))
        self.assertIn(random_pid, ana.CRITICAL_PROCESS_LIST)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        mock_process.assert_called_once()

    @patch("analyzer.pid_from_service_name")
    @patch("analyzer.Process")
    def test_handle_interop(self, mock_process, mock_pid_from_service_name):
        mock_process.return_value = MagicMock()
        random_pid = random.randint(1, 99999999)
        mock_pid_from_service_name.return_value = random_pid
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_interop(None)
        self.assertEqual(1, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_DCOM)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        self.assertIn(random_pid, ana.CRITICAL_PROCESS_LIST)
        mock_pid_from_service_name.assert_called_once()
        self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_handle_interop_already(self, mock_process):
        """If dcom process already monitored, do nothing."""
        ana = self.analyzer
        ana.MONITORED_DCOM = True
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.cph._handle_interop(None)
        # No change to process list or last inject time
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        self.call.assert_not_called()

    @patch("analyzer.pid_from_service_name")
    @patch("analyzer.Process")
    def test_handle_interop_timed_out(self, mock_process, mock_pid_from_service_name):
        """Even if ANALYSIS_TIMED_OUT, we still handle interop"""
        # XXX Is this what we want?
        with patch("analyzer.ANALYSIS_TIMED_OUT", True):
            mock_process.return_value = MagicMock()
            random_pid = random.randint(1, 99999999)
            mock_pid_from_service_name.return_value = random_pid
            ana = self.analyzer
            self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
            self.assertFalse(ana.MONITORED_DCOM)
            self.assertIsNone(ana.LASTINJECT_TIME)
            self.cph._handle_interop(None)
            self.assertEqual(1, len(ana.CRITICAL_PROCESS_LIST))
            self.assertTrue(ana.MONITORED_DCOM)
            self.assertIsNotNone(ana.LASTINJECT_TIME)
            self.assertIn(random_pid, ana.CRITICAL_PROCESS_LIST)
            mock_pid_from_service_name.assert_called_once()
            self.call.assert_not_called()

    @patch("analyzer.pid_from_service_name")
    def test_handle_wmi(self, mock_pid_from_service_name):
        random_pid1 = random.randint(1, 99999999)
        random_pid2 = random.randint(1, 99999999)
        mock_pid_from_service_name.side_effect = [random_pid1, random_pid2]
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_WMI)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_wmi(None)
        self.assertEqual(2, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_WMI)
        self.assertTrue(ana.MONITORED_DCOM)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        self.assertIn(random_pid1, ana.CRITICAL_PROCESS_LIST)
        self.assertIn(random_pid2, ana.CRITICAL_PROCESS_LIST)

    @patch("analyzer.pid_from_service_name")
    def test_handle_wmi_already(self, mock_pid_from_service_name):
        ana = self.analyzer
        ana.MONITORED_WMI = True
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_wmi(None)
        # Should be no change to DCOM or last inject time
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_pid_from_service_name.assert_not_called()
        self.call.assert_not_called()

    def test_handle_wmi_timed_out(self):
        with patch("analyzer.ANALYSIS_TIMED_OUT", True):
            ana = self.analyzer
            self.assertFalse(ana.MONITORED_WMI)
            self.assertFalse(ana.MONITORED_DCOM)
            self.assertIsNone(ana.LASTINJECT_TIME)
            self.cph._handle_wmi(data=None)
            # Should be no change to DCOM, WMI, or last inject time
            self.assertFalse(ana.MONITORED_WMI)
            self.assertFalse(ana.MONITORED_DCOM)
            self.assertIsNone(ana.LASTINJECT_TIME)
            self.call.assert_not_called()

    @patch("analyzer.Process")
    @patch("analyzer.pid_from_service_name")
    def test_handle_tasksched(self, mock_pid_from_service_name, mock_process):
        random_pid = random.randint(1, 99999999)
        mock_pid_from_service_name.return_value = random_pid
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_TASKSCHED)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_tasksched(data=None)
        self.assertEqual(1, len(ana.CRITICAL_PROCESS_LIST))
        self.assertIn(random_pid, ana.CRITICAL_PROCESS_LIST)
        self.assertTrue(ana.MONITORED_TASKSCHED)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        self.call.assert_called()
        mock_process.assert_called_once()

    def test_handle_tasksched_timed_out(self):
        ana = self.analyzer
        with patch("analyzer.ANALYSIS_TIMED_OUT", True):
            self.assertFalse(ana.MONITORED_TASKSCHED)
            self.assertIsNone(ana.LASTINJECT_TIME)
            self.cph._handle_tasksched(data=None)
            # Should be no change to TASKSCHED or last inject time
            self.assertFalse(ana.MONITORED_TASKSCHED)
            self.assertIsNone(ana.LASTINJECT_TIME)
            self.call.assert_not_called()

    @patch("analyzer.pid_from_service_name")
    def test_handle_tasksched_already(self, mock_pid_from_service_name):
        ana = self.analyzer
        ana.MONITORED_TASKSCHED = True
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_tasksched(data=None)
        # Should be no change to last inject time
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.call.assert_not_called()
        mock_pid_from_service_name.assert_not_called()

    @patch("analyzer.pid_from_service_name")
    def test_handle_bits(self, mock_pid_from_service_name):
        random_pid1 = random.randint(1, 99999999)
        random_pid2 = random.randint(1, 99999999)
        mock_pid_from_service_name.side_effect = [random_pid1, random_pid2]
        ana = self.analyzer
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_BITS)
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_bits(data=None)
        self.assertEqual(2, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_BITS)
        self.assertTrue(ana.MONITORED_DCOM)
        self.assertIsNotNone(ana.LASTINJECT_TIME)

    def test_handle_bits_already(self):
        ana = self.analyzer
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        ana.MONITORED_BITS = True
        self.cph._handle_bits(data=None)
        # Should be no change to DCOM or last inject time
        self.assertFalse(ana.MONITORED_DCOM)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.call.assert_not_called()

    def test_handle_bits_timed_out(self):
        with patch("analyzer.ANALYSIS_TIMED_OUT", True):
            ana = self.analyzer
            self.assertFalse(ana.MONITORED_BITS)
            self.assertFalse(ana.MONITORED_DCOM)
            self.assertIsNone(ana.LASTINJECT_TIME)
            self.cph._handle_bits(data=None)
            # Should be no change to DCOM, BITS, or last inject time
            self.assertFalse(ana.MONITORED_BITS)
            self.assertFalse(ana.MONITORED_DCOM)
            self.assertIsNone(ana.LASTINJECT_TIME)
            self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_handle_service(self, mock_process):
        ana = self.analyzer
        # Relies on SERVICES_PID being set.
        ana.SERVICES_PID = 12345
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertFalse(ana.MONITORED_SERVICES)
        self.assertIsNone(ana.LASTINJECT_TIME)
        self.cph._handle_service(servname=b"random-service-name")
        self.assertEqual(1, len(ana.CRITICAL_PROCESS_LIST))
        self.assertTrue(ana.MONITORED_SERVICES)
        self.assertIsNotNone(ana.LASTINJECT_TIME)
        mock_process.assert_called_once()
        self.call.assert_called_once()

    @patch("analyzer.Process")
    def test_handle_service_already(self, mock_process):
        ana = self.analyzer
        self.assertIsNone(ana.LASTINJECT_TIME)
        ana.MONITORED_SERVICES = True
        self.cph._handle_service(servname=b"any-name-can-go-here")
        # Should be no change to process list or last inject time
        self.assertEqual(0, len(ana.CRITICAL_PROCESS_LIST))
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        # It still wil call "sc config"
        self.call.assert_called_once()

    @patch("analyzer.Process")
    def test_handle_service_timed_out(self, mock_process):
        with patch("analyzer.ANALYSIS_TIMED_OUT", True):
            ana = self.analyzer
            self.assertFalse(ana.MONITORED_SERVICES)
            self.assertIsNone(ana.LASTINJECT_TIME)
            self.cph._handle_service(servname="random-service-name")
            # Should be no change to MONITORED_SERVICES or last inject time
            self.assertFalse(ana.MONITORED_SERVICES)
            self.assertIsNone(ana.LASTINJECT_TIME)
            mock_process.assert_not_called()
            self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_inject_process(self, mock_process):
        random_pid = random.randint(1, 99999999)
        ana = self.analyzer
        self.assertEqual(0, len(ana.process_list.pids))
        self.assertEqual(0, len(self.cph.ignore_list["pid"]))
        self.cph._inject_process(process_id=random_pid, thread_id=None, mode=None)
        self.assertEqual(1, len(ana.process_list.pids))
        self.assertIn(random_pid, ana.process_list.pids)
        # XXX Calling _inject_process does nothing to LASTINJECT_TIME ?
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_called_once()
        self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_inject_process_self(self, mock_process):
        """If _inject_process is called with the pid of the analyzer, do nothing."""
        random_pid = random.randint(1, 99999999)
        ana = self.analyzer
        ana.pid = random_pid
        self.assertEqual(0, len(self.cph.ignore_list["pid"]))
        self.cph._inject_process(process_id=random_pid, thread_id=None, mode=None)
        self.assertEqual(1, len(self.cph.ignore_list["pid"]))
        self.assertIn(random_pid, self.cph.ignore_list["pid"])
        # Should be no change to last inject time
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_inject_process_already(self, mock_process):
        """If _inject_process is called with a pid we are already monitoring, do nothing."""
        random_pid = random.randint(1, 99999999)
        ana = self.analyzer
        ana.process_list.pids.append(random_pid)
        self.assertEqual(0, len(self.cph.ignore_list["pid"]))
        self.cph._inject_process(process_id=random_pid, thread_id=None, mode=None)
        self.assertEqual(1, len(self.cph.ignore_list["pid"]))
        self.assertIn(random_pid, self.cph.ignore_list["pid"])
        # Should be no change to last inject time
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        self.call.assert_not_called()

    @patch("analyzer.Process")
    def test_inject_process_already_notrack(self, mock_process):
        """If _inject_process is called with a pid on the notrack list, move it to the track list.

        Do nothing else.
        """
        random_pid = random.randint(1, 99999999)
        ana = self.analyzer
        ana.process_list.pids_notrack.append(random_pid)
        self.assertEqual(0, len(self.cph.ignore_list["pid"]))
        self.assertEqual(0, len(ana.process_list.pids))
        self.cph._inject_process(process_id=random_pid, thread_id=None, mode=None)
        self.assertEqual(1, len(self.cph.ignore_list["pid"]))
        self.assertIn(random_pid, self.cph.ignore_list["pid"])
        self.assertIn(random_pid, ana.process_list.pids)
        self.assertEqual(0, len(ana.process_list.pids_notrack))
        self.assertEqual(1, len(ana.process_list.pids))
        # Should be no change to last inject time
        self.assertIsNone(ana.LASTINJECT_TIME)
        mock_process.assert_not_called()
        self.call.assert_not_called()
