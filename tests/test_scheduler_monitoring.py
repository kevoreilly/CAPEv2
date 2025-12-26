import queue
import logging
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
from lib.cuckoo.core.scheduler import Scheduler
from lib.cuckoo.core.analysis_manager import AnalysisManager
from lib.cuckoo.core.database import Task, Machine

@pytest.fixture
def scheduler():
    # Patch dependencies to isolate Scheduler and avoid environment issues
    with patch('lib.cuckoo.core.scheduler.Database'), \
         patch('lib.cuckoo.core.scheduler.load_categories', return_value=([], False)), \
         patch('lib.cuckoo.core.scheduler.Config') as mock_config_cls:

        # Create a specific mock for the config instance
        mock_config_instance = MagicMock()
        mock_config_cls.return_value = mock_config_instance

        # Configure the 'timeouts' attribute to be a Mock that has integer attributes
        # We explicitly set these on the instance that Scheduler will use
        mock_config_instance.timeouts.default = 200
        mock_config_instance.timeouts.critical = 60

        # Configure 'cuckoo' attribute
        mock_config_instance.cuckoo.max_analysis_count = 0
        mock_config_instance.cuckoo.get.side_effect = lambda k, d=None: d if k == 'task_timeout' else MagicMock()

        sched = Scheduler()

        # Verify the mock setup was applied correctly
        assert sched.cfg.timeouts.default == 200
        assert sched.cfg.timeouts.critical == 60

        return sched

def test_monitoring_kill_stuck_vm(scheduler, caplog):
    # Fixed current time
    now_fixed = datetime(2023, 1, 1, 12, 0, 0)

    # Setup stuck task
    task = MagicMock(spec=Task)
    task.id = 123
    task.timeout = 200
    # Started 1 hour ago (3600 seconds)
    # Config: timeout=200, critical=60. Max runtime = 200 + 60 + 100 = 360s.
    # 3600s > 360s, so it should kill.
    task.started_on = now_fixed - timedelta(seconds=3600)

    machine = MagicMock(spec=Machine)
    machine.label = "vm1"

    machinery_manager = MagicMock()

    analysis = MagicMock(spec=AnalysisManager)
    analysis.task = task
    analysis.machine = machine
    analysis.machinery_manager = machinery_manager

    # Add to scheduler threads
    scheduler.analysis_threads.append(analysis)

    with patch('lib.cuckoo.core.scheduler.datetime') as mock_datetime:
        mock_datetime.now.return_value = now_fixed

        with caplog.at_level(logging.WARNING):
            scheduler.do_main_loop_work(queue.Queue())

    # Check warning log
    expected_msg_part = "Task #123 has been running for 3600.0 seconds, which is longer than the configured timeout + critical timeout + 100s. Killing VM."
    assert expected_msg_part in caplog.text

    # Check stop_machine called
    machinery_manager.stop_machine.assert_called_once_with(machine)

def test_monitoring_dont_kill_healthy_vm(scheduler, caplog):
    # Fixed current time
    now_fixed = datetime(2023, 1, 1, 12, 0, 0)

    # Setup healthy task
    task = MagicMock(spec=Task)
    task.id = 124
    task.timeout = 200
    # Started 10 seconds ago
    task.started_on = now_fixed - timedelta(seconds=10)

    machine = MagicMock(spec=Machine)
    machine.label = "vm2"

    machinery_manager = MagicMock()

    analysis = MagicMock(spec=AnalysisManager)
    analysis.task = task
    analysis.machine = machine
    analysis.machinery_manager = machinery_manager

    # Add to scheduler threads
    scheduler.analysis_threads.append(analysis)

    with patch('lib.cuckoo.core.scheduler.datetime') as mock_datetime:
        mock_datetime.now.return_value = now_fixed

        with caplog.at_level(logging.WARNING):
            scheduler.do_main_loop_work(queue.Queue())

    # Check NO warning log
    assert "Killing VM" not in caplog.text

    # Check stop_machine NOT called
    machinery_manager.stop_machine.assert_not_called()
