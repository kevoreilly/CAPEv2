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
    sched = Scheduler()
    sched.cfg = MagicMock()
    sched.cfg.timeouts.default = 200
    sched.cfg.timeouts.critical = 60
    return sched

def test_monitoring_kill_stuck_vm(scheduler, caplog):
    # Setup stuck task
    task = MagicMock(spec=Task)
    task.id = 123
    task.timeout = 200
    # Started 1 hour ago
    task.started_on = datetime.now() - timedelta(seconds=3600)
    
    machine = MagicMock(spec=Machine)
    machine.label = "vm1"

    machinery_manager = MagicMock()
    
    analysis = MagicMock(spec=AnalysisManager)
    analysis.task = task
    analysis.machine = machine
    analysis.machinery_manager = machinery_manager
    
    # Add to scheduler threads
    scheduler.analysis_threads.append(analysis)

    # Config: timeout=200, critical=60. Max runtime = 260 + 100 = 360s.
    # Current runtime = 3600s. Should kill.

    with caplog.at_level(logging.WARNING):
        scheduler.do_main_loop_work(queue.Queue())

    # Check warning log
    assert "Task #123 has been running for" in caplog.text
    assert "Killing VM" in caplog.text

    # Check stop_machine called
    machinery_manager.stop_machine.assert_called_once_with(machine)

def test_monitoring_dont_kill_healthy_vm(scheduler, caplog):
    # Setup healthy task
    task = MagicMock(spec=Task)
    task.id = 124
    task.timeout = 200
    # Started 10 seconds ago
    task.started_on = datetime.now() - timedelta(seconds=10)
    
    machine = MagicMock(spec=Machine)
    machine.label = "vm2"

    machinery_manager = MagicMock()
    
    analysis = MagicMock(spec=AnalysisManager)
    analysis.task = task
    analysis.machine = machine
    analysis.machinery_manager = machinery_manager
    
    # Add to scheduler threads
    scheduler.analysis_threads.append(analysis)

    with caplog.at_level(logging.WARNING):
        scheduler.do_main_loop_work(queue.Queue())

    # Check NO warning log
    assert "Killing VM" not in caplog.text

    # Check stop_machine NOT called
    machinery_manager.stop_machine.assert_not_called()
