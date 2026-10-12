# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import signal
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from modules.auxiliary.sniffer import Sniffer


@pytest.fixture
def sniffer():
    s = Sniffer()
    s.task = MagicMock()
    s.task.id = 123
    s.task.route = "internet"
    s.options = {}
    return s


def test_stop_proc_already_exited(sniffer):
    sniffer.proc = MagicMock()
    sniffer.proc.poll.return_value = 0

    with patch("subprocess.check_output") as mock_check_output:
        sniffer.stop()
        mock_check_output.assert_not_called()


def test_stop_sudo_ps_called_process_error_exit_1(sniffer):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 676499
    sniffer.proc.poll.return_value = None
    sniffer.proc.communicate.return_value = (b"", b"")
    sniffer.proc.args = [sniffer.sudo_path, "-Z", "cape", "/usr/bin/tcpdump"]

    err = subprocess.CalledProcessError(1, ["ps", "--ppid", "676499", "-o", "pid="])
    with patch("subprocess.check_output", side_effect=err):
        sniffer.stop()

    sniffer.proc.communicate.assert_called_with(timeout=2)


def test_stop_sudo_ps_no_child_pids(sniffer):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 676499
    sniffer.proc.poll.return_value = None
    sniffer.proc.communicate.return_value = (b"", b"")
    sniffer.proc.args = [sniffer.sudo_path, "-Z", "cape", "/usr/bin/tcpdump"]

    with patch("subprocess.check_output", return_value=b"\n"):
        sniffer.stop()

    sniffer.proc.communicate.assert_called_with(timeout=2)


def test_stop_sudo_child_signal_success(sniffer):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 676499
    sniffer.proc.poll.return_value = None
    sniffer.proc.communicate.return_value = (b"", b"")
    sniffer.proc.args = [sniffer.sudo_path, "-Z", "cape", "/usr/bin/tcpdump"]

    with patch("subprocess.check_output", return_value=b" 71234 \n"), patch("os.kill") as mock_kill:
        sniffer.stop()

    mock_kill.assert_called_once_with(71234, signal.SIGTERM)
    sniffer.proc.communicate.assert_called_with(timeout=5)


def test_stop_sudo_child_lookup_error(sniffer):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 676499
    sniffer.proc.poll.return_value = None
    sniffer.proc.communicate.return_value = (b"", b"")
    sniffer.proc.args = [sniffer.sudo_path, "-Z", "cape", "/usr/bin/tcpdump"]

    with patch("subprocess.check_output", return_value=b" 71234 \n"), patch("os.kill", side_effect=ProcessLookupError):
        sniffer.stop()

    sniffer.proc.communicate.assert_called_with(timeout=2)


def test_stop_non_sudo_proc(sniffer):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 1234
    sniffer.proc.poll.return_value = None
    sniffer.proc.communicate.return_value = (b"", b"")
    sniffer.proc.args = ["/usr/bin/tcpdump", "-i", "eth0"]

    sniffer.stop()

    sniffer.proc.terminate.assert_called_once()
    sniffer.proc.communicate.assert_called_with(timeout=5)
