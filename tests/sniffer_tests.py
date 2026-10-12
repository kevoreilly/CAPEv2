# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging
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


def test_stop_proc_already_exited_zero(sniffer, caplog):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 676499
    sniffer.proc.poll.return_value = 0
    sniffer.proc.communicate.return_value = (b"", b"10 packets captured\n")
    sniffer.proc.args = [sniffer.sudo_path, "-Z", "cape", "/usr/bin/tcpdump"]

    with caplog.at_level(logging.WARNING), patch("subprocess.check_output") as mock_check_output:
        sniffer.stop()
        mock_check_output.assert_not_called()

    sniffer.proc.communicate.assert_called_once_with(timeout=2)
    assert "already exited with code 0 before stop()" in caplog.text
    assert "10 packets captured" in caplog.text


def test_stop_proc_already_exited_nonzero(sniffer, caplog):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 676499
    sniffer.proc.poll.return_value = 1
    sniffer.proc.communicate.return_value = (b"", b"tcpdump: virbr1: You don't have permission to capture on that device\n")
    sniffer.proc.args = [sniffer.sudo_path, "-Z", "cape", "/usr/bin/tcpdump"]

    with caplog.at_level(logging.ERROR), patch("subprocess.check_output") as mock_check_output:
        sniffer.stop()
        mock_check_output.assert_not_called()

    sniffer.proc.communicate.assert_called_once_with(timeout=2)
    assert "exited prematurely with code 1 before stop()" in caplog.text
    assert "permission to capture" in caplog.text


def test_stop_sudo_ps_called_process_error_exit_1(sniffer, caplog):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 676499
    sniffer.proc.poll.side_effect = [None, 1]
    sniffer.proc.returncode = 1
    sniffer.proc.communicate.return_value = (b"", b"sudo: a password is required\n")
    sniffer.proc.args = [sniffer.sudo_path, "-Z", "cape", "/usr/bin/tcpdump"]

    err = subprocess.CalledProcessError(1, ["ps", "--ppid", "676499", "-o", "pid="], output=b"", stderr=b"")
    with caplog.at_level(logging.ERROR), patch("subprocess.check_output", side_effect=err):
        sniffer.stop()

    sniffer.proc.communicate.assert_called_once_with(timeout=2)
    assert "ps exited with 1" in caplog.text
    assert "sudo: a password is required" in caplog.text


def test_stop_sudo_ps_no_child_pids(sniffer, caplog):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 676499
    sniffer.proc.poll.side_effect = [None, 0]
    sniffer.proc.returncode = 0
    sniffer.proc.communicate.return_value = (b"", b"0 packets captured\n")
    sniffer.proc.args = [sniffer.sudo_path, "-Z", "cape", "/usr/bin/tcpdump"]

    with caplog.at_level(logging.ERROR), patch("subprocess.check_output", return_value=b"\n"):
        sniffer.stop()

    sniffer.proc.communicate.assert_called_once_with(timeout=2)
    assert "ps returned no pids" in caplog.text
    assert "0 packets captured" in caplog.text


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


def test_stop_sudo_child_lookup_error(sniffer, caplog):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 676499
    sniffer.proc.poll.return_value = None
    sniffer.proc.returncode = 0
    sniffer.proc.communicate.return_value = (b"", b"5 packets captured\n")
    sniffer.proc.args = [sniffer.sudo_path, "-Z", "cape", "/usr/bin/tcpdump"]

    with (
        caplog.at_level(logging.WARNING),
        patch("subprocess.check_output", return_value=b" 71234 \n"),
        patch("os.kill", side_effect=ProcessLookupError("No such process")),
    ):
        sniffer.stop()

    sniffer.proc.communicate.assert_called_with(timeout=2)
    assert "already terminated before signal" in caplog.text
    assert "5 packets captured" in caplog.text


def test_stop_non_sudo_proc(sniffer):
    sniffer.proc = MagicMock()
    sniffer.proc.pid = 1234
    sniffer.proc.poll.return_value = None
    sniffer.proc.communicate.return_value = (b"", b"")
    sniffer.proc.args = ["/usr/bin/tcpdump", "-i", "eth0"]

    sniffer.stop()

    sniffer.proc.terminate.assert_called_once()
    sniffer.proc.communicate.assert_called_with(timeout=5)
