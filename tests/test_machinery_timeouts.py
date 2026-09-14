"""Tests for the machinery/auxiliary wait paths that were unbounded or coarse.

These modules drive hypervisors, so nothing here touches real infrastructure: the
subprocess and libvirt boundaries are stubbed and only the control flow is exercised.
"""

import os
import subprocess
import sys
import time

import pytest

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.insert(0, CUCKOO_ROOT)


# --------------------------------------------------------------------- Mitmdump


def test_wait_for_pid_exit_returns_promptly_when_the_process_is_already_gone():
    from modules.auxiliary.Mitmdump import wait_for_pid_exit

    child = subprocess.Popen([sys.executable, "-c", "pass"])
    child.wait()

    start = time.monotonic()
    assert wait_for_pid_exit(child.pid, 15) is True
    # The old flat one-second tick could not beat this even in the best case.
    assert time.monotonic() - start < 0.5


def test_wait_for_pid_exit_honours_its_timeout():
    from modules.auxiliary.Mitmdump import wait_for_pid_exit

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        start = time.monotonic()
        assert wait_for_pid_exit(child.pid, 1) is False
        elapsed = time.monotonic() - start
        assert 1 <= elapsed < 3, elapsed
    finally:
        child.kill()
        child.wait()


# --------------------------------------------------------------------- Hyper-V


class _FakeCompleted:
    def __init__(self, stdout=b"Running"):
        self.stdout = stdout
        self.stderr = b""
        self.returncode = 0


def _hyperv():
    from modules.machinery import hyperv

    obj = hyperv.HyperV.__new__(hyperv.HyperV)
    obj.host = "hv.example"
    obj.username = "cape"
    obj.ssh_key = "/tmp/key"
    obj._control_path = "/tmp/cape-hyperv-test"
    return obj, hyperv


def test_hyperv_run_cmd_multiplexes_and_does_not_use_a_shell(monkeypatch):
    obj, hyperv = _hyperv()
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return _FakeCompleted()

    monkeypatch.setattr(hyperv.subprocess, "run", fake_run)

    assert obj.run_cmd("Get-VM") == "Running"

    argv = seen["argv"]
    assert isinstance(argv, list), "must not build a shell string"
    assert "shell" not in seen["kwargs"]
    assert seen["kwargs"]["timeout"] == hyperv.HyperV.CMD_TIMEOUT
    assert "ControlMaster=auto" in argv
    assert f"ControlPath={obj._control_path}" in argv
    assert argv[-1] == "powershell.exe Get-VM"
    assert argv[-2] == "cape@hv.example"


def test_hyperv_run_cmd_raises_on_timeout(monkeypatch):
    from lib.cuckoo.common.exceptions import CuckooMachineError

    obj, hyperv = _hyperv()

    def fake_run(argv, **kwargs):
        raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

    monkeypatch.setattr(hyperv.subprocess, "run", fake_run)

    with pytest.raises(CuckooMachineError):
        obj.run_cmd("Get-VM")


def test_hyperv_start_gives_up_instead_of_spinning(monkeypatch):
    from lib.cuckoo.common.exceptions import CuckooMachineError

    obj, hyperv = _hyperv()
    calls = []

    monkeypatch.setattr(hyperv.HyperV, "START_TIMEOUT", 0.3)
    monkeypatch.setattr(hyperv.HyperV, "START_POLL_INTERVAL", 0.05)
    monkeypatch.setattr(obj, "run_cmd", lambda cmd: calls.append(cmd) or "Off")
    monkeypatch.setattr(obj, "stop", lambda _id: None)

    class _DB:
        def view_machine_by_label(self, label):
            return type("M", (), {"snapshot": "snap"})()

    obj.db = _DB()

    with pytest.raises(CuckooMachineError):
        obj.start("vm1")

    # Bounded: a handful of polls, not thousands.
    assert len(calls) < 20, len(calls)
