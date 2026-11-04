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


# --------------------------------------------------------------------- QEMU


class _FakeQemuStdin:
    def __init__(self, fail_after_first_flush=False):
        self.writes = []
        self.flushes = 0
        self.fail_after_first_flush = fail_after_first_flush

    def write(self, data):
        if self.fail_after_first_flush and self.flushes >= 1:
            raise BrokenPipeError("pipe closed")
        self.writes.append(data)

    def flush(self):
        if self.fail_after_first_flush and self.flushes >= 1:
            raise BrokenPipeError("pipe closed")
        self.flushes += 1


class _FakeQemuProc:
    def __init__(self, timeouts_to_raise=0, fail_stdin_on_powerdown=False):
        self.stdin = _FakeQemuStdin(fail_after_first_flush=fail_stdin_on_powerdown)
        self.wait_timeouts = []
        self.timeouts_remaining = timeouts_to_raise
        self.terminated = False
        self.killed = False

    def wait(self, timeout=None):
        self.wait_timeouts.append(timeout)
        if self.timeouts_remaining > 0:
            self.timeouts_remaining -= 1
            raise subprocess.TimeoutExpired(cmd="qemu", timeout=timeout or 0)
        return 0

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


def _qemu_instance(proc):
    from modules.machinery import qemu

    obj = qemu.QEMU.__new__(qemu.QEMU)
    obj.state = {"vm-1": proc}

    class _DB:
        def view_machine_by_label(self, label):
            return type("M", (), {"name": "vm-1", "label": label})()

    obj.db = _DB()
    return obj


def test_qemu_stop_escalates_powerdown_terminate_and_kill_even_on_broken_pipe():
    proc = _FakeQemuProc(timeouts_to_raise=3, fail_stdin_on_powerdown=True)
    obj = _qemu_instance(proc)

    obj.stop("vm1")

    assert proc.terminated is True
    assert proc.killed is True
    assert obj.state["vm-1"] is None


# --------------------------------------------------------------------- VirtualBox


def test_virtualbox_stop_escalates_terminate_and_kill_on_timeout(monkeypatch):
    from modules.machinery import virtualbox

    class _FakeVBoxProc:
        def __init__(self):
            self.returncode = 0
            self.terminated = False
            self.killed = False
            self.calls = 0

        def communicate(self, timeout=None):
            self.calls += 1
            if self.calls <= 2:
                raise subprocess.TimeoutExpired(cmd="VBoxManage", timeout=timeout or 0)
            return b"", b""

        def terminate(self):
            self.terminated = True

        def kill(self):
            self.killed = True

    fake_proc = _FakeVBoxProc()
    monkeypatch.setattr(virtualbox.subprocess, "Popen", lambda *a, **kw: fake_proc)

    obj = virtualbox.VirtualBox.__new__(virtualbox.VirtualBox)
    obj.options = type("O", (), {"virtualbox": type("V", (), {"path": "/usr/bin/VBoxManage"})()})()
    obj._status = lambda _label: obj.RUNNING
    obj._wait_status = lambda _label, _state: None
    obj.stop("vm1")

    assert fake_proc.terminated is True
    assert fake_proc.killed is True
