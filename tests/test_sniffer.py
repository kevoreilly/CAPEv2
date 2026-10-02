# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import shutil
import subprocess

import pytest

from modules.auxiliary.sniffer import Sniffer, build_tcpdump_args

COMBINATIONS = [
    pytest.param(False, "", "", id="local"),
    pytest.param(False, "port 4444", "", id="local-custom"),
    pytest.param(False, "", "port 5555", id="local-bpf"),
    pytest.param(True, "", "", id="remote"),
    pytest.param(True, "port 4444", "", id="remote-custom"),
    pytest.param(True, "", "port 5555", id="remote-bpf"),
    pytest.param(True, "port 4444", "port 5555", id="remote-custom-bpf"),
]


def _args(custom="", bpf="", **kwargs):
    return build_tcpdump_args(
        "/usr/bin/tcpdump",
        "eth0",
        "192.168.56.101",
        "/tmp/dump.pcap",
        "192.168.56.1",
        "2042",
        custom=custom,
        bpf=bpf,
        **kwargs,
    )


@pytest.mark.parametrize("remote, custom, bpf", COMBINATIONS)
def test_no_bare_quote_tokens(remote, custom, bpf):
    """The old builder pushed bare "'" tokens into argv, unbalanced in four of
    the six option combinations."""
    args = build_tcpdump_args(
        "/usr/bin/tcpdump",
        "eth0",
        "192.168.56.101",
        "/tmp/dump.pcap",
        "192.168.56.1",
        "2042",
        user=None if remote else "cape",
        custom=custom,
        bpf=bpf,
    )
    assert "'" not in args
    assert args.count("(") == args.count(")")


def test_filter_contains_custom_and_bpf():
    args = _args(custom="port 4444", bpf="port 5555")
    assert args.count("and") == 10
    joined = " ".join(args)
    assert "( port 4444 )" in joined
    assert "( port 5555 )" in joined


def test_sudo_prefix_and_user():
    args = _args(sudo_path="/usr/bin/sudo", user="cape")
    assert args[:3] == ["/usr/bin/sudo", "--non-interactive", "--"]
    assert args[3] == "/usr/bin/tcpdump"
    assert "-Z" in args and args[args.index("-Z") + 1] == "cape"


def test_no_sudo_no_user():
    args = _args()
    assert args[0] == "/usr/bin/tcpdump"
    assert "-Z" not in args


def test_fog_host_filter():
    args = _args(fog_host="10.0.0.5")
    joined = " ".join(args)
    assert "and not ( dst host 10.0.0.5 )" in joined
    assert "10.0.0.5" not in " ".join(_args())


@pytest.mark.parametrize("remote, custom, bpf", COMBINATIONS)
def test_remote_script_is_valid_shell(tmp_path, remote, custom, bpf):
    """start() writes the remote command into a shell script. An unbalanced
    quote there made bash refuse the whole script."""
    args = build_tcpdump_args(
        "/usr/bin/tcpdump",
        "eth0",
        "192.168.56.101",
        "/tmp/tcp.dump.1",
        "192.168.56.1",
        "2042",
        custom=custom,
        bpf=bpf,
    )
    script = tmp_path / "sniffer.sh"
    script.write_text(f"{shlex.join(args)} & PID=$!\necho $PID > /tmp/1.pid\n")
    proc = subprocess.run(["bash", "-n", str(script)], capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr.decode()


@pytest.mark.skipif(shutil.which("tcpdump") is None, reason="tcpdump not installed")
@pytest.mark.parametrize("custom, bpf", [("", ""), ("port 4444", ""), ("", "port 5555"), ("port 4444", "port 5555")])
def test_tcpdump_accepts_filter(custom, bpf):
    """tcpdump -d only compiles the filter, it does not open the interface, so
    it needs no privileges."""
    args = _args(custom=custom, bpf=bpf)
    # Drop the binary and everything up to the filter expression.
    filter_args = args[args.index("host") :]
    proc = subprocess.run([shutil.which("tcpdump"), "-d", *filter_args], capture_output=True, timeout=30)
    assert proc.returncode == 0, proc.stderr.decode()


class FakeProc:
    def __init__(self, poll_value, args=None):
        self._poll = poll_value
        self.args = args or ["/usr/bin/tcpdump"]
        self.pid = 4242
        self.returncode = poll_value
        self.terminated = False
        self.killed = False

    def poll(self):
        return self._poll

    def communicate(self, timeout=None):
        return b"", b"boom"

    def terminate(self):
        self.terminated = True
        self._poll = -15

    def kill(self):
        self.killed = True


def _sniffer(options, proc=None, pid=None):
    sniffer = Sniffer.__new__(Sniffer)
    sniffer.options = options
    sniffer.proc = proc
    sniffer.pid = pid
    sniffer.task = type("Task", (), {"id": 1, "route": "internet"})()
    return sniffer


def test_stop_remote_without_pid_does_not_shell_out(monkeypatch):
    """Every early return in start()'s remote branch leaves self.pid unset."""
    calls = []
    monkeypatch.setattr(subprocess, "check_output", lambda *a, **kw: calls.append(a))
    _sniffer({"remote": True, "host": "user@host"}).stop()
    assert calls == []


def test_stop_without_proc_is_a_noop():
    _sniffer({}).stop()


def test_stop_does_not_kill_an_already_exited_sniffer(caplog):
    """poll() returns 0 for a clean exit, which `not poll()` read as running."""
    proc = FakeProc(0)
    _sniffer({}, proc=proc).stop()
    assert not proc.terminated
    assert not proc.killed
    assert "already exited" in caplog.text


def test_stop_terminates_a_running_sniffer():
    proc = FakeProc(None)
    _sniffer({}, proc=proc).stop()
    assert proc.terminated
