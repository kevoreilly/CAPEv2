# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import shlex
import shutil
import subprocess

import pytest

from modules.auxiliary import sniffer as sniffer_mod
from modules.auxiliary.sniffer import (
    Sniffer,
    build_remote_script,
    build_tcpdump_args,
    resolve_capture_interface,
    ssh_opts,
    sudo_allows_tcpdump,
)

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
    script.write_text(build_remote_script(shlex.join(args), 1))
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


def test_remote_script_detaches_and_echoes_pid():
    script = build_remote_script("/usr/bin/tcpdump -i eth0", 7)
    assert script.startswith("nohup /usr/bin/tcpdump -i eth0 ")
    assert "/tmp/cape-sniffer-7.log" in script
    assert "/tmp/cape-sniffer-7.err" in script
    assert script.rstrip().endswith("echo $!")
    # No remote pid file and no script file to copy over or clean up.
    assert ".pid" not in script
    assert ".sh" not in script


def test_ssh_opts_multiplex():
    opts = ssh_opts(42)
    assert opts.count("-o") == 4
    assert "ControlMaster=auto" in opts
    assert "ControlPath=/tmp/cape-sniffer-42-%C" in opts
    assert "BatchMode=yes" in opts
    assert any(o.startswith("ControlPersist=") for o in opts)


def test_sudo_probe_runs_once_per_path(monkeypatch):
    """sudo --list was measured at 333-348 ms on a host with a directory-backed
    sudoers policy, and it ran on every task start."""
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, b"", b"")

    monkeypatch.setattr(sniffer_mod, "_SUDO_CACHE", {})
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert sudo_allows_tcpdump("/usr/bin/sudo", "/usr/bin/tcpdump") is True
    assert sudo_allows_tcpdump("/usr/bin/sudo", "/usr/bin/tcpdump") is True
    assert len(calls) == 1
    assert calls[0] == ["/usr/bin/sudo", "--list", "--non-interactive", "/usr/bin/tcpdump"]

    # A different tcpdump path is a different answer, so it is probed again.
    assert sudo_allows_tcpdump("/usr/bin/sudo", "/usr/sbin/tcpdump") is True
    assert len(calls) == 2


def test_sudo_probe_caches_denial(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        raise subprocess.CalledProcessError(1, args)

    monkeypatch.setattr(sniffer_mod, "_SUDO_CACHE", {})
    monkeypatch.setattr(subprocess, "run", fake_run)

    assert sudo_allows_tcpdump("/usr/bin/sudo", "/usr/bin/tcpdump") is False
    assert sudo_allows_tcpdump("/usr/bin/sudo", "/usr/bin/tcpdump") is False
    assert len(calls) == 1


def test_sudo_probe_survives_missing_sudo(monkeypatch):
    monkeypatch.setattr(sniffer_mod, "_SUDO_CACHE", {})
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(FileNotFoundError()))
    assert sudo_allows_tcpdump("/nope/sudo", "/usr/bin/tcpdump") is False


def test_stop_remote_uses_one_multiplexed_connection(monkeypatch, tmp_path):
    invocations = []

    def fake_check_output(args, **kwargs):
        invocations.append(args)
        return b""

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: subprocess.CompletedProcess(a, 0, b"", b""))

    _sniffer({"remote": True, "host": "user@host"}, pid="1234").stop()

    # kill, scp, rm - and every one of them carries the mux options.
    assert len(invocations) == 3
    for args in invocations:
        assert "ControlMaster=auto" in args


def _make_bridge_sysfs(tmp_path, bridge_name="virbr1", port_macs=None):
    sys_net = tmp_path / "sys_net"
    brif = sys_net / bridge_name / "brif"
    brif.mkdir(parents=True)
    for port, mac in (port_macs or {}).items():
        (brif / port).mkdir()
        port_dir = sys_net / port
        port_dir.mkdir(parents=True)
        if mac is not None:
            (port_dir / "address").write_text(f"{mac}\n", encoding="utf-8")
    return sys_net


def test_resolve_capture_interface_non_bridge_unchanged(tmp_path):
    sys_net = tmp_path / "sys_net"
    (sys_net / "eth0").mkdir(parents=True)
    arp = tmp_path / "arp"
    assert (
        resolve_capture_interface(
            "eth0",
            "192.168.122.101",
            sys_net_root=str(sys_net),
            arp_path=str(arp),
        )
        == "eth0"
    )
    assert (
        resolve_capture_interface(
            "../virbr1",
            "192.168.122.101",
            sys_net_root=str(sys_net),
            arp_path=str(arp),
        )
        == "../virbr1"
    )


def test_resolve_capture_interface_libvirt_single_and_multi_nic(monkeypatch, tmp_path):
    sys_net = _make_bridge_sysfs(tmp_path, "virbr1", {"vnet2": "fe:54:00:aa:bb:02", "vnet9": "fe:54:00:aa:bb:09"})
    arp = tmp_path / "arp"

    closed = []
    xml_doc = """
    <domain type='kvm'>
      <name>win10_1</name>
      <devices>
        <interface type='network'>
          <mac address='52:54:00:aa:bb:01'/>
          <source network='mgmt' bridge='virbr0'/>
          <target dev='vnet1'/>
        </interface>
        <interface type='network'>
          <mac address='52:54:00:aa:bb:02'/>
          <source network='default' bridge='virbr1'/>
          <target dev='vnet2'/>
        </interface>
      </devices>
    </domain>
    """

    class FakeDom:
        def XMLDesc(self, flags=0):
            return xml_doc

    class FakeConn:
        def lookupByName(self, name):
            assert name == "win10_1"
            return FakeDom()

        def close(self):
            closed.append(True)

    fake_libvirt = type("FakeLibvirt", (), {"openReadOnly": staticmethod(lambda dsn: FakeConn())})()
    monkeypatch.setitem(__import__("sys").modules, "libvirt", fake_libvirt)

    machine = type("Machine", (), {"label": "win10_1"})()
    resolved = resolve_capture_interface(
        "virbr1",
        "192.168.122.102",
        machine=machine,
        machinery_name="kvm",
        kvm_dsn="qemu:///system",
        sys_net_root=str(sys_net),
        arp_path=str(arp),
    )
    assert resolved == "vnet2"
    assert closed == [True]


def test_resolve_capture_interface_libvirt_disambiguates_same_bridge_by_arp_mac(monkeypatch, tmp_path):
    sys_net = _make_bridge_sysfs(tmp_path, "virbr1", {"vnet2": "fe:54:00:aa:bb:02", "vnet3": "fe:54:00:aa:bb:03"})
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.122.103  0x1         0x2         52:54:00:AA:BB:03     *        virbr1\n",
        encoding="utf-8",
    )
    xml_doc = """
    <domain type='kvm'>
      <devices>
        <interface type='bridge'>
          <mac address='52:54:00:aa:bb:02'/>
          <source bridge='virbr1'/>
          <target dev='vnet2'/>
        </interface>
        <interface type='bridge'>
          <mac address='52:54:00:aa:bb:03'/>
          <source bridge='virbr1'/>
          <target dev='vnet3'/>
        </interface>
      </devices>
    </domain>
    """
    closed = []

    class FakeConn:
        def lookupByName(self, _name):
            return type("FakeDom", (), {"XMLDesc": lambda self, flags=0: xml_doc})()

        def close(self):
            closed.append(True)

    fake_libvirt = type("FakeLibvirt", (), {"openReadOnly": staticmethod(lambda dsn: FakeConn())})()
    monkeypatch.setitem(__import__("sys").modules, "libvirt", fake_libvirt)

    machine = type("Machine", (), {"label": "dual_nic_vm"})()
    assert (
        resolve_capture_interface(
            "virbr1",
            "192.168.122.103",
            machine=machine,
            machinery_name="kvm",
            sys_net_root=str(sys_net),
            arp_path=str(arp),
        )
        == "vnet3"
    )
    assert closed == [True]


def test_resolve_capture_interface_libvirt_error_closes_conn_and_falls_back_to_fdb(monkeypatch, tmp_path, caplog):
    sys_net = _make_bridge_sysfs(tmp_path, "virbr1", {"vnet4": "02:11:22:33:44:55", "vnet5": "02:11:22:33:44:66"})
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.122.104  0x1         0x0         00:00:00:00:00:00     *        virbr1\n"
        "192.168.122.105  0x1         0x2         52:54:00:11:22:33     *        virbr1\n",
        encoding="utf-8",
    )
    closed = []

    class BrokenConn:
        def lookupByName(self, _name):
            raise RuntimeError("libvirt domain lookup failed")

        def close(self):
            closed.append(True)

    fake_libvirt = type("FakeLibvirt", (), {"openReadOnly": staticmethod(lambda dsn: BrokenConn())})()
    monkeypatch.setitem(__import__("sys").modules, "libvirt", fake_libvirt)
    monkeypatch.setattr(shutil, "which", lambda name: "/sbin/bridge" if name == "bridge" else None)

    fdb_out = "02:11:22:33:44:55 dev vnet4 master virbr1 permanent\n52:54:00:11:22:33 dev vnet4 master virbr1\n"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kw: subprocess.CompletedProcess(args, 0, fdb_out, ""),
    )

    machine = type("Machine", (), {"label": "vm105"})()
    assert (
        resolve_capture_interface(
            "virbr1",
            "192.168.122.105",
            machine=machine,
            machinery_name="multi",
            sys_net_root=str(sys_net),
            arp_path=str(arp),
        )
        == "vnet4"
    )
    assert closed == [True]
    # Incomplete 0x0 ARP entry safely falls back to the bridge master interface and logs a warning.
    assert (
        resolve_capture_interface(
            "virbr1",
            "192.168.122.104",
            machine=machine,
            machinery_name="kvm",
            sys_net_root=str(sys_net),
            arp_path=str(arp),
        )
        == "virbr1"
    )
    assert "Could not resolve guest tap on bridge virbr1" in caplog.text


def test_resolve_capture_interface_missing_libvirt_and_ambiguous_fdb_or_tap_fallback(monkeypatch, tmp_path):
    sys_net = _make_bridge_sysfs(tmp_path, "virbr1", {"vnet6": "fe:54:00:de:ad:06", "vnet7": "fe:54:00:de:ad:07"})
    arp = tmp_path / "arp"
    arp.write_text(
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.122.106  0x1         0x2         52:54:00:de:ad:06     *        virbr1\n",
        encoding="utf-8",
    )
    # Simulate python-libvirt not installed (ImportError) and ambiguous 2-port FDB entry falling back to unique fe: MAC.
    monkeypatch.setitem(__import__("sys").modules, "libvirt", None)
    monkeypatch.setattr(shutil, "which", lambda name: "/sbin/bridge" if name == "bridge" else None)
    ambiguous_fdb = "52:54:00:de:ad:06 dev vnet6 master virbr1\n52:54:00:de:ad:06 dev vnet7 master virbr1\n"
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kw: subprocess.CompletedProcess(args, 0, ambiguous_fdb, ""),
    )

    machine = type("Machine", (), {"label": "vm106"})()
    assert (
        resolve_capture_interface(
            "virbr1",
            "192.168.122.106",
            machine=machine,
            machinery_name="kvm",
            sys_net_root=str(sys_net),
            arp_path=str(arp),
        )
        == "vnet6"
    )


def test_sniffer_start_uses_resolved_tap_without_mutating_machine_interface(monkeypatch):
    machine = type(
        "Machine",
        (),
        {
            "label": "win10_1",
            "ip": "192.168.122.101",
            "interface": "virbr1",
            "resultserver_ip": "192.168.122.1",
            "resultserver_port": 2042,
        },
    )()
    popen_calls = []
    resolve_calls = []
    ssh_calls = []

    def fake_popen(args, **kwargs):
        popen_calls.append(list(args))
        return FakeProc(None, args=list(args))

    def fake_resolve(interface, host, **kwargs):
        resolve_calls.append((interface, host, kwargs))
        return "vnet2"

    monkeypatch.setattr(sniffer_mod, "path_exists", lambda _p: True)
    monkeypatch.setattr(sniffer_mod, "sudo_allows_tcpdump", lambda _s, _t: True)
    monkeypatch.setattr(sniffer_mod, "ResultServer", lambda: None)
    monkeypatch.setattr(sniffer_mod, "resolve_capture_interface", fake_resolve)
    monkeypatch.setattr(sniffer_mod.cfg.cuckoo, "machinery", "kvm")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)

    sniffer = _sniffer({"tcpdump": "/usr/bin/tcpdump", "interface": "virbr1", "bpf": "not arp"})
    sniffer.machine = machine
    sniffer.db = type("DB", (), {"view_machine_by_label": staticmethod(lambda _lbl: machine)})()
    sniffer.start()

    assert len(popen_calls) == 1
    assert len(resolve_calls) == 1
    assert resolve_calls[0][2]["machinery_name"] == "kvm"
    assert resolve_calls[0][2]["kvm_dsn"]
    i_idx = popen_calls[0].index("-i")
    assert popen_calls[0][i_idx + 1] == "vnet2"
    # machine.interface must stay on virbr1 for rooter iptables -i virbr1 rules.
    assert machine.interface == "virbr1"

    # Disabling resolve_tap (both bool False from Config.getboolean and string "no") keeps capture on virbr1.
    for opt_val in (False, "no"):
        popen_calls.clear()
        resolve_calls.clear()
        sniffer_no_tap = _sniffer({"tcpdump": "/usr/bin/tcpdump", "interface": "virbr1", "resolve_tap": opt_val})
        sniffer_no_tap.machine = machine
        sniffer_no_tap.db = sniffer.db
        sniffer_no_tap.start()
        assert len(popen_calls) == 1
        assert resolve_calls == []
        i_idx = popen_calls[0].index("-i")
        assert popen_calls[0][i_idx + 1] == "virbr1"

    # Remote mode skips local tap resolution and passes virbr1 over SSH.
    resolve_calls.clear()
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda args, **kw: (ssh_calls.append(kw.get("input", "")), subprocess.CompletedProcess(args, 0, "9876\n", ""))[1],
    )
    sniffer_remote = _sniffer({"tcpdump": "/usr/bin/tcpdump", "interface": "virbr1", "remote": True, "host": "root@192.168.122.1"})
    sniffer_remote.machine = machine
    sniffer_remote.db = sniffer.db
    sniffer_remote.start()
    assert resolve_calls == []
    assert len(ssh_calls) == 1
    assert "-i virbr1" in ssh_calls[0]


@pytest.mark.parametrize(
    "enable_pcap, conf_route, task_route, aux_route, expect_skip",
    [
        (False, "none", None, None, True),
        (False, "none", "", None, True),
        (False, "none", "none", None, True),
        (False, "none", "DROP", None, True),
        (False, "vpn0", None, None, False),
        (False, "vpn0", "none", None, True),
        (False, "vpn0", "vpn0", "none", True),
        (False, "none", "vpn0", "", False),
        (False, "none", None, "gw2", False),
        (True, "none", None, None, False),
    ],
)
def test_sniffer_start_and_stop_route_gating(
    monkeypatch, enable_pcap, conf_route, task_route, aux_route, expect_skip
):
    fake_router_cfg = type(
        "Cfg",
        (),
        {"routing": type("Routing", (), {"enable_pcap": enable_pcap, "route": conf_route})()},
    )()
    monkeypatch.setattr(sniffer_mod, "router_cfg", fake_router_cfg)
    monkeypatch.setattr(sniffer_mod, "path_exists", lambda _p: True)
    monkeypatch.setattr(sniffer_mod, "sudo_allows_tcpdump", lambda _s, _t: False)
    monkeypatch.setattr(sniffer_mod, "ResultServer", lambda: None)

    machine = type(
        "M",
        (),
        {
            "label": "win10_1",
            "name": "win10_1",
            "ip": "192.168.122.101",
            "interface": "virbr1",
            "resultserver_ip": "192.168.122.1",
            "resultserver_port": 2042,
        },
    )()
    popen_calls = []
    monkeypatch.setattr(subprocess, "Popen", lambda args, **kw: popen_calls.append(list(args)) or FakeProc(None, args=list(args)))

    s = _sniffer({"tcpdump": "/usr/bin/tcpdump", "interface": "virbr1", "resolve_tap": False})
    s.task = type("T", (), {"id": 99, "route": task_route})()
    s.set_route(aux_route)
    s.machine = machine
    s.db = type("DB", (), {"view_machine_by_label": staticmethod(lambda _lbl: machine)})()
    s.start()

    if expect_skip:
        assert popen_calls == []
        assert s.proc is None
        sentinel = FakeProc(None)
        s.proc = sentinel
        s.stop()
        assert not sentinel.terminated
    else:
        assert len(popen_calls) == 1
        assert s.proc is not None
        proc = s.proc
        s.stop()
        assert proc.terminated

