# tests/test_rooter_nexthop.py
import pytest
import utils.rooter as rooter


@pytest.fixture
def rec(monkeypatch):
    """Record every run()/run_iptables() invocation as a list of argv tuples.

    utils.rooter functions reference settings.ip / ServicePaths.ip (both the same
    path at runtime, defined only in __main__), so inject both for unit tests.
    """
    calls = {"run": [], "iptables": []}

    def fake_run(*args):
        calls["run"].append(tuple(str(a) for a in args))
        return ("", "")  # (stdout, stderr); real run() never raises

    def fake_run_iptables(*args, **kwargs):
        calls["iptables"].append(tuple(str(a) for a in args))
        # A `-D` of an absent rule returns non-empty stderr; report "gone" so the idempotent
        # delete-until-gone loop (_iptables_delete_all) terminates after one delete in tests.
        if "-D" in args:
            return ("", "iptables: Bad rule (does a matching rule exist in that chain?).")
        return ("", "")

    class _Settings:
        ip = "ip"
    monkeypatch.setattr(rooter, "settings", _Settings, raising=False)
    monkeypatch.setattr(rooter.ServicePaths, "ip", "ip", raising=False)
    monkeypatch.setattr(rooter.ServicePaths, "iptables", "iptables", raising=False)
    monkeypatch.setattr(rooter, "run", fake_run)
    monkeypatch.setattr(rooter, "run_iptables", fake_run_iptables)
    return calls


def test_recorder_captures(rec):
    rooter.run("ip", "route", "show")
    assert rec["run"] == [("ip", "route", "show")]


# ---------------------------------------------------------------------------
# Task 1: nexthop_init
# ---------------------------------------------------------------------------

def test_nexthop_init_onlink(rec):
    rooter.nexthop_init("201", "ens6", "onlink")
    assert rec["run"] == [
        ("ip", "route", "flush", "table", "201"),
        ("ip", "route", "replace", "blackhole", "default", "table", "201"),
        ("ip", "route", "replace", "default", "dev", "ens6", "onlink", "table", "201"),
    ]


def test_nexthop_init_via(rec):
    rooter.nexthop_init("202", "ens7", "10.30.72.1")
    assert rec["run"] == [
        ("ip", "route", "flush", "table", "202"),
        ("ip", "route", "replace", "blackhole", "default", "table", "202"),
        ("ip", "route", "replace", "default", "via", "10.30.72.1", "dev", "ens7", "table", "202"),
    ]


def test_nexthop_init_skips_reserved_table(rec):
    # codex P1 / gemini critical: load_nexthop_profiles feeds each [gwX] rt_table straight into
    # nexthop_init's flush at startup, so a misconfigured reserved table (main/254/...) must NOT
    # be flushed — doing so would wipe the host's own routing. nexthop_teardown already guards
    # this set; the init path must too. No ip command runs at all for a reserved table.
    for bad in ("main", "local", "default", "254", "255", "253", "0"):
        rec["run"].clear()
        rooter.nexthop_init(bad, "ens6", "onlink")
        assert rec["run"] == [], f"nexthop_init flushed reserved table {bad!r}: {rec['run']}"


# ---------------------------------------------------------------------------
# Task 2: nexthop_enable
# ---------------------------------------------------------------------------

def test_nexthop_enable_argv(rec):
    # signature: (vm_ip, ingress_if, egress_if, rt_table, priority)
    rooter.nexthop_enable("192.168.100.42", "virbr0", "ens6", "201", "10042")
    # iproute2 + conntrack go through run(); nat/filter through run_iptables()
    assert rec["run"] == [
        ("conntrack", "-D", "-s", "192.168.100.42"),                                  # pre-bind flush
        ("ip", "rule", "del", "from", "192.168.100.42", "priority", "10042"),          # table-agnostic pre-clean (drops a stale old-table rebind rule too)
        ("ip", "rule", "add", "from", "192.168.100.42", "lookup", "201", "priority", "10042"),
    ]
    # Each iptables rule is delete-until-gone (idempotent; Copilot) then added once. The forward
    # ACCEPT goes into CAPE_ACCEPTED_SEGMENTS (jumped first in FORWARD), NOT a tail `-A FORWARD`
    # (else a libvirt `-i virbr* -j REJECT` would shadow it), and is constrained to the guest
    # ingress interface `-i virbr0` so a spoofed source from another NIC isn't forwarded (codex).
    assert rec["iptables"] == [
        ("-t", "nat", "-D", "POSTROUTING", "-s", "192.168.100.42", "-o", "ens6", "-j", "MASQUERADE"),
        ("-t", "nat", "-A", "POSTROUTING", "-s", "192.168.100.42", "-o", "ens6", "-j", "MASQUERADE"),
        ("-D", "CAPE_ACCEPTED_SEGMENTS", "-i", "virbr0", "-s", "192.168.100.42", "-o", "ens6", "-j", "ACCEPT"),
        ("-I", "CAPE_ACCEPTED_SEGMENTS", "-i", "virbr0", "-s", "192.168.100.42", "-o", "ens6", "-j", "ACCEPT"),
    ]
    # never a raw tail FORWARD append (regression guard for the shadowing bug)
    assert not any(a[:2] == ("-A", "FORWARD") for a in rec["iptables"])


# ---------------------------------------------------------------------------
# Task 3: nexthop_disable
# ---------------------------------------------------------------------------

def test_nexthop_disable_argv(rec):
    # signature: (vm_ip, ingress_if, egress_if, rt_table, priority)
    rooter.nexthop_disable("192.168.100.42", "virbr0", "ens6", "201", "10042")
    assert rec["run"] == [
        ("ip", "rule", "del", "from", "192.168.100.42", "lookup", "201", "priority", "10042"),
        ("conntrack", "-D", "-s", "192.168.100.42"),
    ]
    # mirror-delete (until gone) from the same chain/rules enable installed, incl. the -i ingress
    assert rec["iptables"] == [
        ("-t", "nat", "-D", "POSTROUTING", "-s", "192.168.100.42", "-o", "ens6", "-j", "MASQUERADE"),
        ("-D", "CAPE_ACCEPTED_SEGMENTS", "-i", "virbr0", "-s", "192.168.100.42", "-o", "ens6", "-j", "ACCEPT"),
    ]


# ---------------------------------------------------------------------------
# Task 4: nexthop_intra_exception_enable + nexthop_fail_closed_enable (split; codex P2)
# ---------------------------------------------------------------------------

def test_nexthop_intra_exception_argv(rec):
    # band_lo=10000 => exception at band_lo-1 = 9999, BELOW the per-task band so it wins over a bound
    # VM's `from <vm_ip> lookup <gw_table>` rule for intra-vm_net destinations. Installed regardless
    # of fail_closed (connectivity, not fail-closed) -- see test_nexthop_disabled_is_noop siblings.
    rooter.nexthop_intra_exception_enable("192.168.100.0/24", "10000")
    assert rec["run"] == [
        ("ip", "rule", "del", "from", "192.168.100.0/24", "to", "192.168.100.0/24", "lookup", "main", "priority", "9999"),
        ("ip", "rule", "add", "from", "192.168.100.0/24", "to", "192.168.100.0/24", "lookup", "main", "priority", "9999"),
    ]
    # ORDERING INVARIANT: the intra-subnet exception MUST sit below the per-task band (10000),
    # otherwise a bound VM's per-task rule shadows it and intra-vm_net traffic leaks to the gateway.
    intra = [r for r in rec["run"] if r[:3] == ("ip", "rule", "add") and "to" in r]
    assert intra and all(int(r[-1]) < 10000 for r in intra), intra


def test_nexthop_fail_closed_argv(rec):
    # fail_closed_enable now installs ONLY the blackhole (route + rule); the intra-subnet exception
    # is a separate primitive installed regardless of fail_closed (codex P2). Signature dropped band_lo.
    rooter.nexthop_fail_closed_enable("192.168.100.0/24", "250", "30000")
    assert rec["run"] == [
        ("ip", "route", "replace", "blackhole", "default", "table", "250"),
        ("ip", "rule", "del", "from", "192.168.100.0/24", "lookup", "250", "priority", "30000"),
        ("ip", "rule", "add", "from", "192.168.100.0/24", "lookup", "250", "priority", "30000"),
    ]
    # the blackhole primitive must NOT install the intra-subnet (`to vm_net`) exception anymore
    assert not any("to" in r for r in rec["run"])


# ---------------------------------------------------------------------------
# Task 5: nexthop_teardown + nexthop_configure
# ---------------------------------------------------------------------------

def test_nexthop_teardown_sweeps_policy_routing(rec, monkeypatch):
    # `ip rule show` returns two in-band per-task rules (from within vm_net), an out-of-band rule,
    # AND an UNRELATED host admin rule that happens to sit in the 10000-10255 band but whose source
    # is OUTSIDE vm_net -- teardown must NOT delete that one (codex P2).
    def fake_run(*args):
        rec["run"].append(tuple(str(a) for a in args))
        if args[:3] == ("ip", "rule", "show"):
            return ("10042: from 192.168.100.42 lookup 201\n"
                    "10043: from 192.168.100.43 lookup 202\n"
                    "10099: from 10.0.0.5 lookup 999\n"      # unrelated host rule in the band
                    "32766: from all lookup main\n", "")
        return ("", "")
    monkeypatch.setattr(rooter, "run", fake_run)

    rooter.nexthop_teardown("201,202", "192.168.100.0/24", "250", "30000", "10000", "10255")

    assert ("ip", "route", "flush", "table", "201") in rec["run"]
    assert ("ip", "route", "flush", "table", "202") in rec["run"]
    assert ("ip", "route", "del", "blackhole", "default", "table", "250") in rec["run"]
    assert ("ip", "rule", "del", "from", "192.168.100.0/24", "lookup", "250", "priority", "30000") in rec["run"]
    # intra-subnet exception rule also removed on teardown
    assert ("ip", "rule", "del", "from", "192.168.100.0/24", "to", "192.168.100.0/24", "lookup", "main", "priority", "9999") in rec["run"]
    # in-band per-task rules (source in vm_net) swept -- by FULL selector (from + priority), not
    # priority alone, so a host rule sharing the priority is never hit (codex).
    assert ("ip", "rule", "del", "from", "192.168.100.42", "priority", "10042") in rec["run"]
    assert ("ip", "rule", "del", "from", "192.168.100.43", "priority", "10043") in rec["run"]
    # nothing deleted for the out-of-band 32766 main rule, nor for the in-band-but-NOT-ours rule
    # (from 10.0.0.5, outside vm_net) -- neither its priority nor its source appears in any `del`.
    dels = [r for r in rec["run"] if r[:3] == ("ip", "rule", "del")]
    assert not any("32766" in r for r in dels)
    assert not any(("10099" in r) or ("10.0.0.5" in r) for r in dels)


def test_nexthop_teardown_skips_reserved_tables(rec):
    # gemini #14 HIGH: even if a gateway profile is misconfigured with a reserved/system table
    # id, teardown must NOT flush it — doing so (at startup + SIGTERM) would wipe the host's own
    # routing and take the box offline. The real gateway table IS still flushed.
    rooter.nexthop_teardown("main,254,201", "192.168.100.0/24", "250", "30000", "10000", "10255")
    assert ("ip", "route", "flush", "table", "201") in rec["run"]
    assert ("ip", "route", "flush", "table", "main") not in rec["run"]
    assert ("ip", "route", "flush", "table", "254") not in rec["run"]


def test_nexthop_configure_sets_globals(rec):
    rooter.nexthop_configure("201,202", "192.168.100.0/24", "250", "30000", "10000", "10255")
    assert rooter.GATEWAY_TABLES_CSV == "201,202"
    assert rooter.NEXTHOP_VM_NET == "192.168.100.0/24"
    assert rooter.NEXTHOP_FAIL_TABLE == "250"
    assert rooter.NEXTHOP_PRIORITY_LOW == "30000"
    assert rooter.NEXTHOP_BAND_LO == "10000"
    assert rooter.NEXTHOP_BAND_HI == "10255"


# ---------------------------------------------------------------------------
# SIGTERM teardown gate — disabled node must be a no-op (Copilot C3)
# ---------------------------------------------------------------------------

def test_sigterm_teardown_noop_when_nexthop_never_configured(rec, monkeypatch):
    # On a node that never enabled [nexthop], GATEWAY_TABLES_CSV is "" and the SIGTERM teardown
    # helper must issue ZERO ip commands — no host policy-routing mutation, and crucially no
    # 10000-10255 band sweep (which could delete an unrelated host rule). Guards the disabled=no-op
    # contract, which is otherwise untestable (handle_sigterm lives inside __main__).
    monkeypatch.setattr(rooter, "GATEWAY_TABLES_CSV", "", raising=False)
    rooter.nexthop_teardown_if_configured()
    assert rec["run"] == []
    assert rec["iptables"] == []


def test_sigterm_teardown_runs_when_configured(rec, monkeypatch):
    # When the loader configured nexthop this session, the SIGTERM helper DOES tear down the
    # gateway tables (positive control so the no-op test above can't pass by accident).
    monkeypatch.setattr(rooter, "GATEWAY_TABLES_CSV", "201,202", raising=False)
    monkeypatch.setattr(rooter, "NEXTHOP_VM_NET", "192.168.100.0/24", raising=False)
    monkeypatch.setattr(rooter, "NEXTHOP_FAIL_TABLE", "250", raising=False)
    monkeypatch.setattr(rooter, "NEXTHOP_PRIORITY_LOW", "30000", raising=False)
    monkeypatch.setattr(rooter, "NEXTHOP_BAND_LO", "10000", raising=False)
    monkeypatch.setattr(rooter, "NEXTHOP_BAND_HI", "10255", raising=False)
    rooter.nexthop_teardown_if_configured()
    assert ("ip", "route", "flush", "table", "201") in rec["run"]
    assert ("ip", "route", "flush", "table", "202") in rec["run"]


# --- nic_up: gateway liveness must require IFF_UP, not just existence (codex #14 P2) ---

def _fake_ip_link(line):
    def _co(*a, **k):
        return line
    return _co


def test_nic_up_true_when_admin_up(monkeypatch):
    class _S:
        ip = "ip"
    monkeypatch.setattr(rooter, "settings", _S, raising=False)
    monkeypatch.setattr(rooter.subprocess, "check_output",
                        _fake_ip_link("2: ens6: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP\n"))
    assert rooter.nic_up("ens6") is True


def test_nic_up_false_when_admin_down(monkeypatch):
    class _S:
        ip = "ip"
    monkeypatch.setattr(rooter, "settings", _S, raising=False)
    monkeypatch.setattr(rooter.subprocess, "check_output",
                        _fake_ip_link("3: ens7: <BROADCAST,MULTICAST> mtu 1500 state DOWN\n"))
    assert rooter.nic_up("ens7") is False


def test_nic_up_no_false_match_on_lower_up(monkeypatch):
    # LOWER_UP (carrier) present but IFF_UP absent -> not admin-up; "UP" must be an exact token
    class _S:
        ip = "ip"
    monkeypatch.setattr(rooter, "settings", _S, raising=False)
    monkeypatch.setattr(rooter.subprocess, "check_output",
                        _fake_ip_link("4: ens8: <BROADCAST,MULTICAST,LOWER_UP> mtu 1500 state DOWN\n"))
    assert rooter.nic_up("ens8") is False


def test_nic_up_false_when_missing(monkeypatch):
    class _S:
        ip = "ip"
    monkeypatch.setattr(rooter, "settings", _S, raising=False)

    def _raise(*a, **k):
        raise rooter.subprocess.CalledProcessError(1, "ip")

    monkeypatch.setattr(rooter.subprocess, "check_output", _raise)
    assert rooter.nic_up("nope0") is False
