import subprocess
import pytest
import utils.rooter as rooter

_CAPE_COMMENT = ("-m", "comment", "--comment", "CAPE-rooter")


@pytest.fixture
def rec(monkeypatch):
    state = {
        "cmds": [],
        "delete_counts": {},
        "lock_wait_once": set(),
        "chain_exists": False,
        "missing_chain": False,
        "fail_match": None,
    }

    def fake_subprocess_run(args, capture_output=True, text=True, check=False):
        tup = tuple(str(a) for a in args)
        state["cmds"].append(tup)

        if state["fail_match"] and state["fail_match"](tup):
            err_msg = (
                "Another app is currently holding the xtables lock. Stopped waiting after 5s.\n"
                if "-w" in tup
                else "Another app is currently holding the xtables lock. Perhaps you want to use the -w option?\n"
            )
            return subprocess.CompletedProcess(tup, 4, "", err_msg)

        if "-N" in tup and "CAPE_TOR_CLIENTS" in tup and state["chain_exists"]:
            return subprocess.CompletedProcess(tup, 1, "", "iptables: Chain already exists.\n")

        if "-D" in tup and tup[0] == "iptables":
            count = state["delete_counts"].get(tup, 0)
            state["delete_counts"][tup] = count + 1
            if state["missing_chain"] and "CAPE_TOR_CLIENTS" in tup:
                return subprocess.CompletedProcess(tup, 1, "", "iptables: No chain/target/match by that name.\n")
            if state.get("missing_nat_rule") and "nat" in tup:
                return subprocess.CompletedProcess(
                    tup,
                    1,
                    "",
                    "iptables: Bad rule (does a matching rule exist in that chain?).\n",
                )
            if count == 0 and any(tok in state["lock_wait_once"] for tok in tup):
                return subprocess.CompletedProcess(
                    tup,
                    0,
                    "",
                    "Another app is currently holding the xtables lock; still 4s left...\n",
                )
            if count >= 2:
                return subprocess.CompletedProcess(
                    tup,
                    1,
                    "",
                    "iptables: Bad rule (does a matching rule exist in that chain?).\n",
                )

        if any(tok in state["lock_wait_once"] for tok in tup):
            return subprocess.CompletedProcess(
                tup,
                0,
                "",
                "Another app is currently holding the xtables lock; still 4s left...\n",
            )

        return subprocess.CompletedProcess(tup, 0, "", "")

    monkeypatch.setattr(rooter.ServicePaths, "iptables", "iptables", raising=False)
    monkeypatch.setattr(rooter.subprocess, "run", fake_subprocess_run)
    return state


def test_socks5_enable_installs_forward_drop_and_tor_client_accept(rec):
    rooter.socks5_enable("172.16.1.4", "2042", "5354", "9040")

    conntrack_cmd = ("conntrack", "-D", "-s", "172.16.1.4")
    chain_new_cmd = ("iptables", "-w", "5", "-t", "raw", "-N", "CAPE_TOR_CLIENTS")
    tor_del = ("iptables", "-w", "5", "-t", "raw", "-D", "CAPE_TOR_CLIENTS", "--source", "172.16.1.4", "-p", "tcp", "-j", "ACCEPT", *_CAPE_COMMENT)
    tor_add = ("iptables", "-w", "5", "-t", "raw", "-A", "CAPE_TOR_CLIENTS", "--source", "172.16.1.4", "-p", "tcp", "-j", "ACCEPT", *_CAPE_COMMENT)
    fwd_del = ("iptables", "-w", "5", "-D", "FORWARD", "--source", "172.16.1.4", "-j", "DROP", *_CAPE_COMMENT)
    fwd_add = ("iptables", "-w", "5", "-I", "FORWARD", "1", "--source", "172.16.1.4", "-j", "DROP", *_CAPE_COMMENT)
    nat_redir = (
        "iptables",
        "-w",
        "5",
        "-t",
        "nat",
        "-I",
        "PREROUTING",
        "--source",
        "172.16.1.4",
        "-p",
        "tcp",
        "--syn",
        "!",
        "--dport",
        "2042",
        "-j",
        "REDIRECT",
        "--to-ports",
        "9040",
        *_CAPE_COMMENT,
    )
    nat_dns_udp = (
        "iptables",
        "-w",
        "5",
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "-p",
        "udp",
        "--dport",
        "53",
        "--source",
        "172.16.1.4",
        "-j",
        "REDIRECT",
        "--to-ports",
        "5354",
        *_CAPE_COMMENT,
    )

    assert conntrack_cmd in rec["cmds"]
    assert chain_new_cmd in rec["cmds"]
    assert rec["delete_counts"][tor_del] == 3
    assert rec["delete_counts"][fwd_del] == 3
    assert tor_add in rec["cmds"]
    assert fwd_add in rec["cmds"]
    assert nat_redir in rec["cmds"]
    assert nat_dns_udp in rec["cmds"]

    # Cross-call ordering: conntrack flush -> FORWARD DROP (fail-closed) -> CAPE_TOR_CLIENTS -> nat REDIRECT
    assert rec["cmds"].index(conntrack_cmd) < rec["cmds"].index(fwd_del)
    last_fwd_del = max(i for i, cmd in enumerate(rec["cmds"]) if cmd == fwd_del)
    assert last_fwd_del < rec["cmds"].index(fwd_add)
    assert rec["cmds"].index(fwd_add) < rec["cmds"].index(chain_new_cmd)
    assert rec["cmds"].index(chain_new_cmd) < rec["cmds"].index(tor_del)
    last_tor_del = max(i for i, cmd in enumerate(rec["cmds"]) if cmd == tor_del)
    assert last_tor_del < rec["cmds"].index(tor_add)
    assert rec["cmds"].index(tor_add) < rec["cmds"].index(nat_redir)

    # Every run_iptables/run_iptables_status call carries CAPE-rooter comment and -w 5; -N does not carry comment.
    for cmd in rec["cmds"]:
        if cmd[0] == "iptables":
            assert cmd[1:3] == ("-w", "5")
            if "-N" not in cmd:
                assert cmd[-4:] == _CAPE_COMMENT


def test_socks5_disable_removes_stacked_duplicates_and_flushes_conntrack_last(rec):
    rooter.socks5_disable("172.16.1.4", "2042", "5354", "9040")

    tor_del = ("iptables", "-w", "5", "-t", "raw", "-D", "CAPE_TOR_CLIENTS", "--source", "172.16.1.4", "-p", "tcp", "-j", "ACCEPT", *_CAPE_COMMENT)
    fwd_del = ("iptables", "-w", "5", "-D", "FORWARD", "--source", "172.16.1.4", "-j", "DROP", *_CAPE_COMMENT)
    nat_redir_del = (
        "iptables",
        "-w",
        "5",
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "--source",
        "172.16.1.4",
        "-p",
        "tcp",
        "--syn",
        "!",
        "--dport",
        "2042",
        "-j",
        "REDIRECT",
        "--to-ports",
        "9040",
        *_CAPE_COMMENT,
    )
    conntrack_cmd = ("conntrack", "-D", "-s", "172.16.1.4")

    assert rec["delete_counts"][tor_del] == 3
    assert rec["delete_counts"][fwd_del] == 3
    assert nat_redir_del in rec["cmds"]
    assert rec["cmds"][-1] == conntrack_cmd
    for cmd in rec["cmds"]:
        if cmd[0] == "iptables":
            assert cmd[1:3] == ("-w", "5")
            assert cmd[-4:] == _CAPE_COMMENT


def test_socks5_enable_tolerates_chain_exists_and_lock_wait_stderr(rec):
    rec["chain_exists"] = True
    rec["lock_wait_once"] = {"CAPE_TOR_CLIENTS", "FORWARD"}

    rooter.socks5_enable("172.16.1.4", "2042", "5354", "9040")

    tor_del = ("iptables", "-w", "5", "-t", "raw", "-D", "CAPE_TOR_CLIENTS", "--source", "172.16.1.4", "-p", "tcp", "-j", "ACCEPT", *_CAPE_COMMENT)
    fwd_del = ("iptables", "-w", "5", "-D", "FORWARD", "--source", "172.16.1.4", "-j", "DROP", *_CAPE_COMMENT)
    # Transient lock-wait stderr on rc=0 must not abort duplicate deletion loop
    assert rec["delete_counts"][tor_del] == 3
    assert rec["delete_counts"][fwd_del] == 3


def test_socks5_disable_tolerates_missing_chain_and_missing_nat_rule(rec):
    rec["missing_chain"] = True
    rec["missing_nat_rule"] = True
    rooter.socks5_disable("172.16.1.4", "2042", "5354", "9040")

    tor_del = ("iptables", "-w", "5", "-t", "raw", "-D", "CAPE_TOR_CLIENTS", "--source", "172.16.1.4", "-p", "tcp", "-j", "ACCEPT", *_CAPE_COMMENT)
    fwd_del = ("iptables", "-w", "5", "-D", "FORWARD", "--source", "172.16.1.4", "-j", "DROP", *_CAPE_COMMENT)
    assert rec["delete_counts"][tor_del] == 1
    assert rec["delete_counts"][fwd_del] == 3
    assert rec["cmds"][-1] == ("conntrack", "-D", "-s", "172.16.1.4")


@pytest.mark.parametrize(
    "label,matcher,expect_tor_attempted,expect_fwd_rollback,expect_tor_rollback,expect_nat_rollback",
    [
        ("fwd_delete", lambda cmd: "-D" in cmd and "FORWARD" in cmd, False, False, False, False),
        ("fwd_insert", lambda cmd: "-I" in cmd and "FORWARD" in cmd, False, False, False, False),
        ("chain_create", lambda cmd: "-N" in cmd and "CAPE_TOR_CLIENTS" in cmd, False, True, False, False),
        ("tor_delete", lambda cmd: "-D" in cmd and "CAPE_TOR_CLIENTS" in cmd, False, True, False, False),
        ("tor_add", lambda cmd: "-A" in cmd and "CAPE_TOR_CLIENTS" in cmd, True, True, False, False),
        ("nat_tcp_redirect", lambda cmd: "-I" in cmd and "PREROUTING" in cmd and "REDIRECT" in cmd, True, True, True, False),
        (
            "nat_dns_udp_redirect",
            lambda cmd: "-A" in cmd and "PREROUTING" in cmd and "udp" in cmd and "53" in cmd,
            True,
            True,
            True,
            True,
        ),
        ("output_drop", lambda cmd: "-A" in cmd and "OUTPUT" in cmd and "--source" in cmd, True, True, True, True),
    ],
)
def test_socks5_enable_fails_closed_and_rolls_back_on_error(
    rec, label, matcher, expect_tor_attempted, expect_fwd_rollback, expect_tor_rollback, expect_nat_rollback
):
    rec["fail_match"] = matcher
    with pytest.raises(RuntimeError):
        rooter.socks5_enable("172.16.1.4", "2042", "5354", "9040")

    tor_add = ("iptables", "-w", "5", "-t", "raw", "-A", "CAPE_TOR_CLIENTS", "--source", "172.16.1.4", "-p", "tcp", "-j", "ACCEPT", *_CAPE_COMMENT)
    fwd_add = ("iptables", "-w", "5", "-I", "FORWARD", "1", "--source", "172.16.1.4", "-j", "DROP", *_CAPE_COMMENT)
    fwd_del = ("iptables", "-w", "5", "-D", "FORWARD", "--source", "172.16.1.4", "-j", "DROP", *_CAPE_COMMENT)
    tor_del = ("iptables", "-w", "5", "-t", "raw", "-D", "CAPE_TOR_CLIENTS", "--source", "172.16.1.4", "-p", "tcp", "-j", "ACCEPT", *_CAPE_COMMENT)
    nat_redir_del = (
        "iptables",
        "-w",
        "5",
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "--source",
        "172.16.1.4",
        "-p",
        "tcp",
        "--syn",
        "!",
        "--dport",
        "2042",
        "-j",
        "REDIRECT",
        "--to-ports",
        "9040",
        *_CAPE_COMMENT,
    )

    assert (tor_add in rec["cmds"]) is expect_tor_attempted
    if expect_fwd_rollback:
        fwd_add_idx = rec["cmds"].index(fwd_add)
        assert fwd_del in rec["cmds"][fwd_add_idx + 1 :]
    if expect_tor_rollback:
        tor_add_idx = rec["cmds"].index(tor_add)
        assert tor_del in rec["cmds"][tor_add_idx + 1 :]
    if expect_nat_rollback:
        assert nat_redir_del in rec["cmds"]


@pytest.mark.parametrize(
    "label,matcher",
    [
        ("tor_delete", lambda cmd: "-D" in cmd and "CAPE_TOR_CLIENTS" in cmd),
        ("fwd_delete", lambda cmd: "-D" in cmd and "FORWARD" in cmd),
        ("nat_redir_delete", lambda cmd: "-D" in cmd and "PREROUTING" in cmd and "REDIRECT" in cmd),
    ],
)
def test_socks5_disable_completes_remaining_teardown_before_raising(rec, label, matcher):
    rec["fail_match"] = matcher
    with pytest.raises(RuntimeError):
        rooter.socks5_disable("172.16.1.4", "2042", "5354", "9040")

    fwd_del = ("iptables", "-w", "5", "-D", "FORWARD", "--source", "172.16.1.4", "-j", "DROP", *_CAPE_COMMENT)
    nat_dns_udp_del = (
        "iptables",
        "-w",
        "5",
        "-t",
        "nat",
        "-D",
        "PREROUTING",
        "-p",
        "udp",
        "--dport",
        "53",
        "--source",
        "172.16.1.4",
        "-j",
        "REDIRECT",
        "--to-ports",
        "5354",
        *_CAPE_COMMENT,
    )
    out_drop_del = ("iptables", "-w", "5", "-D", "OUTPUT", "--source", "172.16.1.4", "-j", "DROP", *_CAPE_COMMENT)

    assert fwd_del in rec["cmds"]
    assert nat_dns_udp_del in rec["cmds"]
    assert out_drop_del in rec["cmds"]
    assert rec["cmds"][-1] == ("conntrack", "-D", "-s", "172.16.1.4")


def test_iptables_delete_all_does_not_spin_on_xtables_lock_without_wait(rec, caplog):
    rec["fail_match"] = lambda cmd: "-D" in cmd and "POSTROUTING" in cmd
    with caplog.at_level("WARNING"):
        rooter._iptables_delete_all("-t", "nat", "-D", "POSTROUTING", "-s", "172.16.1.4", "-j", "MASQUERADE")

    postrouting_cmds = [cmd for cmd in rec["cmds"] if "POSTROUTING" in cmd]
    assert len(postrouting_cmds) == 1
    assert "Best-effort iptables delete failed" in caplog.text


def test_iptables_delete_all_removes_stacked_duplicates(rec):
    rooter._iptables_delete_all("-t", "nat", "-D", "POSTROUTING", "-s", "172.16.1.4", "-j", "MASQUERADE")
    del_cmd = ("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", "172.16.1.4", "-j", "MASQUERADE", *_CAPE_COMMENT)
    assert rec["delete_counts"][del_cmd] == 3


def test_run_status_handles_oserror(monkeypatch):
    def fake_run(*args, **kwargs):
        raise FileNotFoundError("No such file or directory: iptables")

    monkeypatch.setattr(rooter.subprocess, "run", fake_run)
    rc, out, err = rooter.run_status("iptables", "-L")
    assert rc == 1
    assert out == ""
    assert "No such file or directory" in err


def test_cleanup_rooter_preserves_cape_tor_clients_chain_and_strips_vm_rules(monkeypatch):
    saved_rules = "\n".join(
        [
            "*raw",
            ":PREROUTING ACCEPT [0:0]",
            ":VT_GUEST_FWD - [0:0]",
            ":CAPE_TOR_CLIENTS - [0:0]",
            "-A VT_GUEST_FWD -s 172.16.1.0/24 -d 10.192.0.0/10 -p tcp -j CAPE_TOR_CLIENTS",
            '-A CAPE_TOR_CLIENTS -s 172.16.1.4/32 -p tcp -m comment --comment "CAPE-rooter" -j ACCEPT',
            "COMMIT",
        ]
    )
    restored = {}

    class FakePopen:
        def __init__(self, cmd, **kwargs):
            restored["cmd"] = cmd

        def communicate(self, input=None):
            restored["input"] = input
            return ("", "")

    monkeypatch.setattr(rooter.ServicePaths, "iptables_save", "iptables-save", raising=False)
    monkeypatch.setattr(rooter.ServicePaths, "iptables_restore", "iptables-restore", raising=False)
    monkeypatch.setattr(rooter, "run", lambda *args: (saved_rules, ""))
    monkeypatch.setattr(rooter.subprocess, "Popen", FakePopen)
    monkeypatch.setattr(rooter.subprocess, "check_output", lambda *args, **kwargs: "")

    rooter.cleanup_rooter()

    assert ":CAPE_TOR_CLIENTS - [0:0]" in restored["input"]
    assert "-j CAPE_TOR_CLIENTS" in restored["input"]
    assert "172.16.1.4/32" not in restored["input"]
