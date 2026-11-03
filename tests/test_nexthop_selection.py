# tests/test_nexthop_selection.py
import pytest
import threading
import lib.cuckoo.core.rooter as core_rooter


class _Profile:
    def __init__(self, name, interface, rt_table, priority):
        self.name, self.interface, self.rt_table, self.priority = name, interface, rt_table, priority


def _seed(monkeypatch, live=("gw1", "gw2", "gw3")):
    gws = {n: _Profile(n, f"ens{6+i}", str(201 + i), 0) for i, n in enumerate(("gw1", "gw2", "gw3"))}
    monkeypatch.setattr(core_rooter, "gateways", gws, raising=False)
    monkeypatch.setattr(core_rooter, "_gw_cursor", 0, raising=False)
    monkeypatch.setattr(core_rooter, "_gw_live", lambda p: p.name in live)  # liveness shim
    return gws


def test_explicit_id_resolves(monkeypatch):
    _seed(monkeypatch)
    assert core_rooter._select_gateway("gw2").name == "gw2"


def test_explicit_id_down_fails_closed(monkeypatch):
    _seed(monkeypatch, live=("gw1", "gw3"))
    assert core_rooter._select_gateway("gw2") is None  # named-but-down => caller drops


def test_roundrobin_cycles_over_live(monkeypatch):
    _seed(monkeypatch, live=("gw1", "gw3"))  # gw2 down
    picks = [core_rooter._select_gateway("roundrobin").name for _ in range(4)]
    assert picks == ["gw1", "gw3", "gw1", "gw3"]


def test_empty_pool_fails_closed(monkeypatch):
    monkeypatch.setattr(core_rooter, "gateways", {}, raising=False)
    assert core_rooter._select_gateway("roundrobin") is None


def test_roundrobin_threadsafe(monkeypatch):
    _seed(monkeypatch)
    out = []
    lock = threading.Lock()

    def worker():
        p = core_rooter._select_gateway("roundrobin")
        with lock:
            out.append(p.name)
    threads = [threading.Thread(target=worker) for _ in range(300)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # even distribution across 3 live gateways, no crash
    assert all(out.count(n) == 100 for n in ("gw1", "gw2", "gw3"))


def test_unknown_selector_fails_closed(monkeypatch):
    # gemini #15: a value that is neither a known gateway id nor 'random'/'roundrobin' must NOT
    # silently fall through to roundrobin — it fails closed (returns None so the caller drops).
    _seed(monkeypatch)
    assert core_rooter._select_gateway("bogus") is None
    assert core_rooter._select_gateway("roundrobin").name in ("gw1", "gw2", "gw3")  # policy still works


# ---------------------------------------------------------------------------
# _FakeRouting helper shared by T7 and T8 tests
# ---------------------------------------------------------------------------

class _FakeGw1:
    """Fake [gw1] section: rt_table is an int (as config.getint would produce)."""
    name = "gw1"
    interface = "ens6"
    next_hop = "onlink"
    rt_table = 201  # int — loader must coerce to str


class _FakeNexthop:
    def __init__(self, enabled=True, route="gw1"):
        self.enabled = enabled
        self.gateways = "gw1"
        self.default_policy = "roundrobin"
        self.fail_closed = True
        self.vm_net = "192.168.100.0/24"


class _FakeRoutingSection:
    """Fake top-level routing config section (routing.routing.route)."""
    def __init__(self, route="none"):
        self.route = route


class _FakeVpn:
    enabled = False


class _FakeRouting:
    """Minimal fake routing config for T7/T8 tests.

    Exposes:
      .nexthop  — _FakeNexthop (enabled/disabled, gateways="gw1")
      .gw1      — _FakeGw1 (interface, next_hop, rt_table as int)
      .routing  — .route
      .vpn      — .enabled = False
      .get(name) -> attribute named `name`
    """
    def __init__(self, nexthop_enabled=True, route="none"):
        self.nexthop = _FakeNexthop(enabled=nexthop_enabled, route=route)
        self.gw1 = _FakeGw1()
        self.routing = _FakeRoutingSection(route=route)
        self.vpn = _FakeVpn()

    def get(self, name):
        return getattr(self, name)


# ---------------------------------------------------------------------------
# T7: [gwX] loader — populates gateways global + coerces rt_table to str
# ---------------------------------------------------------------------------

def test_gwx_loader_populates_and_coerces(monkeypatch):
    import lib.cuckoo.core.startup as startup
    recorded = []
    # startup.gateways is the dict object the loader writes into (imported reference, same object
    # as core_rooter.gateways unless replaced).  Clear it in place so both refs see the reset.
    startup.gateways.clear()
    monkeypatch.setattr(startup, "rooter", lambda cmd, *a, **k: recorded.append((cmd, a)) or {}, raising=False)
    startup.load_nexthop_profiles(_FakeRouting(), apply_rooter_state=True)
    # Check via startup.gateways (the dict the function mutated)
    assert "gw1" in startup.gateways
    assert startup.gateways["gw1"].rt_table == "201"   # coerced to str
    assert ("nexthop_init", ("201", "ens6", "onlink")) in recorded
    assert any(c == "nexthop_fail_closed_enable" for c, _ in recorded)
    assert any(c == "nexthop_teardown" for c, _ in recorded)
    # ORDER MATTERS: nexthop_teardown flushes the gateway tables, so it must run
    # BEFORE nexthop_init (which builds them) — otherwise it wipes the fresh routes.
    # And fail-closed arms last. (Regression guard for the loader ordering bug found
    # in the live FakeNet detonation on 2026-07-01.)
    cmds = [c for c, _ in recorded]
    assert cmds.index("nexthop_teardown") < cmds.index("nexthop_init"), \
        f"teardown must precede init, got order: {cmds}"
    assert cmds.index("nexthop_init") < cmds.index("nexthop_fail_closed_enable"), \
        f"init must precede fail_closed arm, got order: {cmds}"


class _DictSection(dict):
    """Faithful stand-in for CAPE's config Dictionary: attribute access maps to dict
    keys and a MISSING key returns None (not AttributeError). This is exactly how a
    real [gwX] section behaves for the absent `name` field."""
    def __getattr__(self, k):
        return self.get(k)

    def __setattr__(self, k, v):
        self[k] = v


def test_gwx_loader_stamps_profile_name_from_section_header(monkeypatch):
    """Regression (live FakeNet detonation, 2026-07-01): [gwX] sections carry no `name =`
    field (unlike [vpnX]/[socks5]), so config Dictionary.__getattr__ returns None for
    entry.name. The loader MUST stamp the section header as the profile id — otherwise
    analysis_manager._resolve_nexthop sets self.nexthop_id = profile.name = None, and
    _dispatch_nexthop's `if not self.nexthop_id: return` silently no-ops: the per-task
    source rule never installs and every real task falls through to the fail-closed
    blackhole. Unit tests missed it because the fakes hard-coded .name; the real config
    does not."""
    import lib.cuckoo.core.startup as startup

    class _NamelessRouting(_FakeRouting):
        def __init__(self):
            super().__init__()
            # a [gw1] section with NO `name` key — the real routing.conf shape
            self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=201)

    routing = _NamelessRouting()
    # precondition: the section reports no name (mimics config Dictionary -> None)
    assert routing.gw1.name is None
    startup.gateways.clear()
    monkeypatch.setattr(startup, "rooter", lambda cmd, *a, **k: {}, raising=False)
    startup.load_nexthop_profiles(routing)
    # postcondition: loader stamped the id so nexthop_id resolves to a real value
    assert startup.gateways["gw1"].name == "gw1"


# ---------------------------------------------------------------------------
# T8: validate_default_route — gateway route accepted; unknown raises
# ---------------------------------------------------------------------------

def test_nexthop_default_route_boots_without_vpn(monkeypatch):
    import lib.cuckoo.core.startup as startup
    # Seed gateways so "gw1" is known. validate_default_route reads the module-global
    # `gateways` in startup's namespace (bound via `from ... import gateways`), so patch
    # THAT binding — patching core_rooter.gateways would be invisible to startup.
    monkeypatch.setattr(startup, "gateways", {"gw1": _FakeGw1()})
    # routing.route = "gw1", nexthop enabled, vpn disabled -> must NOT raise
    startup.validate_default_route(_FakeRouting(route="gw1"))


def test_nexthop_policy_token_default_route_boots_without_vpn(monkeypatch):
    # codex P2: a pool-policy token (roundrobin/random) is a valid DEFAULT route when nexthop is
    # on — _resolve_nexthop maps it to default_policy and picks from the live pool. validate must
    # accept it WITHOUT a VPN, even though it is not a concrete gateway id; otherwise the
    # documented pool default raises the vpn-not-enabled error at startup. (gateways empty on
    # purpose to prove acceptance is by-token, not by-id.)
    import lib.cuckoo.core.startup as startup
    monkeypatch.setattr(startup, "gateways", {})
    for tok in ("roundrobin", "random"):
        startup.validate_default_route(_FakeRouting(route=tok))  # must NOT raise


def test_nexthop_sentinel_default_route_boots_without_vpn(monkeypatch):
    # Copilot: `[routing] route = nexthop` is the documented pool default (maps to default_policy).
    # validate_default_route must accept the sentinel WITHOUT a VPN, else the default_policy path is
    # unreachable in production. gateways empty on purpose (sentinel is not a gateway id).
    import lib.cuckoo.core.startup as startup
    monkeypatch.setattr(startup, "gateways", {})
    startup.validate_default_route(_FakeRouting(route="nexthop"))  # must NOT raise


def test_gateway_named_nexthop_raises(monkeypatch):
    # Copilot: "nexthop" is the pool sentinel, so a [gwX] must not be named it (ambiguous with the
    # default-policy route). Rejected via _RESERVED_ROUTE_NAMES.
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    class _GwNamedNexthop(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.nexthop = _DictSection(enabled=True, gateways="nexthop", default_policy="roundrobin",
                                        fail_closed=True, vm_net="192.168.100.0/24")
            self.nexthop_section = _DictSection(interface="ens6", next_hop="onlink", rt_table=201)

        def get(self, name):
            return self.nexthop_section if name == "nexthop" else getattr(self, name)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    with pytest.raises(CuckooStartupError):
        startup.load_nexthop_profiles(_GwNamedNexthop())


def test_unknown_gateway_default_route_raises(monkeypatch):
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError
    # gateways is empty — "gw9" is unknown (patch startup's binding, not core_rooter's)
    monkeypatch.setattr(startup, "gateways", {})
    with pytest.raises(CuckooStartupError):
        startup.validate_default_route(_FakeRouting(route="gw9"))


# ---------------------------------------------------------------------------
# T11: no-regress — disabled [nexthop] is a no-op (empty gateways, no rooter calls)
# ---------------------------------------------------------------------------

def test_nexthop_disabled_is_noop(monkeypatch):
    import lib.cuckoo.core.startup as startup
    import lib.cuckoo.core.rooter as core_rooter
    monkeypatch.setattr(core_rooter, "gateways", {}, raising=False)
    called = []
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: called.append(a) or {}, raising=False)
    startup.load_nexthop_profiles(_FakeRouting(nexthop_enabled=False))
    assert core_rooter.gateways == {} and called == []


# ---------------------------------------------------------------------------
# gemini #14 MEDIUM: [nexthop]/[gwX] required-option validation (clear startup error)
# ---------------------------------------------------------------------------

def test_nexthop_missing_vm_net_raises(monkeypatch):
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    class _NexthopNoVmNet(_FakeRouting):
        def __init__(self):
            super().__init__()
            # enabled + gateways set, but vm_net absent (config Dictionary -> None)
            self.nexthop = _DictSection(enabled=True, gateways="gw1", default_policy="roundrobin", fail_closed=True)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    with pytest.raises(CuckooStartupError):
        startup.load_nexthop_profiles(_NexthopNoVmNet())


def test_gwx_missing_interface_raises(monkeypatch):
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    class _GwNoInterface(_FakeRouting):
        def __init__(self):
            super().__init__()
            # [gw1] with next_hop + rt_table but NO interface (config Dictionary -> None)
            self.gw1 = _DictSection(next_hop="onlink", rt_table=201)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    with pytest.raises(CuckooStartupError):
        startup.load_nexthop_profiles(_GwNoInterface())


def test_gwx_reserved_rt_table_raises(monkeypatch):
    # ADVERSARIAL-REVIEW HIGH (2026-07-08): the nexthop_init reserved-table guard alone leaves a
    # fail-OPEN — a [gwX] with rt_table=main is still registered/selectable, and its per-task rule
    # `from vm_ip lookup main priority 100xx` (below the 30000 blackhole) routes the VM out the host
    # default route. Reject a reserved rt_table at LOAD so the profile can never be dispatched.
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    for bad in ("main", "local", "default", "254", "255", "253", "0"):
        class _GwReservedTable(_FakeRouting):
            def __init__(self, rt=bad):
                super().__init__()
                self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=rt)

        startup.gateways.clear()
        monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
        with pytest.raises(CuckooStartupError):
            startup.load_nexthop_profiles(_GwReservedTable())
        assert "gw1" not in startup.gateways, f"reserved-table gw1 (rt={bad}) leaked into gateways"


def test_gwx_rt_table_is_fail_table_raises(monkeypatch):
    # codex P2: a [gwX] rt_table == NEXTHOP_FAIL_TABLE (250) is not a kernel-reserved table so it
    # passes the reserved-table check, but nexthop_fail_closed_enable's `ip route replace blackhole
    # default table 250` would overwrite the gateway's default with a blackhole → every task on that
    # gateway silently drops. Reject it at load.
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    class _GwFailTable(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=startup.NEXTHOP_FAIL_TABLE)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    with pytest.raises(CuckooStartupError):
        startup.load_nexthop_profiles(_GwFailTable())
    assert "gw1" not in startup.gateways


def test_gwx_duplicate_rt_table_raises(monkeypatch):
    # codex P2: two [gwX] sharing an rt_table → nexthop_init flush/replaces the one table per profile
    # so the last gateway's default wins, but the earlier gateway stays selectable with a per-task rule
    # pointing at a table for the WRONG egress interface → misroute/drop. Fail startup on duplicates.
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    class _GwDupTable(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.nexthop = _DictSection(enabled=True, gateways="gw1,gw2", default_policy="roundrobin",
                                        fail_closed=True, vm_net="192.168.100.0/24")
            self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=201)
            self.gw2 = _DictSection(interface="ens7", next_hop="onlink", rt_table=201)  # same table -> reject

    startup.gateways.clear()
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    with pytest.raises(CuckooStartupError):
        startup.load_nexthop_profiles(_GwDupTable())


def test_nexthop_intra_exception_installed_even_when_fail_closed_off(monkeypatch):
    # codex P2: the intra-subnet exception is a CONNECTIVITY guarantee, separate from the blackhole.
    # With [nexthop] fail_closed=no it MUST still be installed (else a bound VM's intra-vm_net traffic
    # misroutes to the gateway), while the blackhole (nexthop_fail_closed_enable) must NOT be.
    import lib.cuckoo.core.startup as startup
    recorded = []

    class _NexthopNoFailClosed(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.nexthop = _DictSection(enabled=True, gateways="gw1", default_policy="roundrobin",
                                        fail_closed=False, vm_net="192.168.100.0/24")

    startup.gateways.clear()
    monkeypatch.setattr(startup, "vpns", {}, raising=False)
    monkeypatch.setattr(startup, "rooter", lambda cmd, *a, **k: recorded.append(cmd) or {}, raising=False)
    startup.load_nexthop_profiles(_NexthopNoFailClosed(), apply_rooter_state=True)
    assert "nexthop_intra_exception_enable" in recorded
    assert "nexthop_fail_closed_enable" not in recorded


def test_gwx_rt_table_collides_with_vpn_raises(monkeypatch):
    # adversarial-review HIGH: a [gwX] rt_table equal to a configured VPN's rt_table would clobber the
    # VPN's just-built routing table (nexthop_init flush/replace) -> VPN tasks silently egress the
    # gateway NIC instead of the tunnel (VPN-isolation break). Reject at load. The VPN rt_table is an
    # int here to prove the str-coercion works (config may give int or name).
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    class _GwVpnTable(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=201)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "vpns", {"vpn0": type("V", (), {"rt_table": 201})()}, raising=False)
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    with pytest.raises(CuckooStartupError):
        startup.load_nexthop_profiles(_GwVpnTable())
    assert "gw1" not in startup.gateways


def test_gwx_rt_table_collides_with_dirty_line_raises(monkeypatch):
    # adversarial-review HIGH: a [gwX] rt_table equal to routing.routing.rt_table (the internet
    # dirty-line table) would be clobbered by the dirty-line init_rttable that runs AFTER us ->
    # gateway tasks egress the dirty line instead of the gateway egress_if. Reject at load.
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    class _GwDirtyLineTable(_FakeRouting):
        def __init__(self):
            super().__init__()
            # dirty-line ENABLED (internet != none) and its table == the gw table -> collision
            self.routing = _DictSection(route="internet", internet="ens_wan", rt_table="201")
            self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=201)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "vpns", {}, raising=False)
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    with pytest.raises(CuckooStartupError):
        startup.load_nexthop_profiles(_GwDirtyLineTable())
    assert "gw1" not in startup.gateways


def test_gwx_rt_table_reused_when_dirty_line_disabled_ok(monkeypatch):
    # codex P2: when the dirty line is DISABLED (internet = none) its rt_table is never built, so a
    # [gwX] reusing that id must NOT be rejected -- a nexthop-only node must be able to start.
    import lib.cuckoo.core.startup as startup

    class _GwDirtyLineDisabled(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.routing = _DictSection(route="none", internet="none", rt_table="201")
            self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=201)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "vpns", {}, raising=False)
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    startup.load_nexthop_profiles(_GwDirtyLineDisabled())   # must NOT raise
    assert "gw1" in startup.gateways


def test_invalid_default_policy_raises(monkeypatch):
    # codex P2: default_policy that is neither roundrobin/random nor a configured gateway id resolves
    # to None in _select_gateway -> every pool task silently drops. Reject it at startup.
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    class _BadPolicy(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.nexthop = _DictSection(enabled=True, gateways="gw1", default_policy="gw2",
                                        fail_closed=True, vm_net="192.168.100.0/24")
            self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=201)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "vpns", {}, raising=False)
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    with pytest.raises(CuckooStartupError):
        startup.load_nexthop_profiles(_BadPolicy())


def test_gateway_id_default_policy_ok(monkeypatch):
    # default_policy may name a configured gateway id (pin the pool default to one exit).
    import lib.cuckoo.core.startup as startup

    class _GwPolicy(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.nexthop = _DictSection(enabled=True, gateways="gw1", default_policy="gw1",
                                        fail_closed=True, vm_net="192.168.100.0/24")
            self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=201)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "vpns", {}, raising=False)
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    startup.load_nexthop_profiles(_GwPolicy())   # must NOT raise
    assert "gw1" in startup.gateways


def test_gateway_named_like_policy_token_raises(monkeypatch):
    # A [gwX] must not be named a pool-policy token (roundrobin/random): _select_gateway would
    # treat the name as the policy, not the id, so the profile could never be explicitly selected.
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    for tok in ("roundrobin", "random"):
        class _GwPolicyName(_FakeRouting):
            def __init__(self, name=tok):
                super().__init__()
                self.nexthop = _DictSection(enabled=True, gateways=name, default_policy="roundrobin",
                                            fail_closed=True, vm_net="192.168.100.0/24")
                setattr(self, name, _DictSection(interface="ens6", next_hop="onlink", rt_table=201))

        startup.gateways.clear()
        monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
        with pytest.raises(CuckooStartupError):
            startup.load_nexthop_profiles(_GwPolicyName())


def test_nexthop_enabled_empty_pool_raises(monkeypatch):
    # gemini medium: [nexthop] enabled with an empty/blank gateways list parses zero profiles.
    # Without a guard, every task would silently fall through to the fail-closed blackhole —
    # so fail loudly at startup instead. `gateways = ""` passes the not-None required-option
    # check (empty string != None) but yields no profiles.
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    class _NexthopEmptyPool(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.nexthop = _DictSection(enabled=True, gateways="  ,  ", default_policy="roundrobin",
                                        fail_closed=True, vm_net="192.168.100.0/24")

    startup.gateways.clear()
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    with pytest.raises(CuckooStartupError):
        startup.load_nexthop_profiles(_NexthopEmptyPool())


def test_gw_live_queries_nic_up(monkeypatch):
    # _gw_live must consult nic_up (admin-up), NOT nic_available (which is true for DOWN links).
    calls = []

    def _fake_rooter(cmd, *a):
        calls.append(cmd)
        return {"output": (cmd == "nic_up" and a and a[0] == "ens-up")}

    monkeypatch.setattr(core_rooter, "rooter", _fake_rooter)
    assert core_rooter._gw_live(_Profile("gw1", "ens-up", "201", 0)) is True
    assert core_rooter._gw_live(_Profile("gw2", "ens-down", "202", 0)) is False
    assert "nic_up" in calls and "nic_available" not in calls


def test_fail_closed_table_collides_with_vpn_raises(monkeypatch):
    # codex P2: fail_closed installs a blackhole into NEXTHOP_FAIL_TABLE; if a VPN already uses that
    # table, the blackhole would overwrite the VPN's default route and drop its traffic. Reject at load.
    import lib.cuckoo.core.startup as startup
    from lib.cuckoo.common.exceptions import CuckooStartupError

    class _FailTableVpn(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.nexthop = _DictSection(enabled=True, gateways="gw1", default_policy="roundrobin",
                                        fail_closed=True, vm_net="192.168.100.0/24")
            self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=201)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "vpns", {"vpn0": type("V", (), {"rt_table": startup.NEXTHOP_FAIL_TABLE})()}, raising=False)
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    with pytest.raises(CuckooStartupError):
        startup.load_nexthop_profiles(_FailTableVpn())


def test_fail_closed_table_collision_ignored_when_fail_closed_off(monkeypatch):
    # the collision only matters when fail_closed arms the blackhole; with fail_closed=no a VPN on
    # table 250 is fine (we never write that table), so startup must NOT reject it.
    import lib.cuckoo.core.startup as startup

    class _FailTableVpnOff(_FakeRouting):
        def __init__(self):
            super().__init__()
            self.nexthop = _DictSection(enabled=True, gateways="gw1", default_policy="roundrobin",
                                        fail_closed=False, vm_net="192.168.100.0/24")
            self.gw1 = _DictSection(interface="ens6", next_hop="onlink", rt_table=201)

    startup.gateways.clear()
    monkeypatch.setattr(startup, "vpns", {"vpn0": type("V", (), {"rt_table": startup.NEXTHOP_FAIL_TABLE})()}, raising=False)
    monkeypatch.setattr(startup, "rooter", lambda *a, **k: {}, raising=False)
    startup.load_nexthop_profiles(_FailTableVpnOff())   # must NOT raise
    assert "gw1" in startup.gateways


def test_web_startup_does_not_sweep_live_rules(monkeypatch):
    # codex P2 (cross-process): the web/API process calls init_routing() -> load_nexthop_profiles with
    # apply_rooter_state=False. It must parse+validate+populate gateways but issue NO rooter mutations,
    # so a web/gunicorn restart cannot flush the scheduler's live per-task nexthop rules mid-analysis.
    import lib.cuckoo.core.startup as startup
    recorded = []
    startup.gateways.clear()
    monkeypatch.setattr(startup, "vpns", {}, raising=False)
    monkeypatch.setattr(startup, "rooter", lambda cmd, *a, **k: recorded.append(cmd) or {}, raising=False)
    startup.load_nexthop_profiles(_FakeRouting())   # default apply_rooter_state=False (web/vpncheck path)
    assert "gw1" in startup.gateways   # parsed + populated (harmless)
    assert recorded == []              # but NO rooter mutations


def test_scheduler_startup_applies_rooter_state(monkeypatch):
    # counterpart: the scheduler (apply_rooter_state=True) DOES sweep/build/arm.
    import lib.cuckoo.core.startup as startup
    recorded = []
    startup.gateways.clear()
    monkeypatch.setattr(startup, "vpns", {}, raising=False)
    monkeypatch.setattr(startup, "rooter", lambda cmd, *a, **k: recorded.append(cmd) or {}, raising=False)
    startup.load_nexthop_profiles(_FakeRouting(), apply_rooter_state=True)
    assert "nexthop_teardown" in recorded and "nexthop_init" in recorded


def test_init_rooter_web_does_not_reset_state(monkeypatch):
    # codex P1: init_rooter() is called by the web/API (web.settings) BEFORE init_routing. On a
    # nexthop-enabled node it now connects, but must NOT run cleanup_rooter/forward_drop/state_* --
    # those remove the scheduler's live per-task iptables rules on a web/gunicorn restart. Only the
    # scheduler (init_rooter(apply_state=True)) resets rooter state.
    import lib.cuckoo.core.startup as startup

    class _FakeSock:
        def connect(self, *a):
            pass

    class _R:
        class vpn:
            enabled = False

        class tor:
            enabled = False

        class inetsim:
            enabled = False

        class socks5:
            enabled = False

        class routing:
            route = "none"
            internet = "none"

        class nexthop:
            enabled = True

    monkeypatch.setattr(startup.socket, "socket", lambda *a, **k: _FakeSock())
    monkeypatch.setattr(startup, "routing", _R, raising=False)
    monkeypatch.setattr(startup.subprocess, "run",
                        lambda *a, **k: type("P", (), {"returncode": 1, "stdout": "", "stderr": ""})())
    recorded = []
    monkeypatch.setattr(startup, "rooter", lambda cmd, *a, **k: recorded.append(cmd) or {"output": True}, raising=False)

    startup.init_rooter()   # web path (apply_state=False)
    assert recorded == []   # reachability checked, but NO state-reset mutations

    startup.init_rooter(apply_state=True)   # scheduler path
    assert "cleanup_rooter" in recorded and "forward_drop" in recorded
