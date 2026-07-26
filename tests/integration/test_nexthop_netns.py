# tests/integration/test_nexthop_netns.py
#
# Root-gated netns integration test for the nexthop egress primitive.
# Requires: root + CAPE_NETNS_TESTS=1 env var.
# Run via:  SUDO=1 bash run-cape-tests-on-box.sh tests/integration/test_nexthop_netns.py -v
#
# What this tests (semantic, not just argv):
#   1. nexthop_init installs a forced-default in the profile's routing table
#   2. nexthop_enable installs a policy rule pointing vm_ip -> that table
#   3. Two concurrent profiles resolve to DISTINCT tables/interfaces
#   4. nexthop_fail_closed_enable installs a blackhole in the fail table and
#      a low-priority subnet rule so an unbound guest source hits the blackhole
#
# Assertion strategy:
#   - "ip rule show" to verify policy rules exist at the right priority
#   - "ip route show table <N>" to verify the forced-default points to the right egress_if
#   - The combination proves a packet from vm_ip would be source-routed through the correct table.
#   - For fail-closed: verify the blackhole route is in table 250 and the subnet rule is present.
#   - We do NOT use "ip route get ... from <non-local-src>" because that command can refuse
#     to execute (EHOSTUNREACH) when the source is not locally assigned, even under root.
#     The rule+table combination is the authoritative semantic check.

import os
import subprocess
import pytest
import threading
import utils.rooter as rooter

pytestmark = pytest.mark.skipif(
    os.geteuid() != 0 or os.environ.get("CAPE_NETNS_TESTS") != "1",
    reason="needs root + CAPE_NETNS_TESTS=1 (creates network namespaces)",
)

# ─── ip path ─────────────────────────────────────────────────────────────────
# /sbin/ip and /usr/sbin/ip both exist on this Ubuntu box (usrmerge symlinks);
# using the PATH-resolved "ip" is most portable. Override in the fixture so the
# rooter functions use the same binary as our assertions.
_IP = "/sbin/ip"


def sh(*args, check=True):
    """Run an ip/iptables command, raising on failure unless check=False."""
    result = subprocess.run(list(args), capture_output=True, text=True, check=False)
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, args, result.stdout, result.stderr
        )
    return result.stdout, result.stderr


def ip_rule_exists(from_addr, table, priority):
    """Return True if 'ip rule show' contains a rule matching from/table/priority."""
    out, _ = sh(_IP, "rule", "show")
    for line in out.splitlines():
        # Line format: "10041:    from 192.168.100.41 lookup 201"
        head = line.split(":", 1)[0].strip()
        if head == str(priority) and f"from {from_addr}" in line and f"lookup {table}" in line:
            return True
    return False


def ip_route_table_has_default_via_if(table, iface):
    """Return True if the routing table has a default route dev iface."""
    out, _ = sh(_IP, "route", "show", "table", table)
    for line in out.splitlines():
        if "default" in line and iface in line:
            return True
    return False


def ip_route_table_has_blackhole(table):
    """Return True if the routing table has a blackhole default."""
    out, _ = sh(_IP, "route", "show", "table", table)
    for line in out.splitlines():
        if "blackhole" in line and "default" in line:
            return True
    return False


def subnet_rule_exists(subnet, table, priority):
    """Return True if a rule for the whole subnet exists in ip rule show."""
    out, _ = sh(_IP, "rule", "show")
    for line in out.splitlines():
        head = line.split(":", 1)[0].strip()
        if head == str(priority) and subnet in line and f"lookup {table}" in line:
            return True
    return False


# ─── fixture ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=False)
def netns():
    """Build two veth egress interfaces + two dummy gateway namespaces.

    Topology:
        default ns         gw1 ns          gw2 ns
        egress_if1  <-veth-> gwp1          (acts as a real next-hop)
        egress_if2  <-veth-> gwp2

    Each egress_if is the "egress interface" we hand to nexthop_init.
    The gateway peer address (10.k.0.2) is the next_hop argument.

    Teardown is run unconditionally (try/except each step) so a failed run
    does not leave stale state that blocks a re-run.
    """
    # Wire the real ip binary into rooter so nexthop_* functions hit the kernel.
    class _Settings:
        ip = _IP
    rooter.settings = _Settings
    rooter.ServicePaths.ip = _IP
    # These tests verify policy ROUTING (ip rule/route), not iptables filtering, and no packets
    # traverse. STUB run_iptables so nexthop_enable's MASQUERADE/ACCEPT rules never touch the real
    # host firewall -- otherwise the root-gated suite would leave CAPE-rooter NAT rules behind
    # (codex/Copilot). Saved + restored around the test.
    rooter.ServicePaths.iptables = "/usr/sbin/iptables"
    _orig_run_iptables = rooter.run_iptables
    # Return non-empty stderr for `-D` so the idempotent delete-until-gone loop terminates after one
    # call instead of spinning to its bound; empty stderr (success) for everything else.
    rooter.run_iptables = lambda *a, **k: (("", "gone") if "-D" in a else ("", ""))

    NEXTHOP_VM_NET = "192.168.100.0/24"   # every test source IP lives here
    created_ns = []
    created_links = []
    created_tables = []     # table ids with content to flush

    def _cleanup():
        # Best-effort teardown; each step is independent.
        # Use the PRODUCTION filtered teardown for ip rules/routes/tables: it deletes only band rules
        # whose source is inside vm_net (never an unrelated host rule at a band priority), flushes the
        # gateway tables, and removes the blackhole + intra-subnet exception (codex/Copilot).
        try:
            rooter.nexthop_teardown(",".join(created_tables), NEXTHOP_VM_NET, "250", "30000", "10000", "10255")
        except Exception:
            pass
        # bring down/del veth links (deleting one side removes the peer too)
        for link in created_links:
            subprocess.run([_IP, "link", "del", link], capture_output=True)
        # delete namespaces
        for ns in created_ns:
            subprocess.run([_IP, "netns", "del", ns], capture_output=True)
        rooter.run_iptables = _orig_run_iptables

    try:
        for k in (1, 2):
            ns = f"gw{k}"
            link = f"egress_if{k}"
            peer = f"gwp{k}"
            sh(_IP, "netns", "add", ns)
            created_ns.append(ns)
            sh(_IP, "link", "add", link, "type", "veth", "peer", "name", peer, "netns", ns)
            created_links.append(link)
            sh(_IP, "addr", "add", f"10.{k}.0.1/24", "dev", link)
            sh(_IP, "link", "set", link, "up")
            sh(_IP, "netns", "exec", ns, _IP, "addr", "add", f"10.{k}.0.2/24", "dev", peer)
            sh(_IP, "netns", "exec", ns, _IP, "link", "set", peer, "up")
            created_tables.append(str(200 + k))  # tables 201, 202
    except Exception:
        _cleanup()
        raise

    yield

    _cleanup()


# ─── tests ───────────────────────────────────────────────────────────────────

def test_two_profiles_route_to_distinct_interfaces(netns):
    """Two VM source IPs bound to two different profiles route via distinct egress interfaces.

    Verification:
    (a) Each profile's routing table has a default pointing to its own egress_if.
    (b) Each VM's source IP has a policy rule pointing it to its table.
    Together these prove that a packet from vm_ip1 would be looked up in table 201
    (-> egress_if1) and a packet from vm_ip2 in table 202 (-> egress_if2).
    """
    VM_IP1 = "192.168.100.41"
    VM_IP2 = "192.168.100.42"
    PRIO1 = "10041"   # 10000 + last octet
    PRIO2 = "10042"

    # Initialize profiles: forced-default routes into tables 201 / 202
    rooter.nexthop_init("201", "egress_if1", "10.1.0.2")
    rooter.nexthop_init("202", "egress_if2", "10.2.0.2")

    # Bind the two VM IPs
    rooter.nexthop_enable(VM_IP1, "lo", "egress_if1", "201", PRIO1)
    rooter.nexthop_enable(VM_IP2, "lo", "egress_if2", "202", PRIO2)

    # (a) Tables have forced defaults via the correct interface
    assert ip_route_table_has_default_via_if("201", "egress_if1"), (
        "table 201 should have a default via egress_if1"
    )
    assert ip_route_table_has_default_via_if("202", "egress_if2"), (
        "table 202 should have a default via egress_if2"
    )

    # (b) Source policy rules point each VM IP to its table
    assert ip_rule_exists(VM_IP1, "201", PRIO1), (
        f"ip rule should map {VM_IP1} -> table 201 at priority {PRIO1}"
    )
    assert ip_rule_exists(VM_IP2, "202", PRIO2), (
        f"ip rule should map {VM_IP2} -> table 202 at priority {PRIO2}"
    )

    # (c) Profiles are DISTINCT: VM_IP1 is NOT in table 202, VM_IP2 is NOT in table 201
    assert not ip_rule_exists(VM_IP1, "202", PRIO1), (
        f"{VM_IP1} must NOT be in table 202"
    )
    assert not ip_rule_exists(VM_IP2, "201", PRIO2), (
        f"{VM_IP2} must NOT be in table 201"
    )


def test_concurrent_profile_setup_is_consistent(netns):
    """Two threads calling nexthop_enable concurrently produce the correct rule set.

    This exercises the real kernel's netlink serialization (iproute2 calls are
    serialized by the kernel, not by us — we verify no rules are duplicated or lost).
    """
    VM_IP1 = "192.168.100.51"
    VM_IP2 = "192.168.100.52"
    PRIO1 = "10051"
    PRIO2 = "10052"

    rooter.nexthop_init("201", "egress_if1", "10.1.0.2")
    rooter.nexthop_init("202", "egress_if2", "10.2.0.2")

    errors = []

    def bind1():
        try:
            rooter.nexthop_enable(VM_IP1, "lo", "egress_if1", "201", PRIO1)
        except Exception as e:
            errors.append(e)

    def bind2():
        try:
            rooter.nexthop_enable(VM_IP2, "lo", "egress_if2", "202", PRIO2)
        except Exception as e:
            errors.append(e)

    t1 = threading.Thread(target=bind1)
    t2 = threading.Thread(target=bind2)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors, f"Concurrent nexthop_enable raised: {errors}"

    # Both rules must be present, independently
    assert ip_rule_exists(VM_IP1, "201", PRIO1), "Concurrent bind: VM_IP1 rule missing"
    assert ip_rule_exists(VM_IP2, "202", PRIO2), "Concurrent bind: VM_IP2 rule missing"


def test_unbound_source_is_blackholed(netns):
    """An unbound guest-subnet source (no per-task rule) resolves to the fail-closed blackhole.

    After nexthop_fail_closed_enable:
    - table 250 has `blackhole default`
    - ip rule has a low-priority (30000) rule routing the entire guest subnet (192.168.100.0/24)
      to table 250

    An unbound IP (e.g. 192.168.100.99) has no higher-priority per-task rule, so it
    hits the subnet rule -> table 250 -> blackhole.

    We verify the state is correctly installed; we do NOT try to inject a test packet
    (that would need an actual VM interface or raw-socket plumbing out of scope here).
    """
    VM_NET = "192.168.100.0/24"
    FAIL_TABLE = "250"
    PRIORITY_LOW = "30000"
    BAND_LO = "10000"

    # intra-subnet exception is now a separate primitive (always installed); the blackhole is
    # fail_closed_enable (3 args). Install both, as load_nexthop_profiles does when fail_closed=yes.
    rooter.nexthop_intra_exception_enable(VM_NET, BAND_LO)
    rooter.nexthop_fail_closed_enable(VM_NET, FAIL_TABLE, PRIORITY_LOW)

    # (a) Blackhole default is in table 250
    assert ip_route_table_has_blackhole(FAIL_TABLE), (
        "table 250 should have a blackhole default after nexthop_fail_closed_enable"
    )

    # (b) Subnet rule at priority 30000 routes the guest /24 to table 250
    assert subnet_rule_exists(VM_NET, FAIL_TABLE, PRIORITY_LOW), (
        f"ip rule should route {VM_NET} -> table {FAIL_TABLE} at priority {PRIORITY_LOW}"
    )

    # (c) No per-task rule for the unbound IP (192.168.100.99) exists —
    # so it falls through to the subnet rule -> blackhole.
    assert not ip_rule_exists("192.168.100.99", FAIL_TABLE, PRIORITY_LOW), (
        "unbound IP must NOT have its own rule — it is covered only by the subnet rule"
    )


def test_enable_then_disable_removes_rules(netns):
    """nexthop_disable is the mirror of nexthop_enable: all rules are removed."""
    VM_IP = "192.168.100.61"
    PRIO = "10061"

    rooter.nexthop_init("201", "egress_if1", "10.1.0.2")
    rooter.nexthop_enable(VM_IP, "lo", "egress_if1", "201", PRIO)

    assert ip_rule_exists(VM_IP, "201", PRIO), "Rule must exist after enable"

    rooter.nexthop_disable(VM_IP, "lo", "egress_if1", "201", PRIO)

    assert not ip_rule_exists(VM_IP, "201", PRIO), (
        "Rule must be removed after disable (mirror teardown)"
    )
