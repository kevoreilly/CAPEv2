"""Regression tests for the Pcap host bookkeeping fast paths.

``_add_hosts`` used to test membership against ``self.hosts``, a list that grows to the
number of unique hosts, once per packet. ``_enrich_hosts`` used to rescan every DNS
request for every host. Both are now O(1)/prebuilt-map lookups; these tests pin the
observable behaviour so the rewrite cannot silently change report content.
"""

import os
import sys

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.insert(0, CUCKOO_ROOT)

from modules.processing.network import Pcap  # noqa: E402

# Globally routable addresses outside the shipped passlist and outside every range
# _is_private_ip treats as private (which includes the RFC 5737 documentation ranges).
A = "93.184.216.34"
B = "23.45.67.89"
C = "104.18.32.7"


def _pcap():
    return Pcap("/nonexistent.pcap", {}, {})


def _conn(dst, dport=443):
    return {"src": "192.168.1.2", "dst": dst, "sport": 1234, "dport": dport}


def test_add_hosts_dedupes_and_preserves_order():
    p = _pcap()
    for dst, dport in ((A, 53), (B, 443), (A, 53), (C, 80), (B, 8080)):
        p._add_hosts(_conn(dst, dport))

    assert p.hosts == [A, B, C]
    assert p.unique_hosts == [A, B, C]
    # Only the dport of the first packet for an address is recorded, as before.
    assert p.ip_n_ports == {A: [53], B: [443], C: [80]}


def test_add_hosts_keeps_private_ips_out_of_unique_hosts():
    p = _pcap()
    p._add_hosts(_conn("10.0.0.5", 445))
    p._add_hosts(_conn(A))

    assert p.hosts == ["10.0.0.5", A]
    assert p.unique_hosts == [A]


def test_add_hosts_does_not_reprocess_a_passlisted_address():
    # A passlisted address is never appended to self.hosts, so the old code re-ran the
    # whole passlist walk for every packet to it. seen_hosts has to stop that.
    p = _pcap()
    p._add_hosts(_conn("8.8.8.8", 53))
    assert p.hosts == []
    assert "8.8.8.8" in p.seen_hosts

    before = len(p.seen_hosts)
    p._add_hosts(_conn("8.8.8.8", 53))
    assert len(p.seen_hosts) == before
    assert p.hosts == []


def test_add_hosts_tolerates_missing_dport():
    # ICMP packets carry no dport; the address is still recorded.
    p = _pcap()
    p._add_hosts({"src": "10.0.0.1", "dst": A})
    assert p.hosts == [A]
    assert p.unique_hosts == [A]
    # setdefault runs before the KeyError on the missing dport, so the key exists but is empty.
    assert p.ip_n_ports == {A: []}


def test_enrich_hosts_resolves_hostname_from_dns_answers():
    p = _pcap()
    p.dns_requests["a"] = {"request": "first.example", "answers": [{"type": "A", "data": A}]}
    p.dns_requests["b"] = {"request": "second.example", "answers": [{"type": "A", "data": A}]}
    p.dns_requests["c"] = {"request": "third.example", "answers": [{"type": "A", "data": B}]}

    by_ip = {e["ip"]: e["hostname"] for e in p._enrich_hosts([A, B, C])}

    # First request that answered with the address wins, matching the previous
    # break-out-of-nested-loop behaviour.
    assert by_ip[A] == "first.example"
    assert by_ip[B] == "third.example"
    assert by_ip[C] == ""


def test_enrich_hosts_consumes_the_input_list():
    p = _pcap()
    hosts = [A, B]
    enriched = p._enrich_hosts(hosts)
    assert hosts == []
    assert len(enriched) == 2
