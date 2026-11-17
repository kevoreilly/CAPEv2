# Copyright (C) 2010-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import modules.processing.network as net


def test_batch_sort_stages_chunks_in_cape_external_and_cleans_up(tmp_path, monkeypatch):
    ext_dir = tmp_path / "cape-external"
    ext_dir.mkdir()
    monkeypatch.setattr(net, "get_cape_external_dir", lambda: str(ext_dir))

    seen_chunk_paths = []

    class _Item:
        def __init__(self, val):
            self.obj = val

        def __lt__(self, other):
            return self.obj < other.obj

    class _MemChunk:
        _store = {}

        def __init__(self, path):
            self.name = path
            if path != str(tmp_path / "out.bin"):
                seen_chunk_paths.append(path)
            self._store.setdefault(path, [])

        def write(self, val=None):
            if val is not None:
                self._store[self.name].append(val)

        def close(self):
            pass

        def __iter__(self):
            return iter(_Item(v) for v in self._store.get(self.name, []))

    out_path = str(tmp_path / "out.bin")
    net.batch_sort(iter([_Item(3), _Item(1), _Item(2)]), out_path, buffer_size=2, output_class=_MemChunk)

    assert len(seen_chunk_paths) == 2
    assert all(p.startswith(str(ext_dir)) for p in seen_chunk_paths)
    assert list(ext_dir.iterdir()) == []
    assert _MemChunk._store[out_path] == [1, 2, 3]


def test_packets_for_stream_supports_pcap_and_pcapng(tmp_path, monkeypatch):
    import dpkt
    from base64 import b64decode

    def _raw_pkt(sport, dport, payload):
        tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, ack=1, flags=dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, data=payload)
        ip = dpkt.ip.IP(src=b"\x0a\x00\x00\x01", dst=b"\x0a\x00\x00\x02", p=dpkt.ip.IP_PROTO_TCP, data=tcp)
        ip.len = len(ip)
        return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x11" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))

    pkt1 = _raw_pkt(40000, 443, b"client-hello")
    pkt2 = _raw_pkt(40000, 443, b"client-data")
    pkt_other = _raw_pkt(40001, 80, b"other-flow")

    for fmt, writer_cls in (("pcap", dpkt.pcap.Writer), ("pcapng", dpkt.pcapng.Writer)):
        pcap_file = tmp_path / f"sample.{fmt}"
        with open(pcap_file, "wb") as f:
            w = writer_cls(f)
            w.writepkt(pkt1, ts=1.0)
            w.writepkt(pkt2, ts=2.0)
            w.writepkt(pkt_other, ts=3.0)

        monkeypatch.setattr(net, "PCAP_TYPE", net.check_pcap_file_type(str(pcap_file)), raising=False)
        res = net.Pcap(str(pcap_file), {}, {"sorted": True}).run()
        conns = {c["sport"]: c["offset"] for c in res["sorted"]["tcp"]}
        assert set(conns) == {40000, 40001}

        with open(pcap_file, "rb") as f:
            stream_40000 = list(net.packets_for_stream(f, conns[40000]))
        assert [b64decode(p["raw"]) for p in stream_40000] == [b"client-hello", b"client-data"]

        with open(pcap_file, "rb") as f:
            stream_40001 = list(net.packets_for_stream(f, conns[40001]))
        assert [b64decode(p["raw"]) for p in stream_40001] == [b"other-flow"]


def _build_dns_udp_packet(qname_wire: bytes, *, qid: int = 0x1234, sport: int = 51000, dport: int = 53) -> bytes:
    import struct
    import dpkt

    # Standard recursive A query: QR=0, RD=1, QDCOUNT=1
    dns_payload = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname_wire + struct.pack(">HH", 1, 1)
    udp = dpkt.udp.UDP(sport=sport, dport=dport, data=dns_payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=b"\xc0\x00\x02\x0a", dst=b"\x5d\xb8\xd8\x22", p=dpkt.ip.IP_PROTO_UDP, data=udp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x11" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def _build_dns_txt_cname_response_packet(qname_wire: bytes, cname_wire: bytes, txt_strings: list[bytes]) -> bytes:
    import struct
    import dpkt

    question = qname_wire + struct.pack(">HH", dpkt.dns.DNS_TXT, dpkt.dns.DNS_IN)
    an_cname = b"\xc0\x0c" + struct.pack(">HHIH", dpkt.dns.DNS_CNAME, dpkt.dns.DNS_IN, 60, len(cname_wire)) + cname_wire
    txt_rdata = b"".join(bytes([len(s)]) + s for s in txt_strings)
    an_txt = b"\xc0\x0c" + struct.pack(">HHIH", dpkt.dns.DNS_TXT, dpkt.dns.DNS_IN, 60, len(txt_rdata)) + txt_rdata
    dns_payload = struct.pack(">HHHHHH", 0x5678, 0x8180, 1, 2, 0, 0) + question + an_cname + an_txt
    udp = dpkt.udp.UDP(sport=53, dport=51001, data=dns_payload)
    udp.ulen = len(udp)
    ip = dpkt.ip.IP(src=b"\x5d\xb8\xd8\x22", dst=b"\xc0\x00\x02\x0a", p=dpkt.ip.IP_PROTO_UDP, data=udp)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x11" * 6, dst=b"\x00" * 6, type=dpkt.ethernet.ETH_TYPE_IP, data=ip))


def test_pcap_handles_malformed_and_idn_dns_names_cleanly(tmp_path, monkeypatch, caplog):
    import logging
    import dpkt

    idn_label = "münchen".encode("utf-8")
    idn_wire = bytes([len(idn_label)]) + idn_label + b"\x02de\x00"
    nul_wire = b"\x11example\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    root_wire = b"\x00"
    leading_dot_wire = b"\x04.bad\x03com\x00"
    ascii_wire = b"\x07example\x03org\x00"

    pcap_file = tmp_path / "dns_edge_cases.pcap"
    with open(pcap_file, "wb") as f:
        w = dpkt.pcap.Writer(f)
        w.writepkt(_build_dns_udp_packet(nul_wire, qid=1, sport=51000), ts=1.0)
        w.writepkt(_build_dns_udp_packet(root_wire, qid=2, sport=51000), ts=2.0)
        w.writepkt(_build_dns_udp_packet(leading_dot_wire, qid=3, sport=51000), ts=3.0)
        w.writepkt(_build_dns_udp_packet(idn_wire, qid=4, sport=51000), ts=4.0)
        w.writepkt(_build_dns_udp_packet(ascii_wire, qid=5, sport=51000), ts=5.0)
        w.writepkt(
            _build_dns_txt_cname_response_packet(
                ascii_wire,
                b"\x09cname\x00bad\x03org\x00",
                [b"v=spf1\x00\x01", b"ok"],
            ),
            ts=6.0,
        )

    monkeypatch.setattr(net, "PCAP_TYPE", net.check_pcap_file_type(str(pcap_file)), raising=False)
    monkeypatch.setattr(net.cfg.processing, "resolve_dns", True, raising=False)
    monkeypatch.setattr(net.cfg.processing, "reverse_dns", False, raising=False)

    def _fake_ghbn(name):
        if name == "münchen.de":
            return "198.51.100.10"
        if name == "example.org":
            return "93.184.216.34"
        raise AssertionError(f"Unexpected socket.gethostbyname call for {name!r}")

    with caplog.at_level(logging.ERROR):
        monkeypatch.setattr("lib.cuckoo.common.dns.socket.gethostbyname", _fake_ghbn)
        res = net.Pcap(str(pcap_file), {}, {}).run()

    assert not [rec for rec in caplog.records if rec.levelno >= logging.ERROR]

    dns_requests = [d["request"] for d in res["dns"]]
    assert "example" + "\\x00" * 10 in dns_requests
    assert "münchen.de" in dns_requests
    assert "example.org" in dns_requests

    txt_entries = [d for d in res["dns"] if d.get("type") == "TXT" and d["request"] == "example.org"]
    assert txt_entries
    answers_by_type = {a["type"]: a["data"] for a in txt_entries[0]["answers"]}
    assert answers_by_type["CNAME"] == "cname\\x00bad.org"
    assert answers_by_type["TXT"] == "v=spf1\\x00\\x01 ok"

    assert any(u["sport"] == 51000 and u["dport"] == 53 for u in res["udp"])
    assert "93.184.216.34" in {h["ip"] for h in res["hosts"]}

    domains = {d["domain"]: d["ip"] for d in res["domains"]}
    assert "" not in domains
    assert not any("\x00" in dom or "\\x00" in dom for dom in domains)
    assert domains["münchen.de"] == "198.51.100.10"
    assert domains["example.org"] == "93.184.216.34"
    assert domains[".bad.com"] == ""
