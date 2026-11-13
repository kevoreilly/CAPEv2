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
