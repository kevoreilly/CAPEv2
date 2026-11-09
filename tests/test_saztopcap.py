import zipfile
from pathlib import Path

from lib.cuckoo.common import saztopcap


def test_saz_to_pcap_skips_non_saz_extension(tmp_path, monkeypatch):
    monkeypatch.setattr(
        saztopcap,
        "get_cape_external_dir",
        lambda: (_ for _ in ()).throw(AssertionError("should not allocate external dir")),
    )
    assert saztopcap.saz_to_pcap(str(tmp_path / "sample.zip")) is None


def test_saz_to_pcap_cleans_temp_dirs_on_invalid_or_incomplete_archive(tmp_path, monkeypatch):
    ext_dir = tmp_path / "cape-external"
    ext_dir.mkdir()

    class _DummyPcapWriter:
        def __init__(self, path, sync=True):
            self.path = path
            with open(path, "wb") as fh:
                fh.write(b"pcap-hdr")

        def close(self):
            pass

    monkeypatch.setattr(saztopcap, "HAVE_SCAPY", True)
    monkeypatch.setattr(saztopcap, "PcapWriter", _DummyPcapWriter, raising=False)
    monkeypatch.setattr(saztopcap, "get_cape_external_dir", lambda: str(ext_dir))

    # 1. Corrupt non-zip .saz file
    bad_saz = tmp_path / "corrupt.saz"
    bad_saz.write_bytes(b"not-a-zip")
    assert saztopcap.saz_to_pcap(str(bad_saz)) is None
    assert list(ext_dir.iterdir()) == []

    # 2. Valid zip without raw/ directory
    no_raw_saz = tmp_path / "noraw.saz"
    with zipfile.ZipFile(no_raw_saz, "w") as zf:
        zf.writestr("metadata/info.txt", "none")
    assert saztopcap.saz_to_pcap(str(no_raw_saz)) is None
    assert list(ext_dir.iterdir()) == []

    # 3. Valid zip with empty raw/ directory
    empty_raw_saz = tmp_path / "emptyraw.saz"
    with zipfile.ZipFile(empty_raw_saz, "w") as zf:
        zf.writestr("raw/placeholder.txt", "unused")
    assert saztopcap.saz_to_pcap(str(empty_raw_saz)) is None
    assert list(ext_dir.iterdir()) == []


def test_saz_to_pcap_success_places_output_in_cape_external_and_cleans_tmpdir(tmp_path, monkeypatch):
    ext_dir = tmp_path / "cape-external"
    ext_dir.mkdir()
    closed = []

    class _FakePcapWriter:
        def __init__(self, path, sync=True):
            self.path = path
            with open(path, "wb") as fh:
                fh.write(b"fake-pcap-bytes")

        def close(self):
            closed.append(self.path)

    monkeypatch.setattr(saztopcap, "HAVE_SCAPY", True)
    monkeypatch.setattr(saztopcap, "PcapWriter", _FakePcapWriter, raising=False)
    monkeypatch.setattr(saztopcap, "build_handshake", lambda *args: (1, 1))
    monkeypatch.setattr(saztopcap, "make_pkts", lambda *args: (2, 2))
    monkeypatch.setattr(saztopcap, "build_finshake", lambda *args: None)
    monkeypatch.setattr(saztopcap, "get_cape_external_dir", lambda: str(ext_dir))

    valid_saz = tmp_path / "capture.saz"
    with zipfile.ZipFile(valid_saz, "w") as zf:
        zf.writestr("raw/1_c.txt", "GET http://example.invalid/index.html HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
        zf.writestr("raw/1_s.txt", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    pcap_path = saztopcap.saz_to_pcap(str(valid_saz))
    assert pcap_path is not None
    assert ext_dir.is_dir()
    assert pcap_path.startswith(str(ext_dir))
    assert closed == [pcap_path]
    with open(pcap_path, "rb") as fh:
        assert fh.read() == b"fake-pcap-bytes"
    # Only the pcap output dir remains inside cape-external; extraction tmpdir was removed.
    remaining_dirs = list(ext_dir.iterdir())
    assert len(remaining_dirs) == 1
    assert remaining_dirs[0] == Path(pcap_path).parent
