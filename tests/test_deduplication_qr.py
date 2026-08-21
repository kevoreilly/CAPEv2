"""QR decode must open the image as a context manager so its file descriptor is
released promptly (screenshots are decoded in a loop)."""
import modules.processing.deduplication as dedup


class _FakeImg:
    def __init__(self):
        self.exited = False

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.exited = True
        return False


class _FakeResult:
    text = "http://evil.example/x"


def test_qr_decode_zxing_closes_image(monkeypatch, tmp_path):
    img = _FakeImg()
    monkeypatch.setattr(dedup, "Image", type("I", (), {"open": staticmethod(lambda p: img)}))
    monkeypatch.setattr(
        dedup, "zxingcpp",
        type("Z", (), {"read_barcodes": staticmethod(lambda i: [_FakeResult()])}),
        raising=False,
    )

    urls = dedup._qr_decode_zxing(str(tmp_path / "shot.png"))

    assert img.exited is True, "Image must be used as a context manager so the fd is closed"
    assert urls == ["http://evil.example/x"]
