"""yara_x.Scanner is unsendable: PyO3 panics if one is touched from a thread
other than the one that built it --

    pyo3_runtime.PanicException: assertion `left == right` failed:
    yara_x::Scanner is unsendable, but sent to another thread

init_yara() may run on any thread (modules/processing/memory.py calls it at
import time), while get_yara() is reached from others -- notably the threaded
web app via lib/cuckoo/core/data/tasking.py. Caching a Scanner on the class is
therefore fatal; the cache must hold the compiled Rules and each thread must
build its own Scanner.
"""
from concurrent.futures import ThreadPoolExecutor

import pytest

try:
    import yara_x

    HAVE_YARA_X = True
except ImportError:
    HAVE_YARA_X = False


pytestmark = pytest.mark.skipif(not HAVE_YARA_X, reason="yara-x not installed")

RULE = 'rule marla { strings: $a = "needle" condition: $a }'


@pytest.fixture
def sample(tmp_path):
    path = tmp_path / "sample.bin"
    path.write_bytes(b"....needle....")
    return str(path)


def test_a_scanner_cached_across_threads_would_panic(sample):
    """Pin the underlying hazard: this is the crash the fix exists to prevent.

    If this ever stops raising, yara-x has changed its threading contract and
    the rest of this module can be simplified.
    """
    scanner = yara_x.Scanner(yara_x.compile(RULE))  # built on THIS thread
    with ThreadPoolExecutor(max_workers=1) as pool:
        with pytest.raises(BaseException) as excinfo:
            pool.submit(scanner.scan_file, sample).result()

    assert type(excinfo.value).__module__ == "pyo3_runtime", excinfo.value
    assert "unsendable" in str(excinfo.value)



def test_init_yara_does_not_cache_a_scanner(monkeypatch, tmp_path):
    """Exercise the real init_yara() and inspect what it actually cached.

    The previous version of this test asserted against an object it had itself
    installed, so it passed even against unfixed code.
    """
    from lib.cuckoo.common import objects as objects_mod
    from lib.cuckoo.common.objects import File

    for category in ("binaries", "urls", "memory", "scripts", "macro", "CAPE"):
        for tree in ("data", "custom"):
            (tmp_path / tree / "yara" / category).mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "yara" / "binaries" / "marla.yar").write_text(RULE)
    monkeypatch.setattr(objects_mod, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(File, "yara_rules", {})
    monkeypatch.setattr(File, "yara_initialized", False)

    File.init_yara(force=True)

    cached = File.yara_rules.get("binaries")
    assert cached is not None, "init_yara compiled nothing -- test setup is wrong"
    assert not isinstance(cached, yara_x.Scanner), (
        "init_yara cached a Scanner; it is unsendable and will panic as soon as "
        "any other thread scans with it"
    )



def test_get_yara_scans_correctly_from_many_threads(monkeypatch, sample):
    """The end-to-end guarantee: concurrent get_yara() from N threads, no panic."""
    from lib.cuckoo.common.objects import File

    monkeypatch.setattr(File, "yara_rules", {"binaries": yara_x.compile(RULE)})
    monkeypatch.setattr(File, "yara_initialized", True)

    scanner_file = File(sample)
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = [f.result() for f in [pool.submit(scanner_file.get_yara, "binaries") for _ in range(64)]]

    assert all([m["name"] for m in r] == ["marla"] for r in results), results



def test_cached_scanner_follows_a_forced_recompile(monkeypatch, tmp_path):
    """After a reload the next scan must use the NEW rules, never the cached old ones."""
    from lib.cuckoo.common.objects import File

    sample = tmp_path / "s.bin"
    sample.write_bytes(b"....needle....")

    monkeypatch.setattr(File, "yara_rules", {"binaries": yara_x.compile(RULE)})
    monkeypatch.setattr(File, "yara_initialized", True)
    scanner_file = File(str(sample))
    assert [m["name"] for m in scanner_file.get_yara("binaries")] == ["marla"]

    # Rules reloaded out from under the cached scanner: same text, different rule name.
    File.yara_rules["binaries"] = yara_x.compile('rule reloaded { strings: $a = "needle" condition: $a }')
    assert [m["name"] for m in scanner_file.get_yara("binaries")] == ["reloaded"], "scan used the stale cached ruleset"
