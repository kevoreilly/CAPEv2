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

    for category in ("binaries", "urls", "memory", "CAPE", "macro", "monitor"):
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


def test_missing_category_is_not_recompiled_for_every_file(monkeypatch, sample):
    """A permanently missing category must cost ONE forced recompile, not one per file.

    Before: get_yara() called init_yara(force=True) on every call for a category
    that could not be compiled -- a full six-category recompile per scanned file
    (~3s each on a production ruleset).
    """
    from lib.cuckoo.common.objects import File

    calls = []
    monkeypatch.setattr(File, "yara_rules", {})
    monkeypatch.setattr(File, "yara_initialized", True)
    monkeypatch.setattr(File, "yara_uncompilable", {})
    monkeypatch.setattr(File, "init_yara", classmethod(lambda cls, **kw: calls.append(kw)))

    scanner_file = File(sample)
    for _ in range(10):
        assert scanner_file.get_yara("bogus") == []

    assert len(calls) == 1, f"forced a recompile {len(calls)} times for one missing category"
    assert "bogus" in File.yara_uncompilable


def test_forced_reinit_clears_the_uncompilable_record(monkeypatch, tmp_path):
    """Fixing the rules and reloading must let a failed category be retried."""
    from lib.cuckoo.common import objects as objects_mod
    from lib.cuckoo.common.objects import File

    for category in ("binaries", "urls", "memory", "CAPE", "macro", "monitor"):
        for tree in ("data", "custom"):
            (tmp_path / tree / "yara" / category).mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "yara" / "binaries" / "marla.yar").write_text(RULE)
    monkeypatch.setattr(objects_mod, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(File, "yara_rules", {})
    monkeypatch.setattr(File, "yara_initialized", False)
    monkeypatch.setattr(File, "yara_uncompilable", {"binaries": 0.0})

    File.init_yara(force=True)

    assert "binaries" not in File.yara_uncompilable, "forced re-init must retry failed categories"
    assert File.yara_rules.get("binaries") is not None


def test_several_broken_categories_do_not_thrash_recompiles(monkeypatch, sample):
    """Each broken category costs ONE forced recompile -- not one per alternating call.

    Clearing the whole uncompilable set on every forced re-init made each broken
    category forget the others, so alternating calls recompiled forever.
    """
    from lib.cuckoo.common.objects import File

    calls = []
    monkeypatch.setattr(File, "yara_rules", {})
    monkeypatch.setattr(File, "yara_initialized", True)
    monkeypatch.setattr(File, "yara_uncompilable", {})
    monkeypatch.setattr(File, "init_yara", classmethod(lambda cls, **kw: calls.append(kw)))

    scanner_file = File(sample)
    for _ in range(10):
        scanner_file.get_yara("broken_a")
        scanner_file.get_yara("broken_b")

    assert len(calls) == 2, f"{len(calls)} recompiles for 2 broken categories over 20 calls"


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


def test_forced_reinit_forgets_only_categories_that_actually_compiled(monkeypatch, tmp_path):
    """A forced re-init must not wipe failures for categories that are STILL broken.

    Clearing the whole set made each broken category forget the others, so with
    two broken categories every alternating get_yara() forced a fresh full
    recompile. Only categories that actually produced rules may be forgotten.
    """
    from lib.cuckoo.common import objects as objects_mod
    from lib.cuckoo.common.objects import File

    for category in ("binaries", "urls", "memory", "CAPE", "macro", "monitor"):
        for tree in ("data", "custom"):
            (tmp_path / tree / "yara" / category).mkdir(parents=True, exist_ok=True)
    (tmp_path / "data" / "yara" / "binaries" / "marla.yar").write_text(RULE)
    monkeypatch.setattr(objects_mod, "CUCKOO_ROOT", str(tmp_path))
    monkeypatch.setattr(File, "yara_rules", {})
    monkeypatch.setattr(File, "yara_initialized", False)
    # "phantom" is not one of the categories init_yara compiles, so it stands in
    # for a category that still does not produce rules after a forced recompile.
    monkeypatch.setattr(File, "yara_uncompilable", {"binaries": 0.0, "phantom": 0.0})

    File.init_yara(force=True)

    assert "binaries" not in File.yara_uncompilable, "compiled category must be retried"
    assert "phantom" in File.yara_uncompilable, (
        "a category that STILL does not compile was forgotten; alternating "
        "get_yara() calls will now force a full recompile every time"
    )


def test_a_transient_compile_failure_is_retried_after_the_backoff(monkeypatch, sample):
    """A backoff, not a permanent skip.

    Workers run with max_tasks=0 (no recycling), so marking a category dead after
    one transient failure -- rules mid-update, storage briefly unreadable -- would
    silently return no matches for the rest of the run.
    """
    from lib.cuckoo.common.objects import File

    calls = []
    monkeypatch.setattr(File, "yara_rules", {})
    monkeypatch.setattr(File, "yara_initialized", True)
    monkeypatch.setattr(File, "yara_uncompilable", {})
    monkeypatch.setattr(File, "yara_recompile_backoff", 300)
    monkeypatch.setattr(File, "init_yara", classmethod(lambda cls, **kw: calls.append(kw)))

    scanner_file = File(sample)
    scanner_file.get_yara("flaky")
    scanner_file.get_yara("flaky")
    assert len(calls) == 1, "backoff did not suppress the second recompile"

    # once the backoff expires the category must be tried again
    File.yara_uncompilable["flaky"] -= 301
    scanner_file.get_yara("flaky")
    assert len(calls) == 2, "category was permanently skipped instead of retried"
