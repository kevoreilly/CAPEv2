"""Regression test for the Suricata DNS-passlist accumulation bug.

`suricata.py` used to `domain_passlist_re.append(domain)` into the imported
module-global on every run(). In a reused worker process (pebble -mc0 never
recycles a worker) the list grew by the whole passlist file every task, so the
per-event `re.search` loop became O(tasks_processed x events) until Suricata
processing stalled — a multi-minute hang that presents as a deadlock. prefork
forks a fresh process per task, which reset the global and hid the bug.

The fix builds a fresh, pre-compiled passlist per run without mutating the
global. These tests lock in: (1) the global is never mutated, (2) repeated
builds do not accumulate, (3) filtering still matches/rejects correctly.
"""

import os
import sys

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.insert(0, CUCKOO_ROOT)

from data.safelist.domains import domain_passlist_re
from modules.processing.suricata import Suricata


def test_compile_passlist_does_not_mutate_global():
    base_len = len(domain_passlist_re)
    # Build twice; neither call may grow the imported module-global, and neither
    # build may accumulate on top of the previous one.
    first = Suricata._compile_passlist(False, "")
    second = Suricata._compile_passlist(False, "")
    assert len(domain_passlist_re) == base_len, "run() must not mutate the shared domain_passlist_re global"
    assert len(first) == len(second) == base_len, "passlist must not accumulate across builds"


def test_compile_passlist_appends_file_without_touching_global(tmp_path, monkeypatch):
    import modules.processing.suricata as suri

    base_len = len(domain_passlist_re)
    wl = tmp_path / "wl.txt"
    wl.write_text("# a comment line\nfoo\\.example\\.com$\n\nbar\\.test$\n")
    monkeypatch.setattr(suri, "CUCKOO_ROOT", str(tmp_path))

    patterns = Suricata._compile_passlist(True, "wl.txt")

    # base + 2 file domains (comment line and blank line are skipped)
    assert len(patterns) == base_len + 2
    # even the file-append path must leave the shared global untouched
    assert len(domain_passlist_re) == base_len
    # and the compiled patterns must still match / reject correctly
    assert any(p.search("foo.example.com") for p in patterns)
    assert not any(p.search("zzz-nomatch-1234.invalid") for p in patterns)


def test_compile_passlist_survives_bad_regex(tmp_path, monkeypatch):
    """A malformed passlist entry must be skipped, not crash the whole run."""
    import modules.processing.suricata as suri

    base_len = len(domain_passlist_re)
    wl = tmp_path / "wl.txt"
    wl.write_text("good\\.test$\n(((unterminated\n")
    monkeypatch.setattr(suri, "CUCKOO_ROOT", str(tmp_path))

    patterns = Suricata._compile_passlist(True, "wl.txt")

    # only the valid entry is compiled; the bad one is dropped
    assert len(patterns) == base_len + 1
    assert any(p.search("good.test") for p in patterns)
