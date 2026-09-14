"""Tests for the evented dispatch cache, the TTP de-duplication and the per-signature timings."""

import time

import pytest

from lib.cuckoo.common.abstracts import Signature
from lib.cuckoo.core import plugins as plugins_module
from lib.cuckoo.core.plugins import RunSignatures

APIS = ("gethostbyname", "send", "NtCreateFile", "RegSetValueExA", "explode")
CATEGORIES = ("network", "filesystem", "registry", "misc")
PROCESS_NAMES = ("powershell.exe", "calc.exe", "explorer.exe")


def _make_signature(name, apinames=(), categories=(), processnames=(), sleep_per_call=0.0):
    """Build an evented signature class that records every call it is handed."""

    class _Recorder(Signature):
        pass

    _Recorder.__name__ = name
    _Recorder.name = name
    _Recorder.description = name
    _Recorder.severity = 1
    _Recorder.categories = ["test"]
    _Recorder.authors = ["tests"]
    _Recorder.minimum = "1.3"
    _Recorder.evented = True
    _Recorder.filter_apinames = set(apinames)
    _Recorder.filter_categories = set(categories)
    _Recorder.filter_processnames = set(processnames)

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.seen = []

    def on_call(self, call, process):
        self.seen.append((process["process_id"], call.get("api"), call.get("category")))
        if sleep_per_call:
            time.sleep(sleep_per_call)
        # Never match: a match would stop further dispatch and hide divergence.
        return False

    def on_complete(self):
        raise NotImplementedError

    _Recorder.__init__ = __init__
    _Recorder.on_call = on_call
    _Recorder.on_complete = on_complete
    return _Recorder


SIGNATURE_CLASSES = (
    _make_signature("always"),
    _make_signature("by_api", apinames=("gethostbyname", "send")),
    _make_signature("by_cat", categories=("network",)),
    _make_signature("by_proc", processnames=("powershell.exe",)),
    _make_signature("api_cat", apinames=("NtCreateFile",), categories=("filesystem",)),
    _make_signature("api_proc", apinames=("send",), processnames=("calc.exe",)),
    _make_signature("cat_proc", categories=("registry",), processnames=("explorer.exe",)),
    _make_signature("all_three", apinames=("RegSetValueExA",), categories=("registry",), processnames=("powershell.exe",)),
)


def _results():
    """A results dict shaped like tests/test_data/*/reports/report.json, with more calls."""
    processes = []
    for pid, process_name in enumerate(PROCESS_NAMES, start=100):
        calls = [
            {"api": api, "category": category, "arguments": []}
            for api in APIS
            for category in CATEGORIES
            # Repeat so the memoised path (not just the cache-miss path) is exercised.
            for _ in range(3)
        ]
        processes.append({"process_id": pid, "process_name": process_name, "calls": calls})
    return {"statistics": {"signatures": []}, "behavior": {"processes": processes}}


def _engine(monkeypatch, classes=SIGNATURE_CLASSES, results=None):
    # Bypass the global plugin registry so these fakes cannot leak into other test modules.
    monkeypatch.setattr(plugins_module, "list_plugins", lambda group=None: list(classes))
    return RunSignatures(task={"id": 1}, results=results if results is not None else _results())


def _legacy_dispatch(engine, results):
    """The pre-cache set algebra, kept here as the equivalence oracle."""
    expected = {sig.name: [] for sig in engine.evented_list}
    evented_set = set(engine.evented_list)
    for proc in results["behavior"]["processes"]:
        sigs = evented_set.intersection(
            engine.call_for_processname.get("any", set()).union(engine.call_for_processname.get(proc["process_name"], set()))
        )
        for call in proc["calls"]:
            api = call.get("api")
            cat = call.get("category")
            call_sigs = sigs.intersection(engine.call_for_api.get(api, set()).union(engine.call_for_api.get("any", set())))
            call_sigs = call_sigs.intersection(engine.call_for_cat.get(cat, set()).union(engine.call_for_cat.get("any", set())))
            call_sigs.update(evented_set.intersection(engine.call_always))
            for sig in call_sigs:
                expected[sig.name].append((proc["process_id"], api, cat))
    return expected


def test_cached_dispatch_matches_the_legacy_set_algebra(monkeypatch):
    results = _results()
    engine = _engine(monkeypatch, results=results)
    assert len(engine.evented_list) == len(SIGNATURE_CLASSES)

    expected = _legacy_dispatch(engine, results)
    engine.run()

    actual = {sig.name: sig.seen for sig in engine.evented_list}
    assert set(actual) == set(expected)
    for name in expected:
        assert sorted(actual[name]) == sorted(expected[name]), name


def test_dispatch_is_not_reused_across_processes(monkeypatch):
    """The cache key is (api, category) but the signature set also depends on the process."""
    results = _results()
    engine = _engine(monkeypatch, results=results)
    engine.run()

    by_proc = next(sig for sig in engine.evented_list if sig.name == "by_proc")
    seen_pids = {pid for pid, _, _ in by_proc.seen}
    # 100 is powershell.exe, the only process this signature filters on.
    assert seen_pids == {100}

    always = next(sig for sig in engine.evented_list if sig.name == "always")
    assert {pid for pid, _, _ in always.seen} == {100, 101, 102}


def test_cache_holds_one_entry_per_distinct_api_category_pair(monkeypatch):
    results = _results()
    engine = _engine(monkeypatch, results=results)
    engine.run()

    last_process = results["behavior"]["processes"][-1]
    distinct = {(call["api"], call["category"]) for call in last_process["calls"]}
    # api_sigs is cleared per process, so what remains is the last process only.
    assert set(engine.api_sigs) == distinct
    assert len(distinct) == len(APIS) * len(CATEGORIES)


def test_statistics_report_each_signature_own_time(monkeypatch):
    slow = _make_signature("slow_sig", apinames=("gethostbyname",), sleep_per_call=0.01)
    fast = _make_signature("fast_sig", apinames=("send",))
    results = {
        "statistics": {"signatures": []},
        "behavior": {
            "processes": [
                {
                    "process_id": 100,
                    "process_name": "powershell.exe",
                    "calls": [{"api": "gethostbyname", "category": "network"}] * 5 + [{"api": "send", "category": "network"}] * 5,
                }
            ]
        },
    }
    engine = _engine(monkeypatch, classes=(slow, fast), results=results)
    engine.run()

    timings = {entry["name"]: entry["time"] for entry in results["statistics"]["signatures"]}
    assert "slow_sig" in timings
    assert timings["slow_sig"] >= 0.04
    # Before the fix both entries reported the same leaked `timediff` value.
    if "fast_sig" in timings:
        assert timings["fast_sig"] < timings["slow_sig"]


def test_add_ttps_deduplicates_and_preserves_order(monkeypatch):
    engine = _engine(monkeypatch)
    engine.ttps = []
    engine._seen_ttps = set()

    first = _make_signature("sig_a")(engine.results)
    first.ttps = ["T1055", "T1027", "T1055"]
    second = _make_signature("sig_b")(engine.results)
    second.ttps = ["T1055"]

    engine._add_ttps(first)
    engine._add_ttps(first)
    engine._add_ttps(second)

    assert engine.ttps == [
        {"ttp": "T1055", "signature": "sig_a"},
        {"ttp": "T1027", "signature": "sig_a"},
        {"ttp": "T1055", "signature": "sig_b"},
    ]


@pytest.mark.parametrize("ttps", ([], ["T1059"]))
def test_add_ttps_handles_empty_and_single(monkeypatch, ttps):
    engine = _engine(monkeypatch)
    engine.ttps = []
    engine._seen_ttps = set()

    sig = _make_signature("sig_c")(engine.results)
    sig.ttps = ttps
    engine._add_ttps(sig)

    assert engine.ttps == [{"ttp": ttp, "signature": "sig_c"} for ttp in ttps]
