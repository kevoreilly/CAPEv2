"""Regression tests for the Summary / ProcessTree / EncryptedBuffers dedup paths.

All three tested membership against a list on every matching API call. They now use
set-backed lookups; these tests pin ordering and content so the rewrite cannot change
report output, and pin the two bugs that were fixed on the way.
"""

import os
import sys

CUCKOO_ROOT = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..")
sys.path.insert(0, CUCKOO_ROOT)

from lib.cuckoo.common.dictionary import Dictionary  # noqa: E402
from modules.processing.behavior import EncryptedBuffers, ProcessTree, Summary, _UniqueList  # noqa: E402


def _options(**kwargs):
    opts = Dictionary()
    opts.update({"replace_patterns": False, "file_activities": False})
    opts.update(kwargs)
    return opts


def _call(api, args, category="registry", status=1):
    return {
        "api": api,
        "category": category,
        "status": status,
        "arguments": [{"name": k, "value": v, "raw_value": v} for k, v in args.items()],
    }


def _process():
    return {
        "process_name": "malware.exe",
        "process_id": 1234,
        "parent_id": 4,
        "module_path": "C:\\malware.exe",
        "threads": [1234],
        "environ": {},
        "file_activities": {},
    }


# --------------------------------------------------------------------------- _UniqueList


def test_uniquelist_preserves_insertion_order_and_dedupes():
    u = _UniqueList()
    for v in ("b", "a", "b", "c", "a"):
        u.append(v)
    assert u.as_list() == ["b", "a", "c"]
    assert list(u) == ["b", "a", "c"]
    assert len(u) == 3
    assert "a" in u
    assert "z" not in u
    assert u == ["b", "a", "c"]


# --------------------------------------------------------------------------- Summary


def test_summary_collects_keys_in_order_without_duplicates():
    s = Summary(_options())
    p = _process()
    for name in ("HKLM\\Software\\A", "HKLM\\Software\\B", "HKLM\\Software\\A"):
        s.event_apicall(_call("RegOpenKeyExW", {"FullName": name}), p)

    out = s.run()
    assert out["keys"] == ["HKLM\\Software\\A", "HKLM\\Software\\B"]
    assert isinstance(out["keys"], list), "reporting expects plain lists"


def test_summary_regsetvalue_populates_both_keys_and_write_keys():
    s = Summary(_options())
    p = _process()
    s.event_apicall(_call("RegSetValueExW", {"FullName": "HKLM\\Run\\evil"}), p)
    s.event_apicall(_call("RegSetValueExW", {"FullName": "HKLM\\Run\\evil"}), p)

    out = s.run()
    assert out["keys"] == ["HKLM\\Run\\evil"]
    assert out["write_keys"] == ["HKLM\\Run\\evil"]


def test_summary_mutexes_are_deduped():
    s = Summary(_options())
    p = _process()
    for _ in range(3):
        s.event_apicall(_call("NtCreateMutant", {"MutexName": "Global\\evil"}, category="synchronization"), p)
    assert s.run()["mutexes"] == ["Global\\evil"]


def test_summary_run_returns_every_key_as_a_list():
    out = Summary(_options()).run()
    assert all(isinstance(v, list) for v in out.values()), out


def test_summary_replace_patterns_marks_raw_and_denylisted_inputs_seen():
    s = Summary(_options(replace_patterns=True, file_activities=True))
    p = _process()
    p["file_activities"] = {"read_files": [], "write_files": [], "delete_files": []}

    # Translated registry prefix: raw input is marked seen after first call.
    for _ in range(3):
        s.event_apicall(_call("RegOpenKeyExW", {"FullName": "HKEY_LOCAL_MACHINE\\Software\\Evil"}), p)
    assert "HKEY_LOCAL_MACHINE\\Software\\Evil" in s.keys
    assert s.run()["keys"] == ["HKLM\\Software\\Evil"]

    # Denylisted file suffix (.mui): rejected by check_deny_pattern and marked seen on first call.
    for _ in range(3):
        s.event_apicall(
            _call("NtCreateFile", {"FileName": "C:\\Windows\\System32\\en-US\\notepad.exe.mui", "DesiredAccess": "0x80000000"}, category="filesystem"),
            p,
        )
    assert "C:\\Windows\\System32\\en-US\\notepad.exe.mui" in s.read_files
    assert s.run()["read_files"] == []
    assert len(p["file_activities"]["read_files"]) == 1


# --------------------------------------------------------------------------- ProcessTree


def test_processtree_records_each_pid_once():
    t = ProcessTree()
    p1 = _process()
    p2 = dict(_process(), process_id=5678, process_name="child.exe")

    for _ in range(5):
        t.event_apicall({}, p1)
        t.event_apicall({}, p2)

    assert [e["pid"] for e in t.processes] == [1234, 5678]


def test_processtree_retries_a_process_missing_a_field():
    # The pid is only marked seen once the entry was built, matching the old list scan.
    t = ProcessTree()
    broken = {"process_id": 99}
    try:
        t.event_apicall({}, broken)
    except KeyError:
        pass
    assert t.processes == []
    assert 99 not in t.seen_pids


def _max_tree_depth(nodes):
    max_d = 0
    stack = [(n, 0) for n in nodes]
    while stack:
        node, d = stack.pop()
        if d > max_d:
            max_d = d
        for child in node.get("children", []):
            stack.append((child, d + 1))
    return max_d


def test_processtree_caps_deep_linear_chains_for_json_and_bson():
    import bson
    import orjson

    for reverse in (False, True):
        t = ProcessTree()
        chain = [
            dict(_process(), process_id=1000 + i, parent_id=999 + i if i > 0 else 4)
            for i in range(300)
        ]
        if reverse:
            chain.reverse()
        for p in chain:
            t.event_apicall({}, p)

        roots = t.run()
        assert len(roots) > 1
        assert _max_tree_depth(roots) <= 64
        doc = {"behavior": {"processtree": roots}}
        assert orjson.dumps(doc)
        assert bson.BSON.encode(doc)


def test_processtree_breaks_cycles_without_exceeding_depth():
    t = ProcessTree()
    p1 = dict(_process(), process_id=100, parent_id=102)
    p2 = dict(_process(), process_id=101, parent_id=100)
    p3 = dict(_process(), process_id=102, parent_id=101)
    for p in (p1, p2, p3):
        t.event_apicall({}, p)

    roots = t.run()
    assert len(roots) == 1
    assert _max_tree_depth(roots) == 2


# --------------------------------------------------------------------------- EncryptedBuffers


def _crypt_call(api, buf, **extra):
    args = {"Buffer": buf}
    args.update(extra)
    return _call(api, args, category="crypto")


def test_encrypted_buffers_dedupe_repeated_buffers():
    e = EncryptedBuffers()
    p = _process()
    for _ in range(4):
        e.event_apicall(_crypt_call("CryptEncrypt", "AAAA", CryptKey="0x1"), p)
    e.event_apicall(_crypt_call("CryptEncrypt", "BBBB", CryptKey="0x1"), p)

    assert [b["buffer"] for b in e.run()] == ["AAAA", "BBBB"]


def test_cryptencryptmessage_is_not_also_recorded_as_cryptencrypt():
    e = EncryptedBuffers()
    p = _process()
    e.event_apicall(_crypt_call("CryptEncryptMessage", "AAAA"), p)

    bufs = e.run()
    assert len(bufs) == 1
    assert bufs[0]["api_call"] == "CryptEncryptMessage"


def test_same_buffer_under_different_apis_is_kept_separately():
    e = EncryptedBuffers()
    p = _process()
    e.event_apicall(_crypt_call("SslEncryptPacket", "AAAA", BufferSize="4"), p)
    e.event_apicall(_crypt_call("CryptEncrypt", "AAAA", CryptKey="0x1"), p)

    assert [b["api_call"] for b in e.run()] == ["SslEncryptPacket", "CryptEncrypt"]


def test_empty_buffer_is_ignored():
    e = EncryptedBuffers()
    e.event_apicall(_crypt_call("CryptEncrypt", "", CryptKey="0x1"), _process())
    assert e.run() == []
