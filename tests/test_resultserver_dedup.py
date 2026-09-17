import io
import json
import os
import sys
import tempfile
from unittest.mock import MagicMock

import types

class _MockProtocolHandler:
    def __init__(self, task_id, ctx, version=None):
        self.task_id = task_id
        self.handler = ctx
        self.fd = None
        self.version = version

    def __enter__(self):
        self.init()

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if self.fd:
            self.fd.close()
            self.fd = None

    def handle(self):
        raise NotImplementedError


for _mod_name in (
    "gevent",
    "gevent.pool",
    "gevent.server",
    "gevent.socket",
    "gevent.thread",
    "gevent.monkey",
    "gevent.event",
    "gevent.lock",
    "pytz",
    "pebble",
    "dns",
    "dns.resolver",
    "pefile",
    "lib.cuckoo.core.database",
    "lib.cuckoo.core.data.db_common",
    "lib.cuckoo.core.data.task",
    "lib.cuckoo.core.data.machines",
):
    try:
        __import__(_mod_name)
    except Exception:
        _m = types.ModuleType(_mod_name)
        _m.__getattr__ = lambda name: MagicMock()
        sys.modules[_mod_name] = _m

try:
    import lib.cuckoo.common.abstracts  # noqa: F401
except Exception:
    abstracts_mod = types.ModuleType("lib.cuckoo.common.abstracts")
    abstracts_mod.ProtocolHandler = _MockProtocolHandler
    abstracts_mod.Processing = MagicMock
    sys.modules["lib.cuckoo.common.abstracts"] = abstracts_mod

from lib.cuckoo.core.resultserver import FileUpload, HandlerContext


class DummyHandlerContext(HandlerContext):
    def __init__(self, task_id, storagepath, lines, payload):
        self.task_id = task_id
        self.storagepath = storagepath
        self._lines = [line.encode("utf-8") if isinstance(line, str) else line for line in lines]
        self._payload = io.BytesIO(payload)
        self.buf = b""
        self.sock = MagicMock()

    def read_newline(self):
        if not self._lines:
            return b""
        return self._lines.pop(0)

    def copy_to_fd(self, fd, max_size=None, hasher=None):
        data = self._payload.read()
        fd.write(data)
        if hasher is not None:
            hasher.update(data)


def _upload_file(
    task_id,
    storagepath,
    dump_path,
    guest_path,
    payload,
    pids="100",
    ppids="50",
    metadata="",
    category="files",
    duplicated="0",
):
    lines = [dump_path, guest_path, pids, ppids, metadata, category, duplicated]
    ctx = DummyHandlerContext(task_id, storagepath, lines, payload)
    handler = FileUpload(task_id, ctx, version=2)
    handler.init()
    handler.handle()


def test_resultserver_dedup_and_versioning():
    task_id = 999991
    with tempfile.TemporaryDirectory() as storagepath:
        payload_a = b"hello world payload A"
        payload_b = b"different content payload B"

        # 1. First upload of test.bin
        _upload_file(
            task_id,
            storagepath,
            "files/test.bin",
            r"C:\Users\admin\Downloads\test.bin",
            payload_a,
            pids="1001",
        )

        file_a_path = os.path.join(storagepath, "files/test.bin")
        assert os.path.exists(file_a_path)
        with open(file_a_path, "rb") as f:
            assert f.read() == payload_a

        # 2. Duplicate upload of same content under colliding filename (e.g. browser retry test(1).bin)
        _upload_file(
            task_id,
            storagepath,
            "files/test(1).bin",
            r"C:\Users\admin\Downloads\test(1).bin",
            payload_a,
            pids="1002",
        )

        # test(1).bin should NOT exist on disk; it should be deduplicated to files/test.bin
        assert not os.path.exists(os.path.join(storagepath, "files/test(1).bin"))

        # 3. Duplicate upload of same content under exact same filename
        _upload_file(
            task_id,
            storagepath,
            "files/test.bin",
            r"C:\Users\admin\Downloads\test.bin",
            payload_a,
            pids="1001",
        )
        assert not os.path.exists(os.path.join(storagepath, "files/test_1.bin"))

        # 4. Different content uploaded to same filename files/test.bin -> should version to files/test_1.bin
        _upload_file(
            task_id,
            storagepath,
            "files/test.bin",
            r"C:\Users\admin\Downloads\test.bin",
            payload_b,
            pids="1003",
        )

        versioned_path = os.path.join(storagepath, "files/test_1.bin")
        assert os.path.exists(versioned_path)
        with open(versioned_path, "rb") as f:
            assert f.read() == payload_b

        # Verify files.json entries
        files_json = os.path.join(storagepath, "files.json")
        assert os.path.exists(files_json)
        with open(files_json, "rb") as f:
            records = [json.loads(line) for line in f]

        # Expected records:
        # - test.bin (pid 1001) -> path: files/test.bin
        # - test(1).bin (pid 1002) -> path: files/test.bin (deduplicated!)
        # Note: identical repeat (test.bin with pid 1001) is deduplicated from files.json
        # - test.bin (pid 1003, payload B) -> path: files/test_1.bin
        assert len(records) == 3
        assert records[0]["path"] == "files/test.bin"
        assert records[0]["filepath"] == r"C:\Users\admin\Downloads\test.bin"
        assert records[1]["path"] == "files/test.bin"
        assert records[1]["filepath"] == r"C:\Users\admin\Downloads\test(1).bin"
        assert records[2]["path"] == "files/test_1.bin"
        assert records[2]["filepath"] == r"C:\Users\admin\Downloads\test.bin"


def test_resultserver_zero_byte_placeholder_replacement():
    task_id = 999992
    with tempfile.TemporaryDirectory() as storagepath:
        payload_real = b"actual APK content bytes"

        # 1. Initial 0-byte upload (e.g. empty file creation event)
        _upload_file(
            task_id,
            storagepath,
            "files/app.apk",
            r"C:\Users\admin\Downloads\app.apk",
            b"",
            pids="2001",
        )
        target_path = os.path.join(storagepath, "files/app.apk")
        assert os.path.exists(target_path)
        assert os.path.getsize(target_path) == 0

        # 2. Full file content uploaded for same path -> replaces 0-byte file in-place (no app_1.apk)
        _upload_file(
            task_id,
            storagepath,
            "files/app.apk",
            r"C:\Users\admin\Downloads\app.apk",
            payload_real,
            pids="2001",
        )
        assert os.path.exists(target_path)
        assert os.path.getsize(target_path) == len(payload_real)
        assert not os.path.exists(os.path.join(storagepath, "files/app_1.apk"))

        # 3. Subsequent 0-byte upload -> ignored, does not overwrite real file
        _upload_file(
            task_id,
            storagepath,
            "files/app.apk",
            r"C:\Users\admin\Downloads\app.apk",
            b"",
            pids="2002",
        )
        assert os.path.getsize(target_path) == len(payload_real)


def test_watchdownloads_event_handler_moved_and_dedup(monkeypatch):
    import importlib.util

    os.environ.setdefault("HOMEPATH", "/tmp")

    # Mock guest-only modules and watchdog if not installed
    mock_abstracts = types.ModuleType("lib.common.abstracts")
    mock_abstracts.Auxiliary = type("Auxiliary", (), {})
    mock_results = types.ModuleType("lib.common.results")
    uploaded = []
    mock_results.upload_to_host = lambda src, dst: uploaded.append((src, dst))

    mock_wd_events = types.ModuleType("watchdog.events")
    mock_wd_events.EVENT_TYPE_DELETED = "deleted"
    mock_wd_events.FileSystemEvent = object
    mock_wd_events.FileSystemEventHandler = object
    mock_wd_observers = types.ModuleType("watchdog.observers")
    mock_wd_observers.Observer = MagicMock()

    monkeypatch.setitem(sys.modules, "lib.common.abstracts", mock_abstracts)
    monkeypatch.setitem(sys.modules, "lib.common.results", mock_results)
    monkeypatch.setitem(sys.modules, "watchdog.events", mock_wd_events)
    monkeypatch.setitem(sys.modules, "watchdog.observers", mock_wd_observers)

    spec = importlib.util.spec_from_file_location(
        "watchdownloads",
        os.path.join(os.path.dirname(__file__), "../analyzer/windows/modules/auxiliary/watchdownloads.py"),
    )
    watchdownloads = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(watchdownloads)

    handler = watchdownloads.MyEventHandler()

    with tempfile.TemporaryDirectory() as tmpdir:
        part_path = os.path.join(tmpdir, "sample.apk.part")
        final_path = os.path.join(tmpdir, "sample.apk")

        # 1. Create empty placeholder -> should be ignored
        with open(final_path, "wb") as f:
            pass
        ev_empty = MagicMock()
        ev_empty.is_directory = False
        ev_empty.event_type = "created"
        ev_empty.src_path = final_path
        ev_empty.dest_path = None
        handler.on_any_event(ev_empty)
        assert len(uploaded) == 0

        # 2. Write payload and simulate FileMovedEvent (.part -> .apk)
        with open(final_path, "wb") as f:
            f.write(b"APK content")
        ev_moved = MagicMock()
        ev_moved.is_directory = False
        ev_moved.event_type = "moved"
        ev_moved.src_path = part_path
        ev_moved.dest_path = final_path
        handler.on_any_event(ev_moved)
        assert len(uploaded) == 1
        assert uploaded[0] == (final_path, "files/sample.apk")

        # 3. Subsequent modified/closed event with same size & mtime -> should be deduplicated
        ev_mod = MagicMock()
        ev_mod.is_directory = False
        ev_mod.event_type = "modified"
        ev_mod.src_path = final_path
        ev_mod.dest_path = None
        handler.on_any_event(ev_mod)
        assert len(uploaded) == 1


def test_cape_processing_without_magika_config():
    """Verify CAPE processing module handles deduplicated dropped files when [magika] config is absent."""
    from lib.cuckoo.common.config import Config
    import modules.processing.CAPE as cape_mod
    import lib.cuckoo.common.integrations.file_extra_info as fei_mod

    proc_cfg = Config("processing")
    if hasattr(proc_cfg, "magika"):
        delattr(proc_cfg, "magika")
    cape_mod.processing_conf = proc_cfg
    fei_mod.processing_conf = proc_cfg

    with tempfile.TemporaryDirectory() as tmpdir:
        files_dir = os.path.join(tmpdir, "files")
        os.makedirs(files_dir)
        sample_path = os.path.join(files_dir, "Reader_en_install.exe")
        with open(sample_path, "wb") as f:
            f.write(b"MZ\x90\x00" + b"A" * 1024)

        files_json = os.path.join(tmpdir, "files.json")
        with open(files_json, "w") as f:
            f.write(
                json.dumps(
                    {
                        "path": "files/Reader_en_install.exe",
                        "filepath": "C:\\Users\\Bruno\\Downloads\\Reader_en_install.exe",
                        "pids": [3540],
                        "ppids": [1412],
                        "metadata": "",
                        "category": "files",
                    }
                )
                + "\n"
            )
            f.write(
                json.dumps(
                    {
                        "path": "files/Reader_en_install.exe",
                        "filepath": "C:\\Users\\Bruno\\Downloads\\Reader_en_install(1).exe",
                        "pids": [3540],
                        "ppids": [1412],
                        "metadata": "",
                        "category": "files",
                    }
                )
                + "\n"
            )

        results = {}
        cape_proc = cape_mod.CAPE(results)
        cape_proc.set_path(tmpdir)
        cape_proc.set_task({"id": 1418, "category": "url", "options": ""})
        cape_proc.set_options(proc_cfg.CAPE)
        cape_proc.run()

        assert "dropped" in results
        assert len(results["dropped"]) == 1
        dropped = results["dropped"][0]
        assert dropped["name"] == ["Reader_en_install.exe", "Reader_en_install(1).exe"]
        assert dropped["guest_paths"] == [
            "C:\\Users\\Bruno\\Downloads\\Reader_en_install.exe",
            "C:\\Users\\Bruno\\Downloads\\Reader_en_install(1).exe",
        ]


