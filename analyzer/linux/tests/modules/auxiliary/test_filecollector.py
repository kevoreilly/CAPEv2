import hashlib
import os
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from modules.auxiliary import filecollector


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Requires Linux inotify")
def test_filecollector_collects_created_and_nested_files(tmp_path):
    uploaded = []

    def fake_upload(src, dst):
        uploaded.append((src, dst))

    watch_dir = tmp_path / "watched"
    watch_dir.mkdir()
    cfg = SimpleNamespace(filecollector=True)

    with (
        patch.object(filecollector, "upload_to_host", side_effect=fake_upload),
        patch.object(filecollector, "_POLL_TIMEOUT_SEC", 0.05),
        patch.object(filecollector.time, "sleep"),
    ):
        collector = filecollector.FileCollector({}, cfg, watch_roots=[str(watch_dir)])
        assert collector.initComplete is True
        collector.start()

        first = watch_dir / "dropped.bin"
        payload = b"payload-one"
        first.write_bytes(payload)

        nested_dir = watch_dir / "sub"
        nested_dir.mkdir()
        # Give watcher a brief window to attach the subdirectory watch.
        deadline = time.monotonic() + 2.0
        while not uploaded and time.monotonic() < deadline:
            time.sleep(0.02)

        second = nested_dir / "nested.bin"
        nested_payload = b"payload-two"
        second.write_bytes(nested_payload)

        # Duplicate content should be skipped.
        dup = watch_dir / "duplicate.bin"
        dup.write_bytes(payload)

        # strace.log should be ignored.
        (watch_dir / "strace.log").write_text("ignored")

        deadline = time.monotonic() + 2.0
        while len(uploaded) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)

        collector.stop()

    expected_h1 = hashlib.sha256(payload).hexdigest()
    expected_h2 = hashlib.sha256(nested_payload).hexdigest()
    uploaded_dsts = [dst for _, dst in uploaded]
    assert os.path.join("files", expected_h1) in uploaded_dsts
    assert os.path.join("files", expected_h2) in uploaded_dsts
    assert len(uploaded_dsts) == 2


def test_filecollector_init_does_not_hang_when_inotify_unavailable():
    cfg = SimpleNamespace(filecollector=True)
    with patch.object(filecollector, "HAVE_INOTIFY", False):
        collector = filecollector.FileCollector({}, cfg)
        assert collector.initComplete is True
        assert collector.do_run is False
        collector.stop()


def test_filecollector_disabled_does_not_spawn_thread():
    cfg = SimpleNamespace(filecollector=False)
    collector = filecollector.FileCollector({}, cfg)
    assert collector.thread is None
    assert collector.start() is False
    assert collector.stop() is False
